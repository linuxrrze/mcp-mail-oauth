"""IMAP/SMTP access using the caller's OAuth access token as SASL credential.

Synchronous on purpose: imaplib/smtplib are blocking, and the MCP tools call
into this module via asyncio.to_thread(). Every operation opens its own
connection, authenticates with the token of the request at hand, and closes
it again (docs/decisions.md, D11). A token is never cached or reused across
requests here, so there is no per-user state and nothing to expire.
"""

from __future__ import annotations

import base64
import binascii
import imaplib
import re
import smtplib
import socket
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, make_msgid
from html.parser import HTMLParser

from .config import MailSettings

MAX_LIST_LIMIT = 50
DEFAULT_BODY_CHARS = 20_000
MAX_BODY_CHARS = 100_000


class MailError(Exception):
    """Base class; the message is safe to show to the user (never contains the token)."""


class MailAuthError(MailError):
    """The mail server rejected the token (it was valid for this MCP server)."""


class MailConnectionError(MailError):
    """Could not reach the mail server or establish TLS."""


class MailRequestError(MailError):
    """The request itself was invalid (unknown folder/UID, bad address, ...)."""


# ── SASL ──────────────────────────────────────────────────────────────────────

_FORBIDDEN_IN_SASL = re.compile(r"[\x00-\x1f\x7f]")


def _escape_saslname(value: str) -> str:
    # RFC 5801 saslname: "," and "=" must be escaped in the GS2 header.
    return value.replace("=", "=3D").replace(",", "=2C")


def sasl_initial_response(mechanism: str, username: str, token: str, host: str, port: int) -> bytes:
    """Build the client's first SASL message (not yet base64-encoded).

    XOAUTH2 (Google's de-facto format, supported by Dovecot):
        user=<username>^Aauth=Bearer <token>^A^A
    OAUTHBEARER (RFC 7628):
        n,a=<username>,^Ahost=<host>^Aport=<port>^Aauth=Bearer <token>^A^A
    """
    # Control characters could forge extra key/value pairs in the message.
    if _FORBIDDEN_IN_SASL.search(username) or _FORBIDDEN_IN_SASL.search(token):
        raise MailRequestError("Username or token contains control characters.")
    if mechanism == "XOAUTH2":
        return f"user={username}\x01auth=Bearer {token}\x01\x01".encode()
    if mechanism == "OAUTHBEARER":
        gs2 = f"n,a={_escape_saslname(username)},"
        return f"{gs2}\x01host={host}\x01port={port}\x01auth=Bearer {token}\x01\x01".encode()
    raise MailRequestError(f"Unsupported SASL mechanism {mechanism!r}.")


def _sasl_error_reply(mechanism: str) -> bytes:
    """What the client sends after the server's error challenge.

    On failure, both mechanisms make the server send one more challenge with
    a JSON error report, and the client must answer it before the server
    sends its final NO/535: an empty response for XOAUTH2, a single ^A for
    OAUTHBEARER (RFC 7628 §3.2.3).
    """
    return b"\x01" if mechanism == "OAUTHBEARER" else b""


def _auth_hint() -> str:
    return (
        "The mail server rejected the OAuth token. This server already accepted "
        "the same token, so the cause is on the mail server's side. Check, in order: "
        "(1) the token's `aud` contains the client Dovecot uses for introspection "
        "(Keycloak 26.6.2+ answers active=false otherwise); "
        "(2) Dovecot's username_attribute names the same claim as MAIL_USERNAME_CLAIM; "
        "(3) the token carries the scope set in Dovecot's oauth2 `scope`. "
        "Dovecot's auth log has the actual reason; `mcp-mail-diagnose` reproduces the check."
    )


# ── TLS / connections ─────────────────────────────────────────────────────────

def _ssl_context(settings: MailSettings) -> ssl.SSLContext:
    # MAIL_CA_FILE *replaces* the system trust store (private CA setups).
    return ssl.create_default_context(cafile=settings.ca_file) if settings.ca_file else ssl.create_default_context()


def _connection_error(kind: str, host: str, port: int, exc: Exception) -> MailConnectionError:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return MailConnectionError(
            f"TLS certificate of {kind} server {host}:{port} could not be verified ({exc.verify_message}). "
            "If it's signed by a private CA, set MAIL_CA_FILE."
        )
    return MailConnectionError(f"Could not connect to {kind} server {host}:{port}: {exc.__class__.__name__}: {exc}")


def _imap_authenticate(conn: imaplib.IMAP4, settings: MailSettings, username: str, token: str) -> None:
    mechanism = settings.sasl_mechanism
    initial = sasl_initial_response(mechanism, username, token, settings.imap_host, settings.imap_port)
    state = {"sent": False}
    server_error: list[bytes] = []

    # imaplib never uses SASL-IR, so the first callback answers the server's
    # empty "+" challenge with the token; any further callback is the error round.
    def respond(challenge: bytes) -> bytes:
        if not state["sent"]:
            state["sent"] = True
            return initial
        server_error.append(challenge)
        return _sasl_error_reply(mechanism)

    try:
        conn.authenticate(mechanism, respond)
    except imaplib.IMAP4.error as exc:
        detail = server_error[0].decode(errors="replace") if server_error else str(exc)
        raise MailAuthError(f"IMAP authentication failed ({detail}). {_auth_hint()}") from None


@contextmanager
def imap_session(settings: MailSettings, username: str, token: str) -> Iterator[imaplib.IMAP4]:
    host, port = settings.imap_host, settings.imap_port
    try:
        if settings.imap_security == "tls":
            conn = imaplib.IMAP4_SSL(host, port, ssl_context=_ssl_context(settings), timeout=settings.timeout)
        else:
            conn = imaplib.IMAP4(host, port, timeout=settings.timeout)
            conn.starttls(ssl_context=_ssl_context(settings))
    except (OSError, imaplib.IMAP4.error) as exc:
        raise _connection_error("IMAP", host, port, exc) from None
    try:
        _imap_authenticate(conn, settings, username, token)
        yield conn
    except (socket.timeout, OSError) as exc:
        raise _connection_error("IMAP", host, port, exc) from None
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _smtp_authenticate(smtp: smtplib.SMTP, settings: MailSettings, username: str, token: str) -> None:
    """AUTH with the token sent as a continuation, not as an initial response.

    A Keycloak access token is typically 1.5-3 KB, i.e. 2-4 KB in base64.
    Inline ("AUTH XOAUTH2 <payload>") that is one command line far beyond
    RFC 5321's 512-octet command limit, and servers enforce such limits on
    the AUTH line inconsistently: other clients hit failures with inline
    tokens over ~500 bytes and fixed them exactly this way. RFC 4954 allows
    both forms, and the continuation form works everywhere (docs/decisions.md, D11).
    """
    mechanism = settings.sasl_mechanism
    initial = sasl_initial_response(mechanism, username, token, settings.smtp_host, settings.smtp_port)
    code, resp = smtp.docmd("AUTH", mechanism)
    if code != 334:
        raise MailAuthError(f"SMTP server refused AUTH {mechanism} ({code} {resp.decode(errors='replace')}).")
    code, resp = smtp.docmd(base64.b64encode(initial).decode())
    if code == 334:  # error challenge: base64 JSON report, then a final 5xx
        try:
            detail = base64.b64decode(resp).decode(errors="replace")
        except (binascii.Error, ValueError):
            detail = resp.decode(errors="replace")
        smtp.docmd(base64.b64encode(_sasl_error_reply(mechanism)).decode())
        raise MailAuthError(f"SMTP authentication failed ({detail}). {_auth_hint()}")
    if code != 235:
        raise MailAuthError(f"SMTP authentication failed ({code} {resp.decode(errors='replace')}). {_auth_hint()}")


@contextmanager
def smtp_session(settings: MailSettings, username: str, token: str) -> Iterator[smtplib.SMTP]:
    host, port = settings.smtp_host, settings.smtp_port
    try:
        if settings.smtp_security == "tls":
            smtp = smtplib.SMTP_SSL(host, port, context=_ssl_context(settings), timeout=settings.timeout)
            smtp.ehlo()
        else:
            smtp = smtplib.SMTP(host, port, timeout=settings.timeout)
            smtp.ehlo()
            smtp.starttls(context=_ssl_context(settings))
            smtp.ehlo()
    except (OSError, smtplib.SMTPException) as exc:
        raise _connection_error("SMTP", host, port, exc) from None
    try:
        _smtp_authenticate(smtp, settings, username, token)
        yield smtp
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


# ── IMAP mailbox names (modified UTF-7, RFC 3501 §5.1.3) ─────────────────────

def _b64_mutf7(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=").replace("/", ",")


def encode_mailbox(name: str) -> str:
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append("&" + _b64_mutf7("".join(run).encode("utf-16-be")) + "-")
            run.clear()

    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            run.append(ch)
    flush()
    return "".join(out)


def decode_mailbox(name: str) -> str:
    def repl(match: re.Match[str]) -> str:
        chunk = match.group(1)
        if not chunk:
            return "&"
        chunk = chunk.replace(",", "/")
        chunk += "=" * (-len(chunk) % 4)
        return base64.b64decode(chunk).decode("utf-16-be")

    return re.sub(r"&([A-Za-z0-9+,]*)-", repl, name)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ── IMAP operations ───────────────────────────────────────────────────────────

_LIST_RE = re.compile(r'\((?P<flags>[^)]*)\) (?P<delim>"(?:[^"\\]|\\.)*"|NIL) (?P<name>.*)$')


def _parse_list_line(item: bytes | tuple[bytes, bytes]) -> dict | None:
    if isinstance(item, tuple):
        # Mailbox name sent as a literal: item[0] is '(flags) "/" {N}' and
        # item[1] the name itself, so match the prefix with the {N} removed.
        line = item[0].decode(errors="replace").rsplit("{", 1)[0].strip()
        match = _LIST_RE.match(line + " _")
        name = item[1].decode(errors="replace")
    else:
        match = _LIST_RE.match(item.decode(errors="replace"))
        name = match.group("name") if match else ""
    if not match:
        return None
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    flags = match.group("flags").split()
    return {"name": decode_mailbox(name), "flags": flags}


def list_folders(settings: MailSettings, username: str, token: str) -> list[dict]:
    with imap_session(settings, username, token) as conn:
        typ, data = conn.list()
        if typ != "OK":
            raise MailRequestError("LIST failed.")
        folders = [f for f in (_parse_list_line(item) for item in data if item) if f]
        return [f for f in folders if "\\Noselect" not in f["flags"] and "\\NonExistent" not in f["flags"]]


def _select(conn: imaplib.IMAP4, folder: str, *, readonly: bool = True) -> None:
    typ, data = conn.select(_quote(encode_mailbox(folder)), readonly=readonly)
    if typ != "OK":
        raise MailRequestError(f"Folder {folder!r} not found or not selectable (use list_folders).")


def _check_uid(uid: str) -> str:
    uid = str(uid).strip()
    if not uid.isdigit():
        raise MailRequestError(f"Invalid message UID {uid!r}.")
    return uid


def _parse_fetch_meta(meta: bytes) -> dict:
    uid = re.search(rb"UID (\d+)", meta)
    flags = re.search(rb"FLAGS \(([^)]*)\)", meta)
    size = re.search(rb"RFC822\.SIZE (\d+)", meta)
    return {
        "uid": uid.group(1).decode() if uid else None,
        "flags": flags.group(1).decode().split() if flags else [],
        "size": int(size.group(1)) if size else None,
    }


_SUMMARY_FIELDS = "FROM TO CC SUBJECT DATE MESSAGE-ID"


def _fetch_summaries(conn: imaplib.IMAP4, uids: list[str]) -> list[dict]:
    if not uids:
        return []
    typ, data = conn.uid("FETCH", ",".join(uids), f"(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({_SUMMARY_FIELDS})])")
    if typ != "OK":
        raise MailRequestError("FETCH failed.")
    by_uid: dict[str, dict] = {}
    for item in data:
        if not isinstance(item, tuple):
            continue
        meta = _parse_fetch_meta(item[0])
        headers = message_from_bytes(item[1], policy=policy.default)
        flags = meta["flags"]
        by_uid[meta["uid"]] = {
            "uid": meta["uid"],
            "from": str(headers.get("From", "")),
            "to": str(headers.get("To", "")),
            "subject": str(headers.get("Subject", "")),
            "date": str(headers.get("Date", "")),
            "unread": "\\Seen" not in flags,
            "flagged": "\\Flagged" in flags,
            "size": meta["size"],
        }
    return [by_uid[u] for u in uids if u in by_uid]


def _uid_search(conn: imaplib.IMAP4, *criteria: str) -> list[str]:
    typ, data = conn.uid("SEARCH", None, *criteria)
    if typ != "OK":
        raise MailRequestError(f"SEARCH failed: {data!r}")
    return [u.decode() for u in (data[0] or b"").split()]


def _clamp(limit: int, maximum: int = MAX_LIST_LIMIT) -> int:
    return max(1, min(int(limit), maximum))


def list_messages(
    settings: MailSettings, username: str, token: str, folder: str, limit: int, offset: int, unread_only: bool
) -> dict:
    with imap_session(settings, username, token) as conn:
        _select(conn, folder)
        uids = _uid_search(conn, "UNSEEN" if unread_only else "ALL")
        uids.sort(key=int, reverse=True)
        offset = max(0, int(offset))
        page = uids[offset:offset + _clamp(limit)]
        return {
            "folder": folder,
            "total": len(uids),
            "offset": offset,
            "messages": _fetch_summaries(conn, page),
        }


def _imap_date(value: str, field: str) -> str:
    try:
        parsed = datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        raise MailRequestError(f"{field} must be YYYY-MM-DD, got {value!r}.") from None
    # IMAP date: 01-Jan-2026, English month names regardless of locale.
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{parsed.day:02d}-{months[parsed.month - 1]}-{parsed.year}"


def build_search(
    *, from_: str | None = None, to: str | None = None, subject: str | None = None, text: str | None = None,
    since: str | None = None, before: str | None = None, unread_only: bool = False,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Split criteria into (ASCII criteria for one SEARCH, non-ASCII ones).

    imaplib can attach only one literal per command, and non-ASCII search
    strings must be sent as a literal with CHARSET UTF-8. So each non-ASCII
    criterion gets its own SEARCH and the results are intersected; plain
    ASCII criteria are combined into one command as quoted strings.
    """
    ascii_parts: list[str] = []
    literal_parts: list[tuple[str, str]] = []
    for key, value in (("FROM", from_), ("TO", to), ("SUBJECT", subject), ("TEXT", text)):
        if value is None or not value.strip():
            continue
        if re.search(r"[\r\n]", value):
            raise MailRequestError(f"{key.lower()} must be a single line.")
        if value.isascii():
            ascii_parts += [key, _quote(value)]
        else:
            literal_parts.append((key, value))
    if since:
        ascii_parts += ["SINCE", _imap_date(since, "since")]
    if before:
        ascii_parts += ["BEFORE", _imap_date(before, "before")]
    if unread_only:
        ascii_parts.append("UNSEEN")
    return ascii_parts, literal_parts


def search_messages(settings: MailSettings, username: str, token: str, folder: str, limit: int, **criteria) -> dict:
    ascii_parts, literal_parts = build_search(**criteria)
    if not ascii_parts and not literal_parts:
        raise MailRequestError("Give at least one search criterion.")
    with imap_session(settings, username, token) as conn:
        _select(conn, folder)
        result: set[str] | None = set(_uid_search(conn, *ascii_parts)) if ascii_parts else None
        for key, value in literal_parts:
            conn.literal = value.encode()
            found = set(_uid_search(conn, "CHARSET", "UTF-8", key))
            result = found if result is None else result & found
        uids = sorted(result or set(), key=int, reverse=True)
        return {
            "folder": folder,
            "total": len(uids),
            "messages": _fetch_summaries(conn, uids[:_clamp(limit)]),
        }


class _HTMLText(HTMLParser):
    _BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _HTMLText()
    parser.feed(html)
    text = "".join(parser.parts)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def parse_message(raw: bytes, max_chars: int) -> dict:
    msg = message_from_bytes(raw, policy=policy.default)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    body = ""
    if body_part is not None:
        try:
            content = body_part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = body_part.get_payload(decode=True).decode("utf-8", errors="replace")
        body = html_to_text(content) if body_part.get_content_type() == "text/html" else content
    max_chars = max(1, min(int(max_chars), MAX_BODY_CHARS))
    truncated = len(body) > max_chars
    attachments = [
        {
            "filename": part.get_filename() or "(unnamed)",
            "content_type": part.get_content_type(),
            "size": len(part.get_payload(decode=True) or b""),
        }
        for part in msg.iter_attachments()
    ]
    return {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "cc": str(msg.get("Cc", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "body": body[:max_chars],
        "body_truncated": truncated,
        "attachments": attachments,
    }


def _fetch_raw(conn: imaplib.IMAP4, uid: str, part: str = "BODY.PEEK[]") -> bytes:
    typ, data = conn.uid("FETCH", uid, f"({part})")
    if typ != "OK":
        raise MailRequestError(f"FETCH failed for UID {uid}.")
    for item in data:
        if isinstance(item, tuple):
            return item[1]
    raise MailRequestError(f"No message with UID {uid} in this folder.")


def read_message(
    settings: MailSettings, username: str, token: str, folder: str, uid: str, max_chars: int, mark_read: bool
) -> dict:
    uid = _check_uid(uid)
    with imap_session(settings, username, token) as conn:
        _select(conn, folder, readonly=not mark_read)
        result = parse_message(_fetch_raw(conn, uid), max_chars)
        if mark_read:
            conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
        return {"uid": uid, "folder": folder, **result}


# ── Sending ──────────────────────────────────────────────────────────────────

def parse_recipients(values: list[str] | None, field: str) -> list[str]:
    """Normalize recipient strings ("Name <a@b>", "a@b, c@d") to formatted addresses."""
    out: list[str] = []
    for value in values or []:
        if re.search(r"[\r\n]", value):
            raise MailRequestError(f"{field} must not contain line breaks.")
        for name, addr in getaddresses([value]):
            if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
                raise MailRequestError(f"Invalid address in {field}: {value!r}.")
            out.append(f"{name} <{addr}>" if name else addr)
    return out


def _reply_headers(conn: imaplib.IMAP4, uid: str) -> dict:
    raw = _fetch_raw(conn, uid, "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID REFERENCES SUBJECT)]")
    headers = message_from_bytes(raw, policy=policy.default)
    message_id = str(headers.get("Message-ID", "")).strip()
    references = " ".join(filter(None, [str(headers.get("References", "")).strip(), message_id]))
    return {"message_id": message_id, "references": references, "subject": str(headers.get("Subject", ""))}


def send_message(
    settings: MailSettings, username: str, token: str, *, to: list[str], subject: str | None, body: str,
    cc: list[str] | None = None, bcc: list[str] | None = None,
    reply_to_uid: str | None = None, reply_folder: str = "INBOX",
) -> dict:
    to_addrs = parse_recipients(to, "to")
    cc_addrs = parse_recipients(cc, "cc")
    bcc_addrs = parse_recipients(bcc, "bcc")
    if not to_addrs:
        raise MailRequestError("At least one 'to' recipient is required.")

    msg = EmailMessage()
    # The sender is always the authenticated user (D10): never a tool argument.
    msg["From"] = username
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    if bcc_addrs:
        msg["Bcc"] = ", ".join(bcc_addrs)  # kept for the Sent copy; never transmitted
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=username.rsplit("@", 1)[-1] if "@" in username else None)

    if reply_to_uid:
        with imap_session(settings, username, token) as conn:
            _select(conn, reply_folder)
            original = _reply_headers(conn, _check_uid(reply_to_uid))
        if original["message_id"]:
            msg["In-Reply-To"] = original["message_id"]
            msg["References"] = original["references"]
        if not subject:
            orig = original["subject"]
            subject = orig if orig.lower().startswith("re:") else f"Re: {orig}"
    if not subject:
        raise MailRequestError("subject is required (it's optional only when replying).")
    try:
        msg["Subject"] = subject
    except ValueError as exc:  # header injection attempt (CR/LF)
        raise MailRequestError(f"Invalid subject: {exc}") from None
    msg.set_content(body)

    with smtp_session(settings, username, token) as smtp:
        try:
            # send_message() never transmits Bcc headers, but does deliver to them.
            refused = smtp.send_message(msg, from_addr=username)
        except smtplib.SMTPRecipientsRefused as exc:
            raise MailRequestError(f"All recipients were refused: {exc.recipients}") from None
        except smtplib.SMTPSenderRefused as exc:
            raise MailRequestError(
                f"The SMTP server refused sender {username} ({exc.smtp_code} {exc.smtp_error!r}). "
                "With Postfix reject_sender_login_mismatch, the login name and the From address must match."
            ) from None

    result: dict = {"status": "sent", "message_id": msg["Message-ID"], "refused": {k: str(v) for k, v in refused.items()}}

    # The message is already out at this point: a failure here must be
    # reported, never raised (a retry would send the mail twice).
    if settings.sent_folder:
        try:
            with imap_session(settings, username, token) as conn:
                typ, data = conn.append(
                    _quote(encode_mailbox(settings.sent_folder)), "(\\Seen)",
                    imaplib.Time2Internaldate(time.time()), msg.as_bytes(),
                )
            result["saved_to"] = settings.sent_folder if typ == "OK" else None
            if typ != "OK":
                result["warning"] = f"Sent, but saving a copy to {settings.sent_folder!r} failed: {data!r}"
        except MailError as exc:
            result["saved_to"] = None
            result["warning"] = f"Sent, but saving a copy to {settings.sent_folder!r} failed: {exc}"
    return result
