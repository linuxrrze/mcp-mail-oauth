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
from email.errors import MessageError
from email.headerregistry import Address
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
    if not re.fullmatch(r"[0-9]+", uid):  # not isdigit(): that accepts "²" too
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


# ── Message structure (BODYSTRUCTURE) ────────────────────────────────────────
#
# Reading a message fetches its BODYSTRUCTURE, its header and the first bytes
# of the one text part shown, never the whole message: a 50 MB attachment
# would otherwise be downloaded, in full, just to report its name and size.

def _response_bytes(data: list) -> bytes:
    """imaplib's FETCH response back as one byte string, literals inline.

    imaplib splits a response at each literal: ('... {N}', <N bytes>) tuples,
    followed by plain bytes for the rest of the line."""
    out = b""
    for item in data:
        if isinstance(item, tuple):
            out += item[0] + b"\r\n" + item[1]
        elif item:
            out += item
    return out


_LITERAL_RE = re.compile(rb"\{(\d+)\+?\}\r\n")


def parse_sexp(data: bytes) -> list:
    """Parse an IMAP response line into nested lists of str (NIL -> None)."""
    stack: list[list] = [[]]
    pos, end = 0, len(data)
    while pos < end:
        c = data[pos:pos + 1]
        if c in (b" ", b"\r", b"\n"):
            pos += 1
        elif c == b"(":
            stack.append([])
            pos += 1
        elif c == b")":
            if len(stack) == 1:
                raise MailRequestError("Malformed IMAP response.")
            done = stack.pop()
            stack[-1].append(done)
            pos += 1
        elif c == b'"':
            pos += 1
            buf = bytearray()
            while pos < end and data[pos:pos + 1] != b'"':
                if data[pos:pos + 1] == b"\\":
                    pos += 1
                buf += data[pos:pos + 1]
                pos += 1
            pos += 1
            stack[-1].append(buf.decode("utf-8", errors="replace"))
        elif c == b"{" and (m := _LITERAL_RE.match(data, pos)):
            start = m.end()
            stack[-1].append(data[start:start + int(m.group(1))].decode("utf-8", errors="replace"))
            pos = start + int(m.group(1))
        else:
            start = pos
            while pos < end and data[pos:pos + 1] not in (b" ", b"(", b")", b"\r", b"\n"):
                if data[pos:pos + 1] == b"[":  # BODY[...] may contain spaces and parens
                    close = data.find(b"]", pos)
                    pos = close if close != -1 else end
                pos += 1
            atom = data[start:pos].decode("utf-8", errors="replace")
            stack[-1].append(None if atom.upper() == "NIL" else atom)
    return stack[0]


def _params(value) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    return {str(k).lower(): v for k, v in zip(value[::2], value[1::2]) if isinstance(k, str) and isinstance(v, str)}


def _param_header(params: dict[str, str]) -> str:
    return "".join(
        f'; {k}="' + re.sub(r"[\x00-\x1f]", "", v).replace("\\", "\\\\").replace('"', '\\"') + '"'
        for k, v in params.items() if re.fullmatch(r"[a-z0-9*_.-]+", k)
    )


def _filename(part: dict) -> str | None:
    """Filename via the email package, so RFC 2231 (filename*=) and
    RFC 2047 encoded words in parameters are decoded the usual way."""
    headers = (f"Content-Type: {part['content_type']}{_param_header(part['params'])}\n"
               f"Content-Disposition: {part['disposition'] or 'attachment'}{_param_header(part['dparams'])}\n\n")
    try:
        return message_from_bytes(headers.encode("utf-8", errors="replace"), policy=policy.default).get_filename()
    except Exception:  # a malformed parameter must not break reading the message
        return None


def _leaf(node: list, section: str) -> dict:
    def at(i):
        return node[i] if len(node) > i else None

    maintype = (at(0) or "application").lower()
    subtype = (at(1) or "octet-stream").lower()
    # Extension data follows the basic fields, whose count depends on the type.
    ext = 8 if maintype == "text" else 10 if (maintype, subtype) == ("message", "rfc822") else 7
    disposition = at(ext + 1)
    try:
        size = int(at(6) or 0)
    except ValueError:
        size = 0
    return {
        "section": section,
        "content_type": f"{maintype}/{subtype}",
        "params": _params(at(2)),
        "encoding": (at(5) or "7bit").lower(),
        "size": size,
        "disposition": disposition[0].lower() if isinstance(disposition, list) and isinstance(disposition[0], str) else None,
        "dparams": _params(disposition[1]) if isinstance(disposition, list) and len(disposition) > 1 else {},
    }


def flatten_bodystructure(node: list, section: str = "") -> list[dict]:
    """The leaf parts of a BODYSTRUCTURE, with their IMAP section numbers."""
    if node and isinstance(node[0], list):  # multipart: children, then the subtype
        parts: list[dict] = []
        index = 0
        for child in node:
            if not isinstance(child, list):
                break  # the subtype: children are over
            index += 1
            parts += flatten_bodystructure(child, f"{section}.{index}" if section else str(index))
        return parts
    return [_leaf(node, section or "1")]


def split_parts(parts: list[dict]) -> tuple[dict | None, list[dict]]:
    """(the text part to show, the attachments), like
    EmailMessage.get_body(("plain", "html")) and iter_attachments()."""
    for part in parts:
        part["filename"] = _filename(part)

    def is_text_body(part: dict) -> bool:
        return (part["content_type"] in ("text/plain", "text/html")
                and part["disposition"] != "attachment" and not part["filename"])

    candidates = [p for p in parts if is_text_body(p)]
    body = next((p for p in candidates if p["content_type"] == "text/plain"), None) or \
        next(iter(candidates), None)
    attachments = [
        {
            "filename": part["filename"] or "(unnamed)",
            "content_type": part["content_type"],
            # BODYSTRUCTURE gives the encoded size. Base64 is 4 bytes per 3, in
            # lines of 76 + CRLF: 57 decoded bytes per 78. An estimate, then.
            "size": part["size"] * 57 // 78 if part["encoding"] == "base64" else part["size"],
        }
        for part in parts if not is_text_body(part)
    ]
    return body, attachments


def decode_part(data: bytes, part: dict, complete: bool) -> str:
    """Transfer- and charset-decode a (possibly truncated) part."""
    encoding = part["encoding"]
    if encoding == "base64":
        compact = re.sub(rb"[^A-Za-z0-9+/=]", b"", data)
        compact = compact[:len(compact) - len(compact) % 4]
        try:
            data = base64.b64decode(compact)
        except (binascii.Error, ValueError):
            data = b""
    elif encoding == "quoted-printable":
        if not complete:  # don't decode a cut-off "=4" or soft line break
            data = re.sub(rb"=[0-9A-Fa-f]?$", b"", data)
        data = binascii.a2b_qp(data)
    charset = part["params"].get("charset") or "us-ascii"
    try:
        text = data.decode(charset, errors="replace")
    except LookupError:
        text = data.decode("utf-8", errors="replace")
    if charset.lower() in ("us-ascii", "ascii") and "\ufffd" in text:
        text = data.decode("utf-8", errors="replace")  # undeclared 8-bit, usually UTF-8
    if not complete:
        text = text.rstrip("\ufffd")  # a multi-byte character cut in half
    return text.replace("\r\n", "\n")


def _headers_dict(headers) -> dict:
    return {
        "from": str(headers.get("From", "")),
        "to": str(headers.get("To", "")),
        "cc": str(headers.get("Cc", "")),
        "subject": str(headers.get("Subject", "")),
        "date": str(headers.get("Date", "")),
        "message_id": str(headers.get("Message-ID", "")),
    }


def _fetch_overview(conn: imaplib.IMAP4, uid: str) -> tuple[dict, dict | None, list[dict]]:
    """(headers + flags + size, text part, attachments), without any body."""
    typ, data = conn.uid("FETCH", uid, "(UID FLAGS RFC822.SIZE BODYSTRUCTURE)")
    if typ != "OK":
        raise MailRequestError(f"FETCH failed for UID {uid}.")
    response = _response_bytes(data)
    if not response.strip():
        raise MailRequestError(f"No message with UID {uid} in this folder.")
    parsed = parse_sexp(response)
    attrs = next((item for item in parsed if isinstance(item, list)), [])
    fields = {str(k).upper(): v for k, v in zip(attrs[::2], attrs[1::2]) if isinstance(k, str)}
    if not isinstance(fields.get("BODYSTRUCTURE"), list):
        raise MailRequestError(f"No message with UID {uid} in this folder.")
    body, attachments = split_parts(flatten_bodystructure(fields["BODYSTRUCTURE"]))
    flags = fields.get("FLAGS") if isinstance(fields.get("FLAGS"), list) else []
    headers = message_from_bytes(_fetch_raw(conn, uid, "BODY.PEEK[HEADER]"), policy=policy.default)
    overview = {
        **_headers_dict(headers),
        "unread": "\\Seen" not in flags,
        "flagged": "\\Flagged" in flags,
        "size": int(fields["RFC822.SIZE"]) if str(fields.get("RFC822.SIZE", "")).isdigit() else None,
    }
    return overview, body, attachments


def _fetch_raw(conn: imaplib.IMAP4, uid: str, part: str = "BODY.PEEK[]") -> bytes:
    typ, data = conn.uid("FETCH", uid, f"({part})")
    if typ != "OK":
        raise MailRequestError(f"FETCH failed for UID {uid}.")
    for item in data:
        if isinstance(item, tuple):
            return item[1]
    raise MailRequestError(f"No message with UID {uid} in this folder.")


def message_info(settings: MailSettings, username: str, token: str, folder: str, uid: str) -> dict:
    """Headers, flags, size and attachment list; no body is downloaded."""
    uid = _check_uid(uid)
    with imap_session(settings, username, token) as conn:
        _select(conn, folder)
        overview, body, attachments = _fetch_overview(conn, uid)
    return {"uid": uid, "folder": folder, **overview,
            "body_type": body["content_type"] if body else None, "attachments": attachments}


def read_message(
    settings: MailSettings, username: str, token: str, folder: str, uid: str, max_chars: int, mark_read: bool
) -> dict:
    uid = _check_uid(uid)
    max_chars = max(1, min(int(max_chars), MAX_BODY_CHARS))
    with imap_session(settings, username, token) as conn:
        _select(conn, folder, readonly=not mark_read)
        overview, part, attachments = _fetch_overview(conn, uid)
        text, truncated = "", False
        if part is not None:
            # Enough encoded bytes for max_chars characters: up to 4 bytes of
            # UTF-8 each, times 4/3 for base64. HTML gets more, since tags go.
            budget = max_chars * (12 if part["content_type"] == "text/html" else 6)
            complete = part["size"] <= budget
            section = f"BODY.PEEK[{part['section']}]" + ("" if complete else f"<0.{budget}>")
            text = decode_part(_fetch_raw(conn, uid, section), part, complete)
            if part["content_type"] == "text/html":
                text = html_to_text(text)
            truncated = not complete or len(text) > max_chars
        if mark_read:
            conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
    return {
        "uid": uid, "folder": folder, **overview,
        "body": text[:max_chars], "body_truncated": truncated, "attachments": attachments,
    }


# ── Sending ──────────────────────────────────────────────────────────────────

def parse_recipients(values: list[str] | None, field: str) -> list[Address]:
    """Parse recipient strings ("Name <a@b>", "a@b, c@d") into addresses.

    Returns Address objects, not strings: the header and the SMTP envelope
    are built from exactly these, never by parsing a joined string again. A
    display name like "Boss, evil@example.org" would otherwise turn into a
    recipient of its own and push out the real address.
    """
    out: list[Address] = []
    for value in values or []:
        if re.search(r"[\x00-\x1f\x7f]", value):
            raise MailRequestError(f"{field} must not contain line breaks or control characters.")
        for name, addr in getaddresses([value]):
            if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
                raise MailRequestError(f"Invalid address in {field}: {value!r}.")
            try:
                out.append(Address(display_name=name, addr_spec=addr))
            except (ValueError, IndexError, MessageError):
                raise MailRequestError(f"Invalid address in {field}: {value!r}.") from None
    return out


_MSGID_RE = re.compile(r"<[^<>\s]+>")


def _reply_headers(conn: imaplib.IMAP4, uid: str) -> dict:
    """Threading headers of the message being answered.

    They come from someone else's mail, so only well-formed <message-ids>
    are taken over; encoded line breaks (=?utf-8?q?=0D=0A?=) would otherwise
    decode into header values Python refuses to set, failing the reply.
    """
    raw = _fetch_raw(conn, uid, "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID REFERENCES SUBJECT)]")
    headers = message_from_bytes(raw, policy=policy.default)
    ids = _MSGID_RE.findall(str(headers.get("Message-ID", "")))
    message_id = ids[0] if len(ids) == 1 else ""
    references = _MSGID_RE.findall(str(headers.get("References", ""))) + ([message_id] if message_id else [])
    subject = re.sub(r"[\x00-\x1f\x7f]+", " ", str(headers.get("Subject", ""))).strip()
    return {"message_id": message_id, "references": " ".join(references), "subject": subject}


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
    msg["To"] = to_addrs
    if cc_addrs:
        msg["Cc"] = cc_addrs
    if bcc_addrs:
        msg["Bcc"] = bcc_addrs  # kept for the Sent copy; never transmitted
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
            refused = smtp.send_message(
                msg, from_addr=username,
                to_addrs=[a.addr_spec for a in to_addrs + cc_addrs + bcc_addrs],
            )
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
