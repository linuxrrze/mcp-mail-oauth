import contextlib
import re
from email.message import EmailMessage

import pytest

from mcp_mail import mail


@pytest.mark.parametrize("name,encoded", [
    ("INBOX", "INBOX"),
    ("Entwürfe", "Entw&APw-rfe"),
    ("Gesendete Objekte", "Gesendete Objekte"),
    ("R&D", "R&-D"),
    ("日本語", "&ZeVnLIqe-"),
])
def test_modified_utf7_roundtrip(name, encoded):
    assert mail.encode_mailbox(name) == encoded
    assert mail.decode_mailbox(encoded) == name


def test_parse_list_quoted_and_literal():
    assert mail._parse_list_line(b'(\\HasNoChildren \\Sent) "/" "Sent"') == {"name": "Sent", "flags": ["\\HasNoChildren", "\\Sent"]}
    assert mail._parse_list_line(b'(\\HasNoChildren) "." INBOX')["name"] == "INBOX"
    assert mail._parse_list_line(b'() "/" "Entw&APw-rfe"')["name"] == "Entwürfe"
    assert mail._parse_list_line((b'(\\HasNoChildren) "/" {11}', b'odd "name"'))["name"] == 'odd "name"'


def test_parse_fetch_meta():
    meta = mail._parse_fetch_meta(b"3 (UID 42 FLAGS (\\Seen \\Flagged) RFC822.SIZE 1234 BODY[HEADER.FIELDS (FROM)] {20}")
    assert meta == {"uid": "42", "flags": ["\\Seen", "\\Flagged"], "size": 1234}
    assert mail._parse_fetch_meta(b"1 (UID 7 FLAGS () RFC822.SIZE 9")["flags"] == []


def test_build_search_combines_ascii_and_separates_utf8():
    ascii_parts, literals = mail.build_search(
        from_="bob@example.com", subject="Müller", text='say "hi"', since="2026-01-05", unread_only=True,
    )
    assert ascii_parts == ["FROM", '"bob@example.com"', "TEXT", '"say \\"hi\\""', "SINCE", "05-Jan-2026", "UNSEEN"]
    assert literals == [("SUBJECT", "Müller")]


@pytest.mark.parametrize("kwargs", [{"since": "05.01.2026"}, {"subject": "a\r\nb"}])
def test_build_search_rejects_bad_input(kwargs):
    with pytest.raises(mail.MailRequestError):
        mail.build_search(**kwargs)


def _raw(plain=None, html=None, attachment=None):
    msg = EmailMessage()
    msg["From"] = "=?utf-8?q?J=C3=BCrgen?= <j@example.com>"
    msg["To"] = "a@example.com"
    msg["Subject"] = "=?utf-8?q?Gr=C3=BC=C3=9Fe?="
    msg["Message-ID"] = "<m1@example.com>"
    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        if plain is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    if attachment:
        msg.add_attachment(b"%PDF-1.4" * 1000, maintype="application", subtype="pdf", filename=attachment)
    return msg


# ── A fake IMAP server answering from an EmailMessage ─────────────────────────
# BODYSTRUCTURE built the way RFC 3501 lays it out (and Dovecot sends it), so
# read_message/message_info run their real code path: structure, header and
# only the fetched section.

def _q(value):
    return b"NIL" if value is None else b'"' + value.encode().replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def _plist(pairs):
    return b"(" + b" ".join(_q(k) + b" " + _q(v) for k, v in pairs) + b")" if pairs else b"NIL"


def _structure(part, section, sections):
    if part.is_multipart():
        children = [_structure(child, f"{section}.{i}" if section else str(i), sections)
                    for i, child in enumerate(part.iter_parts(), 1)]
        return b"(" + b"".join(children) + b" " + _q(part.get_content_subtype()) + b")"
    payload = part.get_payload().replace("\r\n", "\n").replace("\n", "\r\n").encode()
    sections[section or "1"] = payload
    params = [(k, v) for k, v in part.get_params()[1:]]
    dispo = part.get_content_disposition()
    dparams = [("filename", part.get_filename())] if part.get_filename() else []
    fields = [_q(part.get_content_maintype()), _q(part.get_content_subtype()), _plist(params), b"NIL", b"NIL",
              _q(part.get("Content-Transfer-Encoding", "7bit")), str(len(payload)).encode()]
    if part.get_content_maintype() == "text":
        fields.append(str(payload.count(b"\n")).encode())
    fields += [b"NIL", b"(" + _q(dispo) + b" " + _plist(dparams) + b")" if dispo else b"NIL"]
    return b"(" + b" ".join(fields) + b")"


class FakeIMAP:
    def __init__(self, msg, flags=b""):
        self.sections = {}
        self.structure = _structure(msg, "", self.sections)
        self.raw = msg.as_bytes()
        self.header = self.raw.split(b"\n\n", 1)[0] + b"\n\n"
        self.flags = flags
        self.fetched = []

    def uid(self, command, uid, *args):
        if command == "STORE":
            self.stored = args
            return "OK", [b""]
        what = args[0]
        self.fetched.append(what)
        if uid != "7":
            return "OK", [None]
        if "BODYSTRUCTURE" in what:
            return "OK", [b"1 (UID 7 FLAGS (" + self.flags + b") RFC822.SIZE %d BODYSTRUCTURE " % len(self.raw)
                          + self.structure + b")"]
        if what == "(BODY.PEEK[HEADER])":
            return "OK", [(b"1 (UID 7 BODY[HEADER] {%d}" % len(self.header), self.header), b")"]
        m = re.fullmatch(r"\(BODY\.PEEK\[([\d.]+)\](?:<0\.(\d+)>)?\)", what)
        data = self.sections[m.group(1)]
        if m.group(2):
            data = data[:int(m.group(2))]
        return "OK", [(b"1 (UID 7 BODY[%s] {%d}" % (m.group(1).encode(), len(data)), data), b")"]


@pytest.fixture
def imap(monkeypatch):
    holder = {}

    @contextlib.contextmanager
    def session(settings, username, token):
        yield holder["conn"]

    monkeypatch.setattr(mail, "imap_session", session)
    monkeypatch.setattr(mail, "_select", lambda conn, folder, readonly=True: None)

    def use(msg, **kwargs):
        holder["conn"] = FakeIMAP(msg, **kwargs)
        return holder["conn"]

    return use


def _read(max_chars=1000, mark_read=False, uid="7"):
    return mail.read_message(None, "a@example.com", "t", "INBOX", uid, max_chars, mark_read)


def test_read_message_prefers_plain_and_never_fetches_attachments(imap):
    conn = imap(_raw(plain="Hallo\n", html="<p>HTML</p>", attachment="rechnung.pdf"))
    parsed = _read()
    assert parsed["from"] == "Jürgen <j@example.com>"
    assert parsed["subject"] == "Grüße"
    assert parsed["body"] == "Hallo\n"
    [att] = parsed["attachments"]
    assert att["filename"] == "rechnung.pdf" and att["content_type"] == "application/pdf"
    assert abs(att["size"] - 8000) < 50  # estimated from the encoded size
    # The PDF's section (1.2 is the HTML alternative, 2 the PDF) is never fetched.
    assert conn.fetched == ["(UID FLAGS RFC822.SIZE BODYSTRUCTURE)", "(BODY.PEEK[HEADER])", "(BODY.PEEK[1.1])"]
    assert parsed["unread"] is True


def test_read_message_html_only_is_converted(imap):
    html = "<html><head><style>p{}</style></head><body><p>One</p><script>x()</script><p>Two &amp; three</p></body></html>"
    imap(_raw(html=html))
    assert _read()["body"] == "One\n\nTwo & three"


def test_read_message_truncates_and_fetches_only_a_prefix(imap):
    conn = imap(_raw(plain="ü" * 5000))  # base64 or QP-encoded UTF-8
    parsed = _read(max_chars=10)
    assert parsed["body"] == "ü" * 10
    assert parsed["body_truncated"] is True
    assert conn.fetched[-1].endswith("<0.60>)")


@pytest.mark.parametrize("cte", ["base64", "quoted-printable", "8bit"])
def test_read_message_decodes_each_transfer_encoding_even_when_cut(imap, cte):
    msg = EmailMessage()
    msg.set_content("Grüße aus Erlangen " * 400, cte=cte)
    imap(msg)
    for max_chars in (7, 100, 19 * 400):
        body = _read(max_chars=max_chars)["body"]
        assert body == ("Grüße aus Erlangen " * 400)[:max_chars], (cte, max_chars)


def test_message_info_has_no_body_and_fetches_no_part(imap):
    conn = imap(_raw(plain="secret body", attachment="a.pdf"), flags=b"\\Seen \\Flagged")
    info = mail.message_info(None, "a@example.com", "t", "INBOX", "7")
    assert "body" not in info and info["body_type"] == "text/plain"
    assert info["subject"] == "Grüße" and info["message_id"] == "<m1@example.com>"
    assert (info["unread"], info["flagged"]) == (False, True)
    assert [a["filename"] for a in info["attachments"]] == ["a.pdf"]
    assert all("BODY.PEEK[1" not in f and "BODY.PEEK[2" not in f for f in conn.fetched)


def test_unknown_uid_and_bad_uid(imap):
    imap(_raw(plain="x"))
    with pytest.raises(mail.MailRequestError, match="No message"):
        _read(uid="8")
    for bad in ("²", "1:*", "7 8"):
        with pytest.raises(mail.MailRequestError, match="Invalid message UID"):
            _read(uid=bad)


def test_mark_read_stores_seen(imap):
    conn = imap(_raw(plain="x"))
    _read(mark_read=True)
    assert conn.stored == ("+FLAGS", "(\\Seen)")


def test_parse_sexp_literals_nil_and_escapes():
    data = b'1 (UID 7 BODYSTRUCTURE ("application" "pdf" ("name" {11}\r\nR\xc3\xa4 "x".pdf) NIL NIL "base64" 400 NIL ("attachment" ("filename" "a\\"b.pdf")) NIL NIL))'
    parsed = mail.parse_sexp(data)
    assert parsed[0] == "1"
    attrs = parsed[1]
    structure = attrs[3]
    assert structure[2] == ["name", 'Rä "x".pdf']
    assert structure[3] is None
    [part] = mail.flatten_bodystructure(structure)
    _, attachments = mail.split_parts([part])
    assert attachments == [{"filename": 'a"b.pdf', "content_type": "application/pdf", "size": 292}]


def test_response_bytes_puts_literals_back_inline():
    data = [(b'1 (UID 7 BODYSTRUCTURE ("text" "plain" ("name" {3}', b"abc"), b') NIL NIL "7bit" 1 1))']
    assert mail._response_bytes(data) == b'1 (UID 7 BODYSTRUCTURE ("text" "plain" ("name" {3}\r\nabc) NIL NIL "7bit" 1 1))'


@pytest.mark.parametrize("dparams,expected", [
    ({"filename": "=?utf-8?q?Rechnung_M=C3=A4rz.pdf?="}, "Rechnung März.pdf"),
    ({"filename*": "utf-8''R%C3%A4chnung.pdf"}, "Rächnung.pdf"),
    ({"filename*0": "abc", "filename*1": "def.pdf"}, "abcdef.pdf"),
    ({"filename": 'evil"\r\nX-Injected: 1'}, 'evil"X-Injected: 1'),
])
def test_attachment_filenames_are_decoded(dparams, expected):
    part = {"section": "2", "content_type": "application/pdf", "params": {}, "encoding": "base64", "size": 4,
            "disposition": "attachment", "dparams": dparams}
    assert mail.split_parts([part])[1][0]["filename"] == expected


def test_parse_recipients():
    assert [str(a) for a in mail.parse_recipients(["Ann <ann@example.com>, bob@example.com"], "to")] == [
        "Ann <ann@example.com>", "bob@example.com",
    ]


def test_display_name_cannot_smuggle_a_recipient():
    """A comma in a display name used to split it into a recipient of its own,
    replacing the real address (security review, finding 1)."""
    [addr] = mail.parse_recipients(['"Boss, evil@attacker.example" <boss@example.com>'], "to")
    assert addr.addr_spec == "boss@example.com"
    msg = EmailMessage()
    msg["To"] = [addr]
    assert [a.addr_spec for a in msg["To"].addresses] == ["boss@example.com"]
    for bad in (["not-an-address"], ["a@example.com\r\nBcc: x@evil.example"]):
        with pytest.raises(mail.MailRequestError):
            mail.parse_recipients(bad, "to")


class _HeaderConn:
    def __init__(self, raw):
        self.raw = raw

    def uid(self, *args):
        return "OK", [(b"1 (UID 7 BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES SUBJECT)] {%d}" % len(self.raw), self.raw), b")"]


def test_reply_headers_from_a_hostile_message_are_reduced_to_message_ids():
    raw = (b"Message-ID: =?utf-8?q?<a@b>=0D=0ABcc:_x@evil?=\r\n"
           b"References: <r1@x> =?utf-8?q?=0D=0ABcc:_y@evil?= <r2@x>\r\n"
           b"Subject: =?utf-8?q?hi=0D=0ABcc:_x@evil?=\r\n\r\n")
    headers = mail._reply_headers(_HeaderConn(raw), "7")
    assert headers == {"message_id": "<a@b>", "references": "<r1@x> <r2@x> <a@b>", "subject": "hi Bcc: x@evil"}
    msg = EmailMessage()
    msg["In-Reply-To"], msg["References"], msg["Subject"] = headers["message_id"], headers["references"], headers["subject"]
    assert b"\nBcc" not in msg.as_bytes()


def test_send_message_envelope_is_exactly_the_given_addresses(monkeypatch):
    sent = {}

    class FakeSMTP:
        def send_message(self, msg, from_addr, to_addrs):
            sent.update(msg=msg, from_addr=from_addr, to_addrs=to_addrs)
            return {}

    @contextlib.contextmanager
    def session(settings, username, token):
        yield FakeSMTP()

    monkeypatch.setattr(mail, "smtp_session", session)
    cfg = type("Cfg", (), {"sent_folder": ""})()
    result = mail.send_message(cfg, "alice@example.com", "t", to=['"Boss, evil@attacker.example" <boss@example.com>'],
                               cc=["Ann <ann@example.com>"], bcc=["hidden@example.com"], subject="s", body="b")
    assert result["status"] == "sent"
    assert sent["to_addrs"] == ["boss@example.com", "ann@example.com", "hidden@example.com"]
    assert sent["from_addr"] == "alice@example.com"
    assert [a.addr_spec for a in sent["msg"]["To"].addresses] == ["boss@example.com"]
