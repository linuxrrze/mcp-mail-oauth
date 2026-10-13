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
    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        if plain is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    if attachment:
        msg.add_attachment(b"%PDF-1.4", maintype="application", subtype="pdf", filename=attachment)
    return msg.as_bytes()


def test_parse_message_prefers_plain_and_decodes_headers():
    parsed = mail.parse_message(_raw(plain="Hallo\n", html="<p>HTML</p>", attachment="rechnung.pdf"), 1000)
    assert parsed["from"] == "Jürgen <j@example.com>"
    assert parsed["subject"] == "Grüße"
    assert parsed["body"] == "Hallo\n"
    assert parsed["attachments"] == [{"filename": "rechnung.pdf", "content_type": "application/pdf", "size": 8}]


def test_parse_message_html_only_is_converted():
    html = "<html><head><style>p{}</style></head><body><p>One</p><script>x()</script><p>Two &amp; three</p></body></html>"
    assert mail.parse_message(_raw(html=html), 1000)["body"] == "One\n\nTwo & three"


def test_parse_message_truncates():
    parsed = mail.parse_message(_raw(plain="x" * 50), 10)
    assert parsed["body"] == "x" * 10
    assert parsed["body_truncated"] is True


def test_parse_recipients():
    assert mail.parse_recipients(["Ann <ann@example.com>, bob@example.com"], "to") == [
        "Ann <ann@example.com>", "bob@example.com",
    ]
    for bad in (["not-an-address"], ["a@example.com\r\nBcc: x@evil.example"]):
        with pytest.raises(mail.MailRequestError):
            mail.parse_recipients(bad, "to")
