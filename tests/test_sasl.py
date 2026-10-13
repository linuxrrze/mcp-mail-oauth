"""SASL message format and the IMAP/SMTP authentication exchanges, including
the error round both mechanisms use to report a rejected token."""

import base64
import imaplib
from dataclasses import replace

import pytest

from mcp_mail import mail


def test_xoauth2_payload():
    assert mail.sasl_initial_response("XOAUTH2", "a@b.de", "tok", "imap", 993) == (
        b"user=a@b.de\x01auth=Bearer tok\x01\x01"
    )


def test_oauthbearer_payload_escapes_gs2_name():
    payload = mail.sasl_initial_response("OAUTHBEARER", "we,ird=@b.de", "tok", "imap.b.de", 993)
    assert payload == b"n,a=we=2Cird=3D@b.de,\x01host=imap.b.de\x01port=993\x01auth=Bearer tok\x01\x01"


@pytest.mark.parametrize("username,token", [("a@b.de\x01auth=Bearer x", "tok"), ("a@b.de", "tok\r\nA1 LOGOUT")])
def test_control_characters_rejected(username, token):
    with pytest.raises(mail.MailRequestError):
        mail.sasl_initial_response("XOAUTH2", username, token, "h", 1)


class FakeIMAP:
    """Drives the authenticate() callback the way imaplib does."""

    def __init__(self, challenges, fail):
        self.challenges = challenges
        self.fail = fail
        self.responses = []

    def authenticate(self, mechanism, callback):
        self.mechanism = mechanism
        for challenge in self.challenges:
            self.responses.append(callback(challenge))
        if self.fail:
            raise imaplib.IMAP4.error("AUTHENTICATE failed.")
        return "OK", [b"Logged in"]


def test_imap_auth_success_sends_token_once(settings):
    conn = FakeIMAP([b""], fail=False)
    mail._imap_authenticate(conn, settings.mail, "a@b.de", "tok")
    assert conn.mechanism == "XOAUTH2"
    assert conn.responses == [b"user=a@b.de\x01auth=Bearer tok\x01\x01"]


def test_imap_auth_failure_answers_error_round_and_reports_it(settings):
    error_json = b'{"status":"401","schemes":"bearer"}'
    conn = FakeIMAP([b"", error_json], fail=True)
    with pytest.raises(mail.MailAuthError) as exc_info:
        mail._imap_authenticate(conn, settings.mail, "a@b.de", "tok")
    # Second response must be the empty error acknowledgement, not the token again.
    assert conn.responses[1] == b""
    assert '"status":"401"' in str(exc_info.value)
    assert "tok" not in str(exc_info.value).replace("token", "")


def test_oauthbearer_error_round_reply_is_ctrl_a(settings):
    conn = FakeIMAP([b"", b"{}"], fail=True)
    with pytest.raises(mail.MailAuthError):
        mail._imap_authenticate(conn, replace(settings.mail, sasl_mechanism="OAUTHBEARER"), "a@b.de", "tok")
    assert conn.responses[1] == b"\x01"


class FakeSMTP:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def docmd(self, cmd, args=""):
        self.sent.append(f"{cmd} {args}".strip())
        return self.replies.pop(0)


def test_smtp_auth_sends_token_as_continuation_not_inline(settings):
    smtp = FakeSMTP([(334, b""), (235, b"2.7.0 Authentication successful")])
    mail._smtp_authenticate(smtp, settings.mail, "a@b.de", "tok")
    assert smtp.sent[0] == "AUTH XOAUTH2"  # nothing inline: Postfix line_length_limit
    assert base64.b64decode(smtp.sent[1]) == b"user=a@b.de\x01auth=Bearer tok\x01\x01"


def test_smtp_auth_error_challenge(settings):
    error = base64.b64encode(b'{"status":"invalid_token"}')
    smtp = FakeSMTP([(334, b""), (334, error), (535, b"5.7.8 Authentication failed")])
    with pytest.raises(mail.MailAuthError, match="invalid_token"):
        mail._smtp_authenticate(smtp, settings.mail, "a@b.de", "tok")
    assert smtp.sent[2] == ""  # empty acknowledgement of the error challenge


def test_smtp_auth_mechanism_not_offered(settings):
    smtp = FakeSMTP([(504, b"5.5.4 Unrecognized authentication type")])
    with pytest.raises(mail.MailAuthError, match="refused AUTH XOAUTH2"):
        mail._smtp_authenticate(smtp, settings.mail, "a@b.de", "tok")
