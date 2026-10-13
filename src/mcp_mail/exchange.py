"""RFC 8693 token exchange: the incoming MCP token for a mail-server token.

Only used with MAIL_TOKEN_EXCHANGE=on (docs/decisions.md, D23). The token a
client sends this server is then valid here only (`aud` = MCP_AUDIENCE); for
IMAP/SMTP the server, as Keycloak client OIDC_CLIENT_ID, exchanges it for a
separate token whose audience is the mail server's introspection client.
This is what the MCP authorization spec asks of servers that call upstream
APIs: a separate token, no pass-through.

Keycloak's standard token exchange (26.2+) requires the subject token to name
the requesting client in `aud`; MCP_AUDIENCE must therefore equal
OIDC_CLIENT_ID in this mode (checked in config.load).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections import OrderedDict

import httpx2

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# Exchanged tokens are reused until shortly before they expire: a tool call
# makes up to two mail connections (send + Sent copy), and a conversation many
# calls, all with the same incoming token.
EXPIRY_MARGIN = 30
CACHE_SIZE = 1000


class TokenExchangeError(Exception):
    """Keycloak refused or failed the exchange. The message is safe to show."""


def _exp(token: str) -> float | None:
    try:
        payload = token.split(".")[1]
        return float(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])
    except (IndexError, ValueError, KeyError, TypeError):
        return None


class TokenExchanger:
    def __init__(self, token_endpoint: str, client_id: str, client_secret: str, audience: str,
                 timeout: float = 10.0) -> None:
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.audience = audience
        self._auth = (client_id, client_secret)
        self._timeout = timeout
        # sha256(subject token) -> (mail token, usable until). Keys are
        # hashes so the cache never holds the incoming tokens themselves.
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def mail_token(self, subject_token: str) -> str:
        key = hashlib.sha256(subject_token.encode()).hexdigest()
        now = time.time()
        async with self._lock:
            hit = self._cache.get(key)
            if hit and hit[1] > now:
                self._cache.move_to_end(key)
                return hit[0]
        token = await self._exchange(subject_token)
        # Never past the subject token's own expiry: once that is gone, the
        # user's authorization is gone too, whatever Keycloak issued.
        usable_until = min(e for e in (_exp(token), _exp(subject_token), now + 300) if e is not None) - EXPIRY_MARGIN
        async with self._lock:
            self._cache[key] = (token, usable_until)
            self._cache.move_to_end(key)
            while len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)
        return token

    async def _exchange(self, subject_token: str) -> str:
        data = {
            "grant_type": GRANT_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": self.audience,
        }
        try:
            async with httpx2.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self.token_endpoint, data=data, auth=self._auth)
        except httpx2.HTTPError as exc:
            raise TokenExchangeError(f"Token exchange at {self.token_endpoint} failed: {exc}") from None
        if resp.status_code != 200:
            try:
                body = resp.json()
                reason = f"{body.get('error')}: {body.get('error_description', '')}".strip(": ")
            except ValueError:
                reason = resp.text[:200]
            logger.info("token exchange refused (%s): %s", resp.status_code, reason)
            raise TokenExchangeError(
                f"Keycloak refused to exchange your token for a mail token ({resp.status_code} {reason}). "
                f"Check: client {self.client_id!r} has standard token exchange enabled and the "
                f"`mail` scope as a default scope; your token has {self.client_id!r} in `aud`; "
                f"{self.audience!r} is an audience the `mail` scope adds (docs/keycloak.md)."
            )
        try:
            return resp.json()["access_token"]
        except (ValueError, KeyError):
            raise TokenExchangeError("Token exchange answered without an access_token.") from None
