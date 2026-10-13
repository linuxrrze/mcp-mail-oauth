"""Entry point: `python -m mcp_mail` or the `mcp-mail-oauth` console script."""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv

from . import __version__
from .config import ConfigError, load
from .server import MCP_PATH, client_settings, create_server, http_middleware


def main() -> None:
    load_dotenv()  # a local .env, if present; real env vars take precedence
    # LOG_LEVEL configures this package's loggers (via the root logger).
    # FastMCP configures its own "fastmcp" logger separately from
    # FASTMCP_LOG_LEVEL and doesn't propagate to root, so without this the
    # package's own log lines would be dropped (finding from the predecessor).
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = load()
        mcp = create_server(settings)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    log = logging.getLogger(__name__)
    log.info(
        "Starting mcp-mail-oauth %s in AUTH_MODE=%s, issuer=%s, audience=%s, IMAP %s:%s, SMTP %s:%s",
        __version__, settings.auth_mode, settings.oidc_issuer, settings.mcp_audience,
        settings.mail.imap_host, settings.mail.imap_port, settings.mail.smtp_host, settings.mail.smtp_port,
    )
    for line in client_settings(settings):
        log.info("%s", line)
    # Stateless HTTP (D12): no MCP session state in this process, so restarts
    # and multiple replicas behind a load balancer need no session affinity.
    # No banner: besides log noise, showing it makes FastMCP query pypi.org
    # for updates on every start, an outbound call a mail server has no need for.
    mcp.run(
        transport="http", host=settings.host, port=settings.port, path=MCP_PATH,
        stateless_http=True, show_banner=False, middleware=http_middleware(settings),
    )


if __name__ == "__main__":
    main()
