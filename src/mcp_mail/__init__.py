"""mcp-mail-oauth: an MCP server for OAuth-enabled IMAP/SMTP mailboxes."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-mail-oauth")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0"

# Authlib >= 1.8 warns on import when `httpx2` isn't installed. FastMCP's
# OAuth proxy imports Authlib's httpx client, so every start printed this
# warning, though neither FastMCP nor this package can act on it. Authlib
# forces its warnings to "always" when `authlib.deprecate` is imported, so the
# filter has to be added after that import to take precedence. Only this one
# message is silenced; other Authlib deprecations still show. (D21)
try:
    import warnings

    from authlib.deprecate import AuthlibDeprecationWarning

    warnings.filterwarnings(
        "ignore", message=r"The httpx module is deprecated", category=AuthlibDeprecationWarning
    )
except ImportError:  # Authlib absent or reorganised: nothing to silence
    pass
