FROM python:3.12-slim

# Version from CI (git tag vX.Y.Z without the "v"). .git isn't part of the
# build context, so setuptools-scm gets it injected instead of reading tags.
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="mcp-mail-oauth" \
      org.opencontainers.image.description="MCP server for OAuth-enabled IMAP/SMTP mailboxes" \
      org.opencontainers.image.version="${VERSION}"

# Apply pending Debian security updates: the base image tag lags behind, and
# CI fails the build on fixable HIGH/CRITICAL findings (docs/decisions.md, D20).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Non-root: this process holds users' bearer tokens in memory for the
# duration of a request; it has no business running as root.
RUN useradd --system --uid 10001 --home-dir /app app
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
# Build tooling isn't needed at runtime, and stale copies are a common source
# of scanner findings; the uninstall may find nothing to remove, which is fine.
RUN SETUPTOOLS_SCM_PRETEND_VERSION=${VERSION} pip install --no-cache-dir . \
    && (pip uninstall -y setuptools wheel || true)

# Only used in AUTH_MODE=proxy (DCR registrations, OAuth sessions). Mount a
# volume here so they survive container recreation (docs/decisions.md, D13).
ENV FASTMCP_HOME=/data
RUN mkdir /data && chown app /data
VOLUME /data

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz').status != 200)"
CMD ["mcp-mail-oauth"]
