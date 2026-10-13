# Postfix + Dovecot for the disposable test stack, configured with the files
# from deploy/ (the ones users copy), only placeholders replaced.
#   DOVECOT=2.3 -> Debian bookworm: Dovecot 2.3.19, Postfix 3.7  (deploy/dovecot/2.3)
#   DOVECOT=2.4 -> Debian trixie:   Dovecot 2.4.1,  Postfix 3.10 (deploy/dovecot/2.4)
# Build context: the repository root.
ARG DOVECOT=2.3
FROM debian:bookworm-slim AS base-2.3
FROM debian:trixie-slim AS base-2.4
FROM base-${DOVECOT}
ARG DOVECOT

RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         dovecot-imapd dovecot-lmtpd postfix postfix-pcre ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 5000 --user-group --home-dir /var/mail --no-create-home vmail \
    && mkdir -p /var/mail && chown vmail:vmail /var/mail

COPY deploy/dovecot /opt/deploy/dovecot
COPY deploy/postfix /opt/deploy/postfix
COPY test-stack/mail/ /opt/test-stack/
RUN sh /opt/test-stack/configure.sh "${DOVECOT}"

EXPOSE 993 587
HEALTHCHECK --interval=5s --timeout=3s --retries=30 \
  CMD test -S /var/spool/postfix/private/auth && test -S /var/spool/postfix/private/dovecot-lmtp && postfix status
# Postfix's and Dovecot's master processes must start as root; they drop
# privileges themselves. Test-only image, never published.
# trivy:ignore:AVD-DS-0002
USER root
ENTRYPOINT ["/opt/test-stack/entrypoint.sh"]
