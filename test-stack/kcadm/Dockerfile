# kcadm.sh with the tools deploy/keycloak/setup-kcadm.sh uses (bash, grep,
# awk). Keycloak's own image is too minimal to rely on for those.
ARG KEYCLOAK_VERSION=26.8.1
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS keycloak
FROM eclipse-temurin:21-jre
COPY --from=keycloak /opt/keycloak/bin /opt/keycloak/bin
ENV PATH=/opt/keycloak/bin:$PATH
