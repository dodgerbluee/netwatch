# The HA add-on wraps the published GHCR image and translates the
# add-on's options.json into the env vars netwatch expects.

ARG BUILD_FROM=ghcr.io/dodgerbluee/netwatch:latest
FROM ${BUILD_FROM}

USER root

# bashio is available in HA add-on base images, but the published netwatch
# image is a plain python:slim — we need to install jq for option parsing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends jq curl \
    && rm -rf /var/lib/apt/lists/*

COPY run.sh /run.sh
RUN chmod +x /run.sh

USER netwatch
ENTRYPOINT ["/run.sh"]
