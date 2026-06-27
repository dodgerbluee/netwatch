#!/usr/bin/env sh
# Translate HA add-on options.json into NETWATCH_* env vars, then exec the
# main service. Runs as the unprivileged `netwatch` user (the base image
# already created it with UID/GID 10001).

set -eu

OPTIONS=/data/options.json
if [ ! -f "$OPTIONS" ]; then
  echo "no options.json at $OPTIONS; running with defaults"
fi

j() { jq -r "$1 // empty" "$OPTIONS" 2>/dev/null || true; }

export NETWATCH_LOG_LEVEL="$(j '.log_level')"
export NETWATCH_ENFORCEMENT_ENABLED="$(j '.enforcement_enabled')"

export NETWATCH_UNIFI_HOST="$(j '.unifi.host')"
export NETWATCH_UNIFI_SITE="$(j '.unifi.site')"
export NETWATCH_UNIFI_USERNAME="$(j '.unifi.username')"
export NETWATCH_UNIFI_PASSWORD="$(j '.unifi.password')"
export NETWATCH_UNIFI_VERIFY_TLS="$(j '.unifi.verify_tls')"
export NETWATCH_UNIFI_BOOTSTRAP_GRACE_SECONDS="$(j '.unifi.bootstrap_grace_seconds')"

export NETWATCH_MQTT_HOST="$(j '.mqtt.host')"
export NETWATCH_MQTT_PORT="$(j '.mqtt.port')"
export NETWATCH_MQTT_USERNAME="$(j '.mqtt.username')"
export NETWATCH_MQTT_PASSWORD="$(j '.mqtt.password')"
export NETWATCH_MQTT_DISCOVERY_PREFIX="$(j '.mqtt.discovery_prefix')"
export NETWATCH_MQTT_BASE_TOPIC="$(j '.mqtt.base_topic')"

export NETWATCH_OPNSENSE_HOST="$(j '.opnsense.host')"
export NETWATCH_OPNSENSE_API_KEY="$(j '.opnsense.api_key')"
export NETWATCH_OPNSENSE_API_SECRET="$(j '.opnsense.api_secret')"

# Use /share for persistence so DB survives add-on updates.
export NETWATCH_DATA_DIR="/share/netwatch"
mkdir -p "$NETWATCH_DATA_DIR"

exec netwatch
