# Netwatch — Home Assistant add-on

This directory contains the manifest + glue that wraps the upstream
`netwatch` Docker image as a HA add-on.

## Installing as an add-on

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add: `https://github.com/dodgerbluee/netwatch`
3. Install **Netwatch** from the new repository entry.
4. Fill in the UniFi credentials in the add-on configuration tab.
5. **Start** the add-on. The web UI is available under "Open Web UI".

The add-on stores its SQLite DB in `/share/netwatch/netwatch.db` so it
survives add-on updates.

## Notes

- Set `enforcement_enabled: false` until you've reviewed the device list
  in the web UI; otherwise everything currently online may get blocked.
- The default `mqtt.host` is `core-mosquitto`, which resolves inside the
  HA add-on Docker network and points at the official Mosquitto add-on.
