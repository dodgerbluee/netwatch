"""MQTT layer.

Two responsibilities:
  1. Publish state + Home Assistant auto-discovery messages so HA gets
     entities for free.
  2. Subscribe to a small command topic the HA automations can hit to
     mark devices known/blocked from a notification button.
"""

from __future__ import annotations
