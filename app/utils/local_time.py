"""University clock for campus access and academic schedules.

Store local-naive timestamps for compatibility with existing UniTrack SQLite
records. Use the same explicit IANA timezone on every host.
"""
import os
from datetime import datetime
from zoneinfo import ZoneInfo


def campus_now():
    name = os.environ.get("UNITRACK_TIMEZONE", "America/Tijuana").strip()
    if not name:
        name = "America/Tijuana"
    return datetime.now(ZoneInfo(name)).replace(tzinfo=None)
