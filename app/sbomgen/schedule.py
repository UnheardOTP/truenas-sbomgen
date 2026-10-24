"""Runs scans on the configured schedule (container TZ applies)."""
import logging
import threading
import time
from datetime import datetime, timedelta

from .config import Config
from .scan import scan

log = logging.getLogger("sbomgen")
DOW = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def next_run(cfg: Config, now: datetime | None = None) -> datetime | None:
    if cfg.schedule not in ("daily", "weekly"):
        return None
    now = now or datetime.now()
    try:
        hh, mm = (int(x) for x in cfg.sched_time.split(":", 1))
    except ValueError:
        hh, mm = 3, 17
    cand = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if cfg.schedule == "daily":
        return cand if cand > now else cand + timedelta(days=1)
    target = DOW.index(cfg.sched_dow) if cfg.sched_dow in DOW else 6
    cand += timedelta(days=(target - now.weekday()) % 7)
    return cand if cand > now else cand + timedelta(days=7)


def start(cfg: Config) -> None:
    def loop():
        while True:
            when = next_run(cfg)
            if when is None:
                log.info("schedule is off; scans run only from the web page")
                return
            log.info("next scheduled scan: %s", when.isoformat(timespec="minutes"))
            while (wait := (when - datetime.now()).total_seconds()) > 0:
                time.sleep(min(wait, 300))   # re-check, so clock changes don't strand the timer
            scan(cfg)
    threading.Thread(target=loop, name="scheduler", daemon=True).start()
