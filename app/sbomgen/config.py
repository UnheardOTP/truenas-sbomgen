"""Settings, all from environment variables (set them in the TrueNAS app's YAML)."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _yes(name: str, default: str = "yes") -> bool:
    return _env(name, default).lower() in ("1", "yes", "true", "on")


@dataclass(frozen=True)
class Config:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "/data")))
    host_root: Path = field(default_factory=lambda: Path(_env("HOST_ROOT", "/host")))
    scan_host: bool = field(default_factory=lambda: _yes("SCAN_HOST"))
    scan_containers: bool = field(default_factory=lambda: _yes("SCAN_CONTAINERS"))
    vuln_scan: bool = field(default_factory=lambda: _yes("VULN_SCAN"))
    keep_runs: int = field(default_factory=lambda: int(_env("KEEP_RUNS", "12") or 0))
    schedule: str = field(default_factory=lambda: _env("SCHEDULE", "weekly").lower())   # daily | weekly | off
    sched_dow: str = field(default_factory=lambda: _env("SCHED_DOW", "sun").lower()[:3])
    sched_time: str = field(default_factory=lambda: _env("SCHED_TIME", "03:17"))
    notify: str = field(default_factory=lambda: _env("NOTIFY", "new").lower())          # new | always | off
    webhook_url: str = field(default_factory=lambda: _env("WEBHOOK_URL"))
    dt_url: str = field(default_factory=lambda: _env("DT_URL").rstrip("/"))
    dt_api_key: str = field(default_factory=lambda: _env("DT_API_KEY"))
    ui_user: str = field(default_factory=lambda: _env("UI_USER", "admin"))
    ui_password: str = field(default_factory=lambda: _env("UI_PASSWORD"))
    port: int = field(default_factory=lambda: int(_env("PORT", "8099")))
    docker_host: str = field(default_factory=lambda: _env("DOCKER_HOST"))

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def latest(self) -> Path:
        return self.data_dir / "latest"
