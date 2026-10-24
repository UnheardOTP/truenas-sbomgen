"""Entry point: `python -m sbomgen` starts the scheduler and web UI; `python -m sbomgen scan` runs one scan."""
import logging
import sys

from . import schedule, web
from .config import Config
from .scan import scan


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    if sys.argv[1:] == ["scan"]:
        scan(cfg)
        return
    schedule.start(cfg)
    web.serve(cfg)


if __name__ == "__main__":
    main()
