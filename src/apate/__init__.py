import logging
from pathlib import Path

logger = logging.getLogger('apate')

logger.setLevel(logging.INFO)

Formatter = logging.Formatter("%(levelname)s:%(asctime)s:%(message)s")

log_dir = Path("logs")
log_dir.mkdir(parents=True, exist_ok=True)

file_handler = logging.FileHandler(log_dir / "tasks.log")
file_handler.setFormatter(Formatter)

logger.addHandler(file_handler)
