import logging
from pathlib import Path

def setup_logger():
    log_path = Path.home() / ".antiworm" / "antiworm.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(log_path),
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    return logging.getLogger("antiworm")
