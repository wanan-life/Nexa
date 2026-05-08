import logging

from app.config import get_settings


def setup_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)

