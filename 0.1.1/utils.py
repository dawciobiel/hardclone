import logging


def parse_size(size_str: str) -> int:
    return 0


def format_size(size_bytes: int) -> str:
    return "0 B"


def setup_logging(level=logging.INFO):
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')


def validate_device_path(device_path: str) -> bool:
    return False
