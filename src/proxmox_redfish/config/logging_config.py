"""Logging configuration for the Proxmox Redfish daemon."""

import logging
import logging.handlers
import os

# Configure logging to send to system journal
# Logging configuration with configurable levels
logger = logging.getLogger("proxmox-redfish")

def setup_logging() -> None:
    """Setup logging configuration based on environment variables."""
    # Get logging level from environment variable
    # Valid levels: CRITICAL, ERROR, WARNING, INFO, DEBUG
    # Default to INFO for production use
    log_level_str = os.getenv("REDFISH_LOG_LEVEL", "INFO").upper()
    log_level_map = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }

    # Validate and set logging level
    if log_level_str in log_level_map:
        log_level = log_level_map[log_level_str]
    else:
        print(f"Warning: Invalid REDFISH_LOG_LEVEL '{log_level_str}', using INFO")
        log_level = logging.INFO

    # Check if logging is enabled at all
    logging_enabled = os.getenv("REDFISH_LOGGING_ENABLED", "true").lower() == "true"

    if logging_enabled:
        # Configure logging with the specified level
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(levelname)s:%(lineno)d: %(message)s",
            handlers=[logging.handlers.SysLogHandler(address="/dev/log")],
        )
        logger.setLevel(log_level)
        logger.info("Proxmox-Redfish daemon started with log level: %s", log_level_str)
    else:
        logger.handlers = [logging.NullHandler()]
        print("Logging disabled via REDFISH_LOGGING_ENABLED=false") 