import logging
from canary_api.settings import server_log



class Logger():
    """Class for logging messages."""

    def __init__(self):
        """Initialize default values, such as log levels and log format"""

        self.logger = logging.getLogger('server')
        self.logger.setLevel(logging.DEBUG)

        ch = logging.FileHandler(server_log)
        ch.setLevel(logging.DEBUG)

        msg_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        formatter = logging.Formatter(msg_format)

        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def log_debug(self, message):
        """Log debug messages."""

        self.logger.debug(message)

    def log_info(self, message):
        """Log info messages."""

        self.logger.info(message)

    def log_warning(self, message):
        """Log warning messages."""

        self.logger.warning(message)

    def log_exception(self, message):
        """Log exceptions."""

        self.logger.exception(message)
