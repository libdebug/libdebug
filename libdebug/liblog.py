import logging
import sys


class LogColors:
    RED = '\033[91m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RESET = '\033[0m'


class LibLog:
    """Custom logger class that can be used to log messages to the console.
    It is a singleton class, so that it is instantiated only once.
    """

    _instance = None


    def __new__(cls) -> 'LibLog':
        """Create a new instance of the class if it does not exist yet.
        
        Returns:
            CustomLogger: the instance of the class.
        """

        if cls._instance is None:
            cls._instance = super(LibLog, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance


    def __init__(self):
        """Initialize the logger"""

        if self._initialized:
            return
        
        # General logger
        self.general_logger = self._setup_logger("libdebug", logging.INFO)

        # Component-specific loggers
        self.debugger_logger = self._setup_logger("debugger", logging.INFO)
        self.pipe_logger = self._setup_logger("pipe", logging.INFO)

        # Adjust log levels based on command-line arguments
        if len(sys.argv) > 1:
            if "DEBUGGER" in sys.argv:
                self.debugger_logger.setLevel(logging.DEBUG)
            elif "PIPE" in sys.argv:
                self.pipe_logger.setLevel(logging.DEBUG)
            elif "DBG" in sys.argv:
                self._set_debug_level_for_all()

        self._initialized = True


    def _setup_logger(self, name: str, level: int) -> logging.Logger:
        """Setup a logger with the given name and level.

        Args:
            name (str): name of the logger.
            level (int): logging level.

        Returns:
            logging.Logger: the logger object.
        """

        logger = logging.getLogger(name)
        logger.setLevel(level)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger


    def _set_debug_level_for_all(self):
        """Set the debug level for all the loggers to DEBUG"""

        for logger in [self.general_logger, self.debugger_logger, self.pipe_logger]:
            logger.setLevel(logging.DEBUG)

    
    def debugger(self, message: str, *args, **kwargs):
        """Log a message to the debugger logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """

        header = f"[{LogColors.RED}DEBUGGER{LogColors.RESET}]"
        self.debugger_logger.debug(f"{header} {message}", *args, **kwargs)

    
    def pipe(self, message: str, *args, **kwargs):
        """Log a message to the pipe logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """

        header = f"[{LogColors.BLUE}PIPE{LogColors.RESET}]"
        self.pipe_logger.debug(f"{header} {message}", *args, **kwargs)
    

    def info(self, message: str, *args, **kwargs):
        """Log a info message to the general logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """

        header = f"[{LogColors.GREEN}INFO{LogColors.RESET}]"
        self.general_logger.info(f"{header} {message}", *args, **kwargs)


# Create the logger instance
liblog = LibLog()