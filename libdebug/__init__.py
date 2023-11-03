# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

from .oldlibdebug import Debugger as OldDebugger
from .libdebug import Debugger

logging.getLogger(__name__).addHandler(NullHandler())
