# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

from .libdebug import debugger

logging.getLogger(__name__).addHandler(NullHandler())
