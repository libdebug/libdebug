#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Gabriele Digregorio.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from contextlib import contextmanager
from copy import deepcopy

class LibContext:
    """
    A class that holds the global context of the library.
    """

    _instance = None

    def __new__(cls) -> 'LibContext':
        """Create a new instance of the class if it does not exist yet.
        
        Returns:
            LibContext: the instance of the class.
        """

        if cls._instance is None:
            cls._instance = super(LibContext, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance


    def __init__(self):
        """Initialize the context"""

        if self._initialized:
            return
        
        self._sym_lvl = 3

        self._initialized = True


    @property
    def sym_lvl(self) -> int:
        """
        Property getter for sym_lvl.

        Returns:
            _sym_lvl (int): the current symbol level.
        """
        return self._sym_lvl


    @sym_lvl.setter
    def sym_lvl(self, value: int):
        """
        Property setter for sym_lvl, ensuring it's between 0 and 4.
        """
        
        if 0 <= value <= 5:
            self._sym_lvl = value
        else:
            raise ValueError("sym_lvl must be between 0 and 4")


    def update(self, **kwargs):
        """
        Update the context with the given values.
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)


    @contextmanager
    def tmp(self, **kwargs):
        """
        Context manager that temporarily changes the library context. Use "with" statement.
        """
        # Make a deep copy of the current state
        old_context = deepcopy(self)  
        self.update(**kwargs)
        try:
            yield
        finally:
            # Restore the original state
            self.__dict__.update(old_context.__dict__)  
    

# Global context instance
libcontext = LibContext()