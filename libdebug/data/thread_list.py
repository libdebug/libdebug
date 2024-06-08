#
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


class ThreadList(list):
    def __init__(self, debugger, *args):
        super().__init__(*args)
        # Reference to the debugger class instance
        self.debugger = debugger

    def __getitem__(self, index):
        # Ensure the process is stopped before accessing the thread list
        self.debugger._ensure_process_stopped()
        return super().__getitem__(index)
