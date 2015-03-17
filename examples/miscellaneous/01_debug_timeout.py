#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2015, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# This line is needed in Python 2.5 to use the "with" statement.
from __future__ import with_statement

from winappdbg import *
from time import time

# Using the Debug object in a "with" context ensures proper cleanup.
with Debug( bKillOnExit = True ) as dbg:

    # Run the Windows Calculator (calc.exe).
    dbg.execl('calc.exe')

    # For the extra paranoid: this makes sure calc.exe dies
    # even if our own process is killed from the Task Manager.
    System.set_kill_on_exit_mode(True)

    # The execution time limit is 5 seconds.
    maxTime = time() + 5

    # Loop while calc.exe is alive and the time limit wasn't reached.
    while dbg and time() < maxTime:
        try:

            # Get the next debug event.
            dbg.wait(1000)  # 1 second accuracy

            # Show the current time on screen.
            print time()

        # If wait() times out just try again.
        # On any other error stop debugging.
        except WindowsError, e:
            if e.winerror in (win32.ERROR_SEM_TIMEOUT,
                              win32.WAIT_TIMEOUT):
                continue
            raise

        # Dispatch the event and continue execution.
        try:
            dbg.dispatch()
        finally:
            dbg.cont()
