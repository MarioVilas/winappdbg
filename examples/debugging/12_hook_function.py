#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
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

from winappdbg.debug import Debug
from winappdbg.event import EventHandler
from winappdbg.win32 import PVOID


# This function will be called when the hooked function is entered.
def wsprintf(event, ra, lpOut, lpFmt):
    # Get the format string.
    process = event.get_process()
    lpFmt = process.peek_string(lpFmt, fUnicode=True)

    # Get the vararg parameters.
    count = lpFmt.replace("%%", "%").count("%")
    thread = event.get_thread()
    if process.get_bits() == 32:
        parameters = thread.read_stack_dwords(count, offset=3)
    else:
        parameters = thread.read_stack_qwords(count, offset=3)

    # Show a message to the user.
    showparams = ", ".join([hex(x) for x in parameters])
    print("wsprintf( %r, %s );" % (lpFmt, showparams))


class MyEventHandler(EventHandler):
    def load_dll(self, event):
        # Get the new module object.
        module = event.get_module()

        # If it's user32...
        if module.match_name("user32.dll"):
            # Get the process ID.
            pid = event.get_pid()

            # Get the address of wsprintf.
            address = module.resolve("wsprintfW")

            # This is an approximated signature of the wsprintf function.
            # Pointers must be void so ctypes doesn't try to read from them.
            # Varargs are obviously not included.
            signature = (PVOID, PVOID)

            # Hook the wsprintf function.
            event.debug.hook_function(pid, address, wsprintf, signature=signature)

            # Use stalk_function instead of hook_function
            # to be notified only the first time the function is called.
            #
            # event.debug.stalk_function( pid, address, wsprintf, signature = signature)


def simple_debugger(argv):
    # Instance a Debug object, passing it the MyEventHandler instance.
    with Debug(MyEventHandler(), bKillOnExit=True) as debug:
        # Start a new process for debugging.
        debug.execv(argv)

        # Wait for the debugee to finish.
        debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys

    simple_debugger(sys.argv[1:])
