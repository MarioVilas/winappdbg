#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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

# $Id$

from winappdbg import Debug, EventHandler, HexDump


# This function will be called when our breakpoint is hit.
def action_callback( event ):
    process = event.get_process()
    thread  = event.get_thread()

    # Get the address of the top of the stack.
    stack   = thread.get_sp()

    # Get the return address of the call.
    address = process.read_pointer( stack )

    # Get the process and thread IDs.
    pid     = event.get_pid()
    tid     = event.get_tid()

    # Show a message to the user.
    message = "kernel32!CreateFileW called from %s by thread %d at process %d"
    print message % ( HexDump.address(address, process.get_bits()), tid, pid )


class MyEventHandler( EventHandler ):

    def load_dll( self, event ):

        # Get the new module object.
        module = event.get_module()

        # If it's kernel32.dll...
        if module.match_name("kernel32.dll"):

            # Get the process ID.
            pid = event.get_pid()

            # Get the address of CreateFile.
            address = module.resolve( "CreateFileW" )

            # Set a breakpoint at CreateFile.
            event.debug.break_at( pid, address, action_callback )

            # If you use stalk_at instead of break_at,
            # the message will only be shown once.
            #
            # event.debug.stalk_at( pid, address, action_callback )


def simple_debugger( argv ):

    # Instance a Debug object, passing it the MyEventHandler instance.
    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:

        # Start a new process for debugging.
        debug.execv( argv )

        # If you start the new process like this instead, the
        # debugger will automatically attach to the child processes.
        #
        # debug.execv( argv, bFollow = True )

        # Wait for the debugee to finish.
        debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
