#!~/.wine/drive_c/Python25/python.exe
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

# $Id$

from sys import exit

from winappdbg import win32, Debug, HexDump, Crash

try:
    from winappdbg import CrashDAO
except ImportError:
    raise ImportError("Error: SQLAlchemy is not installed!")

def my_event_handler( event ):

    # Get the event name.
    name = event.get_event_name()

    # Get the event code.
    code = event.get_event_code()

    # Get the process ID where the event occured.
    pid = event.get_pid()

    # Get the thread ID where the event occured.
    tid = event.get_tid()

    # Get the value of EIP at the thread.
    pc = event.get_thread().get_pc()

    # Show something to the user.
    bits = event.get_process().get_bits()
    format_string = "%s (%s) at address %s, process %d, thread %d"
    message = format_string % ( name,
                                HexDump.integer(code, bits),
                                HexDump.address(pc, bits),
                                pid,
                                tid )
    print message

    # If the event is a crash...
    if code == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
        print "Crash detected, storing crash dump in database..."

        # Generate a minimal crash dump.
        crash = Crash( event )

        # You can turn it into a full crash dump (recommended).
        # crash.fetch_extra_data( event, takeMemorySnapshot = 0 ) # no memory dump
        # crash.fetch_extra_data( event, takeMemorySnapshot = 1 ) # small memory dump
        crash.fetch_extra_data( event, takeMemorySnapshot = 2 ) # full memory dump

        # Connect to the database. You can use any URL supported by SQLAlchemy.
        # For more details see the reference documentation.
        dao = CrashDAO( "sqlite:///crashes.sqlite" )
        #dao = CrashDAO( "mysql+MySQLdb://root:toor@localhost/crashes" )

        # Store the crash dump in the database.
        dao.add( crash )

        # If you do this instead, heuristics are used to detect duplicated
        # crashes so they aren't added to the database.
        # dao.add( crash, allow_duplicates = False )

        # You can also launch the interactive debugger from here. Try it! :)
        # event.debug.interactive()

        # Kill the process.
        event.get_process().kill()

def simple_debugger( argv ):

    # Instance a Debug object, passing it the event handler callback.
    debug = Debug( my_event_handler, bKillOnExit = True )
    try:

        # Start a new process for debugging.
        debug.execv( argv )

        # Wait for the debugee to finish.
        debug.loop()

    # Stop the debugger.
    finally:
        debug.stop()

# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
