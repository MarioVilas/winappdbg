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

from winappdbg import Debug, EventHandler, System, HexDump, win32


class MyHook (object):

    # Keep record of the buffers we watch.
    def __init__(self):
        self.__watched  = dict()
        self.__previous = None


    # This function will be called when entering the hooked function.
    def entering( self, event, ra, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped ):

        # Ignore calls using a NULL pointer.
        if not lpBuffer:
            return

        # Show a message to the user.
        print "\nReadFile:\n\tHandle %x\n\tExpected bytes: %d" % ( hFile, nNumberOfBytesToRead )

        # Stop watching the previous buffer.
        if self.__previous:
            event.debug.dont_watch_buffer( self.__previous )
            self.__previous = None

        # Remember the location of the buffer and its size.
        self.__watched[ event.get_tid() ] = ( lpBuffer, lpNumberOfBytesRead )


    # This function will be called when leaving the hooked function.
    def leaving( self, event, return_value ):

        # If the function call failed ignore it.
        if return_value == 0:
            print "\nReadFile:\n\tStatus: FAIL"
            return

        # Get the buffer location and size.
        tid     = event.get_tid()
        process = event.get_process()
        ( lpBuffer, lpNumberOfBytesRead ) = self.__watched[ tid ]
        del self.__watched[ tid ]

        # Watch the buffer for access.
        pid     = event.get_pid()
        address = lpBuffer
        size    = process.read_dword( lpNumberOfBytesRead )
        action  = self.accessed
        self.__previous = event.debug.watch_buffer( pid, address, size, action )

        # Use stalk_buffer instead of watch_buffer to be notified
        # only of the first access to the buffer.
        #
        # self.__previous = event.debug.stalk_buffer( pid, address, size, action )

        # Show a message to the user.
        print "\nReadFile:\n\tStatus: SUCCESS\n\tRead bytes: %d" % size


    # This function will be called every time the procedure name buffer is accessed.
    def accessed( self, event ):

        # Show the user where we're running.
        thread = event.get_thread()
        pc     = thread.get_pc()
        code   = thread.disassemble( pc, 0x10 ) [0]
        print "%s: %s" % (
            HexDump.address(code[0], thread.get_bits()),
            code[2].lower()
        )


class MyEventHandler( EventHandler ):

    # Called on guard page exceptions NOT raised by our breakpoints.
    def guard_page( self, event ):
        print event.get_exception_name()

    # Called on DLL load events.
    def load_dll( self, event ):

        # Get the new module object.
        module = event.get_module()

        # If it's kernel32...
        if module.match_name( "kernel32.dll" ):

            # Get the process ID.
            pid = event.get_pid()

            # Get the address of the function to hook.
            address = module.resolve( "ReadFile" )

            # This is an approximated signature of the function.
            # Pointers must be void so ctypes doesn't try to read from them.
            signature = ( win32.HANDLE, win32.PVOID, win32.DWORD, win32.PVOID, win32.PVOID )

            # Hook the function.
            hook = MyHook()
            event.debug.hook_function( pid, address, hook.entering, hook.leaving, signature = signature )


def simple_debugger( argv ):

    # Instance a Debug object, passing it the MyEventHandler instance.
    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:

        # Start a new process for debugging.
        debug.execv( argv )

        # Wait for the debugee to finish.
        debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
