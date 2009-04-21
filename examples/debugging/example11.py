# Copyright (c) 2009, Mario Vilas
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

# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example11:watchingabuffer

from winappdbg import Debug, EventHandler, win32


class MyHook (object):

    # Keep record of the buffers we watch
    def __init__(self):
        self.__watched = dict()


    # This function will be called when entering the hooked function
    def entering( self, event, ra, hModule, lpProcName ):

        # Ignore calls using ordinals intead of names
        if lpProcName & 0xFFFF0000 == 0:
            return

        # Get the procedure name
        procName = event.get_process().peek_string( lpProcName )

        # Ignore calls using an empty string
        if not procName:
            return

        # Show a message to the user
        print "GetProcAddress( %r );" % procName

        # Watch the procedure name buffer for access
        pid     = event.get_pid()
        address = lpProcName
        size    = len(procName) + 1
        action  = self.accessed
        event.debug.watch_buffer( pid, address, size, action )

        # Use stalk_buffer instead of watch_buffer to be notified
        # only of the first access to the buffer.
        #
        # event.debug.stalk_buffer( pid, address, size, action )

        # Remember the location of the buffer
        self.__watched[ event.get_tid() ] = ( address, size )


    # This function will be called when leaving the hooked function
    def leaving( self, event, return_value ):

        # Get the thread ID
        tid = thread.get_tid()

        # Get the buffer location
        ( address, size ) = self.__watched[ tid ]

        # Stop watching the buffer
        event.debug.dont_watch_buffer( event.get_pid(), address, size )
        #event.debug.dont_stalk_buffer( event.get_pid(), address, size )

        # Forget the buffer location
        del self.__watched[ tid ]


    # This function will be called every time the procedure name buffer is accessed
    def accessed( self, event ):

        # Show the user where we're running
        thread = event.get_thread()
        pc     = thread.get_pc()
        code   = thread.disassemble( pc, 0x10 ) [0]
        print "0x%.08x: %s" % ( code[0], code[2].lower() )


class MyEventHandler( EventHandler ):

    # Called guard page exceptions NOT raised by our breakpoints
    def guard_page( self, event ):
        print event.get_exception_name()

    # Called on DLL load events
    def load_dll( self, event ):

        # Get the new module object
        module = event.get_module()

        # If it's kernel32...
        if module.match_name("kernel32.dll"):

            # Get the process ID
            pid = event.get_pid()

            # Get the address of wsprintf
            address = module.resolve( "GetProcAddress" )

            # Hook the wsprintf function
            event.debug.hook_function( pid, address, MyHook().entering, paramCount = 2 )


def simple_debugger( argv ):

    # Instance a Debug object, passing it the MyEventHandler instance
    debug = Debug( MyEventHandler() )

    # Start a new process for debugging
    debug.execv( argv )

    # Wait for the debugee to finish
    debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
