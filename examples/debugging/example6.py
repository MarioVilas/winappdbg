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

# Example #6
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example6:usingtheEventHandlerclass

from winappdbg import Debug, EventHandler, CrashDump, win32

class MyEventHandler( EventHandler ):
    
    # This private method enables the tracing mode
    def __trace( self, event ):
        
        # Enable the step on branch mode (optional)
        # event.debug.system.enable_step_on_branch_mode()
        
        # Set the trap flag
        event.get_thread().set_tf()
    
    
    # Create process events go here
    def create_process( self, event ):
        
        # Start tracing the main thread
        self.__trace( event )
    
    
    # Create thread events go here
    def create_thread( self, event ):
        
        # Start tracing the new thread
        self.__trace( event )
    
    
    # Single step events go here
    def single_step( self, event ):
        
        # The debugee mustn't see this exception
        event.continueStatus = win32.DBG_CONTINUE
        
        # Continue tracing
        self.__trace( event )
        
        # Show the user where we're running
        thread = event.get_thread()
        pc     = thread.get_pc()
        code   = thread.disassemble( pc, 0x10 ) [0]
        print "0x%.08x: %s" % ( code[0], code[2].lower() )


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
