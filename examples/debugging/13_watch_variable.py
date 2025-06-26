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

from winappdbg import Debug, EventHandler, HexDump


# This function will be called when the breakpoint is hit.
def entering( event ):

    # Get the thread object.
    thread = event.get_thread()

    # Get the thread ID.
    tid = thread.get_tid()

    # Get the return address location (the top of the stack).
    stack_top = thread.get_sp()

    # Get the return address and the parameters from the stack.
    bits = event.get_process().get_bits()
    if bits == 32:
        return_address, hModule, lpProcName = thread.read_stack_dwords( 3 )
    else:
        return_address = thread.read_stack_qwords( 1 )
        registers  = thread.get_context()
        hModule    = registers['Rcx']
        lpProcName = registers['Rdx']

    # Get the string from the process memory.
    procedure_name = event.get_process().peek_string( lpProcName )

    # Show a message to the user.
    message = "%s: GetProcAddress(%s, %r);"
    print(message % (
        HexDump.address(return_address, bits),
        HexDump.address(hModule, bits),
        procedure_name
    ))

    # Watch the DWORD at the top of the stack.
    try:
        event.debug.stalk_variable( tid, stack_top, 4, returning )
        #event.debug.watch_variable( tid, stack_top, 4, returning )

    # If no more slots are available, set a code breakpoint at the return address.
    except RuntimeError:
        event.debug.stalk_at( event.get_pid(), return_address, returning_2 )


# This function will be called when the variable is accessed.
def returning( event ):

    # Get the address of the watched variable.
    variable_address = event.breakpoint.get_address()

    # Stop watching the variable.
    event.debug.dont_stalk_variable( event.get_tid(), variable_address )
    #event.debug.dont_watch_variable( event.get_tid(), variable_address )

    # Get the return address (in the stack).
    return_address = event.get_process().read_uint( variable_address )

    # Get the return value (in the registers).
    registers = event.get_thread().get_context()
    if event.get_process().get_bits() == 32:
        return_value = registers['Eax']
    else:
        return_value = registers['Rax']

    # Show a message to the user.
    message = "%.08x: GetProcAddress() returned 0x%.08x"
    print(message % ( return_address, return_value ))


# This function will be called if we ran out of hardware breakpoints,
# and we ended up setting a code breakpoint at the return address.
def returning_2( event ):

    # Get the return address from the breakpoint.
    return_address = event.breakpoint.get_address()

    # Remove the code breakpoint.
    event.debug.dont_stalk_at( event.get_pid(), return_address )

    # Get the return value (in the registers).
    registers = event.get_thread().get_context()
    if event.get_process().get_bits() == 32:
        return_value = registers['Eax']
    else:
        return_value = registers['Rax']

    # Show a message to the user.
    message = "%.08x: GetProcAddress() returned 0x%.08x"
    print(message % ( return_address, return_value ))


# This event handler sets a breakpoint at kernel32!GetProcAddress.
class MyEventHandler( EventHandler ):

    def load_dll( self, event ):

        # Get the new module object.
        module = event.get_module()

        # If it's kernel32...
        if module.match_name("kernel32.dll"):

            # Get the process ID.
            pid = event.get_pid()

            # Get the address of GetProcAddress.
            address = module.resolve( "GetProcAddress" )

            # Set a breakpoint at the entry of the GetProcAddress function.
            event.debug.break_at( pid, address, entering )


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
