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

from winappdbg import HexDump, CrashDump, System

def print_state( process_name ):

    # Request debug privileges.
    System.request_debug_privileges()

    # Find the first process that matches the requested name.
    system = System()
    process, filename = system.find_processes_by_filename( process_name )[ 0 ]

    # Suspend the process execution.
    process.suspend()
    try:

        # For each thread in the process...
        for thread in process.iter_threads():

            # Get the thread state.
            tid     = thread.get_tid()
            eip     = thread.get_pc()
            code    = thread.disassemble_around( eip )
            context = thread.get_context()

            # Display the thread state.
            print()
            print("-" * 79)
            print("Thread: %s" % HexDump.integer(tid))
            print()
            print(CrashDump.dump_registers(context))
            print(CrashDump.dump_code(code, eip))
            print("-" * 79)

    # Resume the process execution.
    finally:
        process.resume()

# When invoked from the command line,
# each argument is a process name.
if __name__ == "__main__":
    import sys
    for process_name in sys.argv[1:]:
        print_state( process_name )
