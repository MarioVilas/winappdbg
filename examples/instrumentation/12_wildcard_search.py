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

# The WinAppDbg search engine will issue a warning if there is some part of
# the process memory that cannot be read. We will ignore them for now.
import warnings
warnings.simplefilter("ignore")

from winappdbg import Process, HexDump

def wildcard_search( pid, pattern ):

    #
    # Hex patterns must be in this form:
    #     "68 65 6c 6c 6f 20 77 6f 72 6c 64"  # "hello world"
    #
    # Spaces are optional. Capitalization of hex digits doesn't matter.
    # This is exactly equivalent to the previous example:
    #     "68656C6C6F20776F726C64"            # "hello world"
    #
    # Wildcards are allowed, in the form of a "?" sign in any hex digit:
    #     "5? 5? c3"          # pop register / pop register / ret
    #     "b8 ?? ?? ?? ??"    # mov eax, immediate value
    #

    # Instance a Process object.
    process = Process( pid )

    # Search for the hexadecimal pattern in the process memory.
    for address, data in process.search_hexa( pattern ):

        # Print a hex dump for each memory location found.
        print(HexDump.hexblock(data, address = address))

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a DLL filename.
if __name__ == "__main__":
    import sys
    pid   = int( sys.argv[1] )
    pattern = sys.argv[2]
    wildcard_search( pid, pattern )
