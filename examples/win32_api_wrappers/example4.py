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

# Example #4
# http://apps.sourceforge.net/trac/winappdbg/wiki/Win32APIWrappers#Example4:enumeratingmodulesusingtheToolhelplibrary

from winappdbg.win32 import *

def print_modules( pid ):
    print "Modules for process %d:" % pid
    print
    print "Address     Size        Path"

    # Create a snapshot of the process, only take the heap list
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid )

    # Enumerate the modules
    module = Module32First( hSnapshot )
    while module is not None:

        # Print the module address, size and pathname
        print "%.8x    %.8x    %s" % ( module.modBaseAddr,
                                       module.modBaseSize,
                                       module.szExePath )

        # Next module in the process
        module = Module32Next( hSnapshot )

    # No need to call CloseHandle, the handle is closed automatically when it goes out of scope
    return

# When invoked from the command line,
# take the first argument as a process id
if __name__ == "__main__":
    import sys
    print_modules( int( sys.argv[1] ) )
