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

# Example #3
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Win32APIWrappers#Example3:enumeratingheapblocksusingtheToolhelplibrary

from winappdbg.win32 import *

def print_heap_blocks( pid ):
    print "Heaps for process %d:" % pid
    print "Heap ID\tAddress\tSize"

    # Create a snapshot of the process, only take the heap list
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPHEAPLIST, pid )

    # Enumerate the heaps
    heap = Heap32ListFirst( hSnapshot )
    while heap is not None:

        # For each heap, enumerate the entries
        entry = Heap32First( heap.th32ProcessID, heap.th32HeapID )
        while entry is not None:

            # Print the heap id and the entry address and size
            print "%.8x\t%.8x\t%.8x" % \
                  (entry.th32HeapID, entry.dwAddress, entry.dwBlockSize)

            # Next entry in the heap
            entry = Heap32Next( entry )

        # Next heap in the list
        heap = Heap32ListNext( hSnapshot )

    # No need to call CloseHandle, the handle is closed automatically when it goes out of scope
    return

# When invoked from the command line,
# take the first argument as a process id
if __name__ == "__main__":
    import sys
    print_heap_blocks( int( sys.argv[1] ) )
