# $Id$
# Example #3
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Win32APIWrappers#Example3:enumeratingheapblocksusingtheToolhelplibrary

from winappdbg.win32 import *

def print_heap_blocks( pid ):
    print "Heaps for process %d:" % pid
    print "Heap ID\tAddress\tSize"
    
    # Create a snapshot of the process, only take the heap list
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPHEAPLIST, pid )
    
    # Catch exceptions so we can call CloseHandle always before returning
    try:
        
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
    
    # Always call CloseHandle before returning, so we don't leak a handle
    finally:
        CloseHandle( hSnapshot )

# When invoked from the command line,
# take the first argument as a process id
if __name__ == "__main__":
    import sys
    print_heap_blocks( int( sys.argv[1] ) )
