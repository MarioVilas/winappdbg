# $Id$
# Example #4
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Win32APIWrappers#Example4:enumeratingmodulesusingtheToolhelplibrary

from winappdbg import Handle
from winappdbg.win32 import *

def print_modules( pid ):
    print "Modules for process %d:" % pid
    print
    print "Address     Size        Path"
    
    # Create a snapshot of the process, only take the heap list
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid )

    # Wrap the handle to make sure it's closed when we finish working with it
    hSnapshot = Handle(hSnapshot)

    # Enumerate the modules
    module = Module32First( hSnapshot )
    while module is not None:
        
        # Print the module address, size and pathname
        print "%.8x    %.8x    %s" % ( module.modBaseAddr,
                                       module.modBaseSize,
                                       module.szExePath )
        
        # Next module in the process
        module = Module32Next( hSnapshot )

# When invoked from the command line,
# take the first argument as a process id
if __name__ == "__main__":
    import sys
    print_modules( int( sys.argv[1] ) )
