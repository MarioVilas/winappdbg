# Example #2
# http://code.google.com/p/python-winappdbg/wiki/Win32APIWrappers#Example_#2:_killing_a_process_by_attaching_to_it

import sys
import thread

from winappdbg import win32

def processKiller(dwProcessId):
    
    # Attach to the process
    win32.DebugActiveProcess( dwProcessId )
    
    # Quit the current thread
    thread.exit()

# When invoked from the command line,
# take the first argument as a process id
if __name__ == "__main__":
    dwProcessId = int( sys.argv[1] )
    processKiller( dwProcessId )
