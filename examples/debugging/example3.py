# Example #3
# http://code.google.com/p/python-winappdbg/wiki/Debugging#Example_#3:_attaching_to_a_process_by_filename

from winappdbg import Debug

import sys

# Get the process filename from the command line
filename = sys.argv[1]

# Instance a Debug object
debug = Debug()

# Lookup the currently running processes
debug.system.scan_processes()

# For all processes that match the requested filename...
for ( process, name ) in debug.system.find_processes_by_filename( filename ):
    print name
    
    # Attach to the process
    debug.attach( process.get_pid() )

# Wait for the debugees to finish
debug.loop()
