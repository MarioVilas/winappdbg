# $Id$
# Example #3
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example3:attachingtoaprocessbyfilename

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
    print process.get_pid(), name
    
    # Attach to the process
    debug.attach( process.get_pid() )

# Wait for all the debugees to finish
debug.loop()
