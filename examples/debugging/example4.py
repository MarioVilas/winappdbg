# $Id$
# Example #4
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example4:killingaprocessbyattachingtoit

from winappdbg import Debug

import sys
import thread

# Get the process ID from the command line
pid = int( sys.argv[1] )

# Instance a Debug object, set the kill on exit property to True
debug = Debug( bKillOnExit = True )

# Attach to a running process
debug.attach( pid )

# Exit the current thread, killing the attached process
thread.exit()
