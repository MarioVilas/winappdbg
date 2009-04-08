# $Id$
# Example #2
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example2:attachingtoaprocessandwaitingforittofinish

from winappdbg import Debug

import sys

# Get the process ID from the command line
pid = int( sys.argv[1] )

# Instance a Debug object
debug = Debug()

# Attach to a running process
debug.attach( pid )

# Wait for the debugee to finish
debug.loop()
