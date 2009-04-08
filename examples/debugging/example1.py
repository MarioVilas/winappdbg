# $Id$

# Example #1
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example1:startinganewprocessandwaitingforittofinish

from winappdbg import Debug

import sys

# Instance a Debug object
debug = Debug()

# Start a new process for debugging
command_line = debug.system.argv_to_cmdline( sys.argv[ 1 : ] )
debug.start( command_line )

# Wait for the debugee to finish
debug.loop()
