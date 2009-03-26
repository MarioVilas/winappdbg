# Example #1
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging#Example_#1:_starting_a_new_process_and_waiting_for_it_to_finish

from winappdbg import Debug

import sys

# Instance a Debug object
debug = Debug()

# Start a new process for debugging
command_line = debug.system.argv_to_cmdline( sys.argv[ 1 : ] )
debug.start( command_line )

# Wait for the debugee to finish
debug.loop()
