# Example #2
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example2:startinganewprocess

from winappdbg import System

import sys

# Instance a System object
system = System()

# Get the target application
command_line = system.argv_to_cmdline( sys.argv[ 1 : ] )

# Start a new process
system.start_process( command_line )    # see the docs for more options
