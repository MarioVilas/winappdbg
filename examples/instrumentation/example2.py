# Example #2
# http://code.google.com/p/python-winappdbg/wiki/Instrumentation#Example_#2:_starting_a_new_process

from winappdbg import System

import sys

# Instance a System object
system = System()

# Get the target application
command_line = system.argv_to_cmdline( sys.argv[ 1 : ] )

# Start a new process
system.start_process( command_line )    # see the docs for more options
