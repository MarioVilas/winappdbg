# $Id$
# Example #1
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example1:enumeratingrunningprocesses

from winappdbg import System

# Request debugging privileges for the current process
# This is needed to get some information from services
# (Try commenting out this line to see what happens!)
System.request_debug_privileges()

# Create a system snaphot
system = System()

# The snapshot is initially empty, so populate it
system.scan_processes()

# Now we can enumerate the running processes
for process in system:
    print "%d:\t%s" % ( process.get_pid(), process.get_filename() )
