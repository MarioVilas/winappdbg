# $Id$
# Example #7
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example7:loadingaDLLintotheprocess

from winappdbg import Process

def load_dll( pid, filename ):
    
    # Instance a Process object
    process = Process( pid )
    
    # Load the DLL library in the process
    process.inject_dll( filename )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a DLL filename
if __name__ == "__main__":
    import sys
    pid      = int( sys.argv[1] )
    filename = sys.argv[2]
    load_dll( pid, filename )
