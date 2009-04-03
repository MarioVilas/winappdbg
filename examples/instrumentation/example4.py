# Example #4
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example4killingaprocess

from winappdbg import Process

def process_kill( pid ):
    
    # Instance a Process object
    process = Process( pid )
    
    # Kill the process
    process.kill()

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    pid = int( sys.argv[1] )
    process_kill( pid )
