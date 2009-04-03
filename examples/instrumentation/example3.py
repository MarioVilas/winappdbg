# Example #3
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example3:enumeratingthreadsandDLLmodulesinaprocess

from winappdbg import Process

def enum_threads( pid ):
    
    # Instance a Process object
    process = Process( pid )
    print "Process %d" % process.get_pid()
    
    # The Process snapshot is initially empty, so populate it
    process.scan_threads()
    process.scan_modules()
    
    # Now we can enumerate the threads in the process...
    print "Threads:"
    for thread in process:
        print "\t%d" % thread.get_tid()
    
    # ...and the modules in the process
    print "Modules:"
    for module in process.iter_modules():
        print "\t0x%.8x\t%s" % ( module.get_base(), module.get_filename() )

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    pid = int( sys.argv[1] )
    enum_threads( pid )
