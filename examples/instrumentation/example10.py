# Example #10
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example_#10:_enumerate_all_modules_in_a_process

from winappdbg import System, Process

def print_modules( pid ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Enumerate the modules
    print "Base address\tFile name"
    for module in process.iter_modules():
        print "0x%.08x\t%s" % ( module.get_base(), module.get_filename() )

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    pid = int( sys.argv[1] )
    print_modules( pid )
