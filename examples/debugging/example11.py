# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example10:resolvealabelinaprocess

from winappdbg import System, Process

def print_label( pid, address ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Resolve the requested label address
    label = process.get_label_at_address( address )
    
    # Print the label
    print "%s == 0x%.08x" % ( label, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a remote pointer (in hexadecimal)
if __name__ == "__main__":
    import sys
    pid     = int( sys.argv[1] )
    address = int( sys.argv[2], 0x10 )
    print_label( pid, address )
