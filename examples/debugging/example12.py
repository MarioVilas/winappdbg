# $Id$

# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example12:resolvingalabelbackintoamemoryaddress

from winappdbg import System, Process

def print_label_address( pid, label ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Resolve the requested label address
    address = process.resolve_label( label )
    
    # Print the address
    print "%s == 0x%.08x" % ( label, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a label
if __name__ == "__main__":
    import sys
    pid   = int( sys.argv[1] )
    label = sys.argv[2]
    print_label_address( pid, label )
