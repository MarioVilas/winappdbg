# $Id$
# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example11:resolveanAPIfunctioninaprocess

from winappdbg import Process

def print_api_address( pid, modName, procName ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Get the module
    module = process.get_module_by_name( modName )
    if not module:
        print "Module not found: %s" % modName
        return
    
    # Resolve the requested API function address
    address = module.resolve( procName )
    
    # Print the address
    print "%s!%s == 0x%.08x" % ( modName, procName, address )

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    pid      = int( sys.argv[1] )
    modName  = sys.argv[2]
    procName = sys.argv[3]
    print_api_address( pid, modName, procName )
