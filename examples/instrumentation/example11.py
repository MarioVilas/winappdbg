# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example11resolveanAPIfunctioninaprocess

from winappdbg import System, Process

def print_api_address( pid, dllname, exportname ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # See if the module is loaded
    if not process.has_module( dllname ):
        print "Module not found: %s" % dllname
        return
    
    # Get the module
    module = process.get_module( dllname )
    
    # Resolve the requested API function address
    address = module.resolve( exportname )
    
    # Print the address
    print "%s!%s == 0x%.08x" % ( dllname, exportname, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a DLL filename,
# the third argument is an API name
if __name__ == "__main__":
    import sys
    pid         = int( sys.argv[1] )
    dllname     = sys.argv[2]
    exportname  = sys.argv[3]
    print_api_address( pid, dllname, exportname )
