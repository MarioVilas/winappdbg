# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example11:resolveanAPIfunctioninaprocess

from winappdbg import System, Process

def print_api_address( pid, dllname, apiname ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Get the module
    module = process.get_module_by_name( dllname )
    if not module:
        print "Module not found: %s" % dllname
        return
    
    # Resolve the requested API function address
    address = module.resolve( apiname )
    
    # Print the address
    print "%s!%s == 0x%.08x" % ( dllname, apiname, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a DLL filename,
# the third argument is an API name
if __name__ == "__main__":
    import sys
    pid         = int( sys.argv[1] )
    dllname     = sys.argv[2]
    apiname     = sys.argv[3]
    print_api_address( pid, dllname, apiname )
