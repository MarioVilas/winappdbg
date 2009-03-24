# Example #11
# http://code.google.com/p/python-winappdbg/wiki/Instrumentation#Example_#11:_resolve_an_API_function_in_a_process

from winappdbg import System, Process

def print_api_address( pid, dllname, symbolname ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup it's modules
    process.scan_modules()
    
    # Resolve the requested API function address
    address = process.resolve_exported_symbol( dllname, symbolname )
    
    # Print the address
    print "%s!%s == 0x%.08x" % ( dllname, symbolname, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a DLL filename,
# the third argument is an API name
if __name__ == "__main__":
    import sys
    pid         = int( sys.argv[1] )
    dllname     = sys.argv[2]
    symbolname  = sys.argv[3]
    print_api_address( pid, dllname, symbolname )
