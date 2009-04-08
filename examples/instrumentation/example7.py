# $Id$

# Example #7
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example7:gettingtheprocessmemorymap

from winappdbg import win32, Process

def print_memory_map( pid ):
    
    # Instance a Process object
    process = Process( pid )
    
    # Get the process memory map
    memoryMap = process.get_memory_map()
    
    # Now you could do this:
    #
    # from winappdbg import CrashDump
    # print CrashDump.dump_memory_map( memoryMap ),
    #
    # But for demonstration purposes let's do it manually:
    
    # For each memory block in the map...
    print "Address   \tSize      \tState     \tAccess    \tType"
    for mbi in memoryMap:
        
        # Address and size of memory block
        BaseAddress = "0x%.08x" % mbi.BaseAddress
        RegionSize  = "0x%.08x" % mbi.RegionSize
        
        # State (free or allocated)
        if   mbi.State == win32.MEM_RESERVE:
            State   = "Reserved  "
        elif mbi.State == win32.MEM_COMMIT:
            State   = "Commited  "
        elif mbi.State == win32.MEM_FREE:
            State   = "Free      "
        else:
            State   = "Unknown   "
        
        # Page protection bits (R/W/X/G)
        if mbi.State != win32.MEM_COMMIT:
            Protect = "          "
        else:
##            Protect = "0x%.08x" % mbi.Protect
            if   mbi.Protect & win32.PAGE_NOACCESS:
                Protect = "--- "
            elif mbi.Protect & win32.PAGE_READONLY:
                Protect = "R-- "
            elif mbi.Protect & win32.PAGE_READWRITE:
                Protect = "RW- "
            elif mbi.Protect & win32.PAGE_WRITECOPY:
                Protect = "RC- "
            elif mbi.Protect & win32.PAGE_EXECUTE:
                Protect = "--X "
            elif mbi.Protect & win32.PAGE_EXECUTE_READ:
                Protect = "R-- "
            elif mbi.Protect & win32.PAGE_EXECUTE_READWRITE:
                Protect = "RW- "
            elif mbi.Protect & win32.PAGE_EXECUTE_WRITECOPY:
                Protect = "RCX "
            else:
                Protect = "??? "
            if   mbi.Protect & win32.PAGE_GUARD:
                Protect += "G"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_NOCACHE:
                Protect += "N"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_WRITECOMBINE:
                Protect += "W"
            else:
                Protect += "-"
            Protect += "   "
       
        # Type (file mapping, executable image, or private memory)
        if   mbi.Type == win32.MEM_IMAGE:
            Type    = "Image     "
        elif mbi.Type == win32.MEM_MAPPED:
            Type    = "Mapped    "
        elif mbi.Type == win32.MEM_PRIVATE:
            Type    = "Private   "
        elif mbi.Type == 0:
            Type    = "Free      "
        else:
            Type    = "Unknown   "
        
        # Print the memory block information
        fmt = "%s\t%s\t%s\t%s\t%s"
        print fmt % ( BaseAddress, RegionSize, State, Protect, Type )

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    print_memory_map( int( sys.argv[1] ) )
