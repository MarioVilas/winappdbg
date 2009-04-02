# Example #5
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Win32APIWrappers#Example5enumeratingdevicedrivers

from winappdbg import Handle
from winappdbg.win32 import *

def print_drivers( fFullPath = False ):
    
    # Get the list of loaded device drivers
    ImageBaseList = EnumDeviceDrivers()
    print "Device drivers found: %d" % len(ImageBaseList)
    print
    print "Image base\tFile name"
    
    # For each device driver...
    for ImageBase in ImageBaseList:
        
        # Get the device driver filename
        if fFullPath:
            DriverName = GetDeviceDriverFileName(ImageBase)
        else:
            DriverName = GetDeviceDriverBaseName(ImageBase)
        
        # Print the device driver image base and filename
        print "%.08x\t%s" % (ImageBase, DriverName)

# When invoked from the command line,
# -f means show full pathnames instead of base filenames
if __name__ == "__main__":
    import sys
    fFullPath = '-f' in sys.argv[1:]
    print_drivers( fFullPath )
