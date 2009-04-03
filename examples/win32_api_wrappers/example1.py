# Example #1
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Win32APIWrappers#Example1findingaDLLinthesearchpath

import sys

from winappdbg import win32

fullpath, basename = win32.SearchPath( None, sys.argv[1], None )

print "Full path: %s" % fullpath
print "Base name: %s" % basename
