# Example #1
# http://code.google.com/p/python-winappdbg/wiki/Win32APIWrappers#Example_#1:_finding_a_DLL_in_the_search_path

import sys

from winappdbg import win32

fullpath, basename = win32.SearchPath( None, sys.argv[1], None )

print "Full path: %s" % fullpath
print "Base name: %s" % basename
