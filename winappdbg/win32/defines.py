# Copyright (c) 2009, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Debugging API wrappers in ctypes.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/Win32APIWrappers}
"""

__revision__ = "$Id$"

import time
import struct
import ctypes

#------------------------------------------------------------------------------

# Some stuff from ctypes we'll be using very frequently.
sizeof      = ctypes.sizeof
POINTER     = ctypes.POINTER
Structure   = ctypes.Structure
Union       = ctypes.Union

#------------------------------------------------------------------------------

# Laxy reference to ctypes.windll.
# Currently it's only use is to allow importing winappdbg in a non Windows
# environment, for example to get the documentation or build the packages.
# Later on it may be extended with some sort of syscall proxy, if it turns
# out to be justified (I tend to think a high level RPC is a better approach).
try:
    from ctypes import windll
except ImportError:
    class FakeWinDll(object):
        def __getattr__(self, name):
            return self
        def __call__(self, *argv, **argd):
            raise ctypes.WinError(50)   # ERROR_NOT_SUPPORTED
    windll = FakeWinDll()

# Lazy reference to ctypes.WINFUNCTYPE.
# See explanation above.
try:
    WINFUNCTYPE = ctypes.WINFUNCTYPE
except AttributeError:
    class WINFUNCTYPE(object):
        def __init__(self, restype, *argtypes):
            self.restype  = restype
            self.argtypes = argtypes
        def __call__(self, *argv):
            return ctypes.WINFUNCTYPE(self.restype, *self.argtypes)(*argv)

#------------------------------------------------------------------------------

# XXX DEBUG
# The following code can be enabled to make the Win32 API wrappers log to
# standard ouput the dll and function names, the parameter values and the
# return value for each call.

##WIN32_VERBOSE_MODE = True
WIN32_VERBOSE_MODE = False

if WIN32_VERBOSE_MODE:

    class WinDllHook(object):
        def __getattr__(self, name):
            if name.startswith('_'):
                return object.__getattr__(self, name)
            return WinFuncHook(name)

    class WinFuncHook(object):
        def __init__(self, name):
            self.__name = name

        def __getattr__(self, name):
            if name.startswith('_'):
                return object.__getattr__(self, name)
            return WinCallHook(self.__name, name)

    class WinCallHook(object):
##        def __new__(typ, dllname, funcname):
##            print dllname, funcname
##            return getattr(getattr(ctypes.windll, dllname), funcname)

        def __init__(self, dllname, funcname):
            self.__dllname = dllname
            self.__funcname = funcname
            self.__func = getattr(getattr(ctypes.windll, dllname), funcname)

        def __copy_attribute(self, attribute):
            try:
                value = getattr(self, attribute)
                setattr(self.__func, attribute, value)
            except AttributeError:
                try:
                    delattr(self.__func, attribute)
                except AttributeError:
                    pass

        def __call__(self, *argv):
            self.__copy_attribute('argtypes')
            self.__copy_attribute('restype')
            self.__copy_attribute('errcheck')
            print "-"*10
            print "%s ! %s %r" % (self.__dllname, self.__funcname, argv)
            retval = self.__func(*argv)
            print "== %r" % (retval,)
            return retval

    windll = WinDllHook()

#------------------------------------------------------------------------------

def winerror(e):
    """
    Auxiliary function to extract the Windows error code from a C{WindowError}
    exception instance. This is only needed for compatibility with Python 2.3.

    For example, replace this code::

        try:
            # ...some stuff...
        except WindowsError, e:
            if e.winerror == ERROR_ACCESS_DENIED:
                print "Access denied!"
            else:
                print "Error: %s" % str(e)

    With this code::

        try:
            # ...some stuff...
        except WindowsError, e:
            if win32.winerror(e) == ERROR_ACCESS_DENIED:
                print "Access denied!"
            else:
                print "Error: %s" % str(e)

    And it'll be automagically compatible with Python 2.3. :)
    """
    # Another example of the docstring being much more complex than the code :)
    try:
        return e.winerror   # Python 2.4 and better
    except AttributeError:
        return e.errno      # Python 2.3

def RaiseIfZero(result, func = None, arguments = ()):
    """
    Error checking for most Win32 API calls.

    The function is assumed to return an integer, which is C{0} on error.
    In that case the C{WindowsError} exception is raised.
    """
    if not result:
        raise ctypes.WinError()
    return result

class GuessStringType(object):
    """
    Decorator that guesses the correct version (A or W) to call
    based on the types of the strings passed as parameters.

    Defaults to B{ANSI} if no string arguments are passed.

    Defaults to B{Unicode} if mixed string types are passed.

    @type fn_ansi: function
    @ivar fn_ansi: ANSI version of the API function to call.
    @type fn_unicode: function
    @ivar fn_unicode: Unicode (wide) version of the API function to call.
    """

    def __init__(self, fn_ansi, fn_unicode):
        """
        @type  fn_ansi: function
        @param fn_ansi: ANSI version of the API function to call.
        @type  fn_unicode: function
        @param fn_unicode: Unicode (wide) version of the API function to call.
        """
        self.fn_ansi    = fn_ansi
        self.fn_unicode = fn_unicode

    def __call__(self, *argv, **argd):
        guessed   = None
        t_ansi    = type('')
        t_unicode = type(u'')
        v_types   = [ type(item) for item in argv ]
        v_types.extend( [ type(value) for (key, value) in argd.iteritems() ] )
        if t_unicode in v_types:
            if t_ansi in v_types:
                argv = list(argv)
                for index in xrange(len(argv)):
                    if v_types[index] == t_ansi:
                        argv[index] = unicode(argv[index])
                for key, value in argd.items():
                    if type(value) == t_ansi:
                        argd[key] = unicode(value)
            return self.fn_unicode(*argv, **argd)
        return self.fn_ansi(*argv, **argd)

class MakeANSIVersion(object):
    """
    Decorator that generates an ANSI version of a Unicode (wide) only API call.

    @type fn: function
    @ivar fn: Unicode (wide) version of the API function to call.
    """

    def __init__(self, fn):
        """
        @type  fn: function
        @param fn: Unicode (wide) version of the API function to call.
        """
        self.fn = fn

    def __call__(self, *argv, **argd):
        t_ansi    = type('')
        v_types   = [ type(item) for item in argv ]
        v_types.extend( [ type(value) for (key, value) in argd.iteritems() ] )
        if t_ansi in v_types:
            argv = list(argv)
            for index in xrange(len(argv)):
                if v_types[index] == t_ansi:
                    argv[index] = unicode(argv[index])
            for key, value in argd.items():
                if type(value) == t_ansi:
                    argd[key] = unicode(value)
        return self.fn(*argv, **argd)

#--- Types --------------------------------------------------------------------

LPVOID      = ctypes.c_void_p
CHAR        = ctypes.c_char
WCHAR       = ctypes.c_wchar
BYTE        = ctypes.c_ubyte
SBYTE       = ctypes.c_byte
WORD        = ctypes.c_ushort
SWORD       = ctypes.c_short
DWORD       = ctypes.c_uint
SDWORD      = ctypes.c_int
QWORD       = ctypes.c_ulonglong
SQWORD      = ctypes.c_longlong
SHORT       = ctypes.c_short
USHORT      = ctypes.c_ushort
INT         = ctypes.c_int
UINT        = ctypes.c_uint
LONG        = ctypes.c_long
ULONG       = ctypes.c_ulong
LONGLONG    = ctypes.c_longlong
ULONGLONG   = ctypes.c_ulonglong
LPSTR       = ctypes.c_char_p
LPWSTR      = ctypes.c_wchar_p

try:
    SIZE_T  = ctypes.c_size_t
except AttributeError:
    # Size of a pointer
    SIZE_T  = {1:BYTE, 2:WORD, 4:DWORD, 8:QWORD}[sizeof(LPVOID)]
PSIZE_T     = POINTER(SIZE_T)

PVOID       = LPVOID
PPVOID      = POINTER(PVOID)
PSTR        = LPSTR
PWSTR       = LPWSTR
PCHAR       = LPSTR
PWCHAR      = LPWSTR
LPBYTE      = POINTER(BYTE)
LPSBYTE     = POINTER(SBYTE)
LPWORD      = POINTER(WORD)
LPSWORD     = POINTER(SWORD)
LPDWORD     = POINTER(DWORD)
LPSDWORD    = POINTER(SDWORD)
DWORD_PTR   = POINTER(DWORD)
ULONG_PTR   = POINTER(ULONG)
LONG_PTR    = POINTER(LONG)
PDWORD      = DWORD_PTR
PULONG      = ULONG_PTR
PLONG       = LONG_PTR
BOOL        = DWORD
BOOLEAN     = BYTE
PBOOL       = POINTER(BOOL)
LPBOOL      = PBOOL
TCHAR       = CHAR      # XXX ANSI by default?
UCHAR       = BYTE
ULONG32     = DWORD
DWORD32     = DWORD
ULONG64     = QWORD
DWORD64     = QWORD
DWORDLONG   = ULONGLONG
HANDLE      = LPVOID
PHANDLE     = POINTER(HANDLE)
LPHANDLE    = PHANDLE
HMODULE     = HANDLE
HINSTANCE   = HANDLE
HRGN        = HANDLE
HTASK       = HANDLE
HKEY        = HANDLE
HDESK       = HANDLE
HMF         = HANDLE
HEMF        = HANDLE
HPEN        = HANDLE
HRSRC       = HANDLE
HSTR        = HANDLE
HWINSTA     = HANDLE
HKL         = HANDLE
HGDIOBJ     = HANDLE
HDWP        = HANDLE
HFILE       = HANDLE
HRESULT     = LONG
HGLOBAL     = HANDLE
HLOCAL      = HANDLE
HBITMAP     = HANDLE
HPALETTE    = HANDLE
HENHMETAFILE = HANDLE
HMETAFILE   = HANDLE
HMETAFILEPICT = HANDLE
HWND        = HANDLE
NTSTATUS    = LONG
PNTSTATUS   = POINTER(NTSTATUS)
KAFFINITY   = PVOID             # ULONG_PTR
RVA         = DWORD
RVA64       = QWORD
WPARAM      = DWORD
LPARAM      = LPVOID
LRESULT     = LPVOID

# typedef union _LARGE_INTEGER {
#   struct {
#     DWORD LowPart;
#     LONG HighPart;
#   } ;
#   struct {
#     DWORD LowPart;
#     LONG HighPart;
#   } u;
#   LONGLONG QuadPart;
# } LARGE_INTEGER,
#  *PLARGE_INTEGER;

# XXX TODO

# typedef struct _FLOAT128 {
#     __int64 LowPart;
#     __int64 HighPart;
# } FLOAT128;
class FLOAT128 (Structure):
    _fields_ = [
        ("LowPart",     QWORD),
        ("HighPart",    QWORD),
    ]
PFLOAT128 = POINTER(FLOAT128)

# typedef struct DECLSPEC_ALIGN(16) _M128A {
#     ULONGLONG Low;
#     LONGLONG High;
# } M128A, *PM128A;
class M128A(Structure):
    _fields_ = [
        ("Low",     ULONGLONG),
        ("High",    LONGLONG),
    ]
PM128A = POINTER(M128A)

#--- Constants ----------------------------------------------------------------

NULL        = None
INFINITE    = -1
TRUE        = 1
FALSE       = 0

# http://blogs.msdn.com/oldnewthing/archive/2004/08/26/220873.aspx
ANYSIZE_ARRAY = 1

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value #-1 #0xFFFFFFFF

MAX_MODULE_NAME32   = 255
MAX_PATH            = 260

# Error codes
# TODO maybe add more error codes?
ERROR_SUCCESS                       = 0
ERROR_INVALID_FUNCTION              = 1
ERROR_FILE_NOT_FOUND                = 2
ERROR_PATH_NOT_FOUND                = 3
ERROR_ACCESS_DENIED                 = 5
ERROR_INVALID_HANDLE                = 6
ERROR_NOT_ENOUGH_MEMORY             = 8
ERROR_INVALID_DRIVE                 = 15
ERROR_NO_MORE_FILES                 = 18
ERROR_BAD_LENGTH                    = 24
ERROR_HANDLE_EOF                    = 38
ERROR_HANDLE_DISK_FULL              = 39
ERROR_NOT_SUPPORTED                 = 50
ERROR_FILE_EXISTS                   = 80
ERROR_INVALID_PARAMETER             = 87
ERROR_BUFFER_OVERFLOW               = 111
ERROR_DISK_FULL                     = 112
ERROR_CALL_NOT_IMPLEMENTED          = 120
ERROR_SEM_TIMEOUT                   = 121
ERROR_INSUFFICIENT_BUFFER           = 122
ERROR_INVALID_NAME                  = 123
ERROR_MOD_NOT_FOUND                 = 126
ERROR_PROC_NOT_FOUND                = 127
ERROR_DIR_NOT_EMPTY                 = 145
ERROR_BAD_THREADID_ADDR             = 159
ERROR_BAD_ARGUMENTS                 = 160
ERROR_BAD_PATHNAME                  = 161
ERROR_ALREADY_EXISTS                = 183
ERROR_INVALID_FLAG_NUMBER           = 186
ERROR_FILENAME_EXCED_RANGE          = 206
WAIT_TIMEOUT                        = 258
ERROR_NO_MORE_ITEMS                 = 259
ERROR_PARTIAL_COPY                  = 299
ERROR_INVALID_ADDRESS               = 487
ERROR_THREAD_NOT_IN_PROCESS         = 566
ERROR_CONTROL_C_EXIT                = 572
ERROR_UNHANDLED_EXCEPTION           = 574
ERROR_ASSERTION_FAILURE             = 668
ERROR_WOW_ASSERTION                 = 670

ERROR_DBG_EXCEPTION_NOT_HANDLED     = 688
ERROR_DBG_REPLY_LATER               = 689
ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE  = 690
ERROR_DBG_TERMINATE_THREAD          = 691
ERROR_DBG_TERMINATE_PROCESS         = 692
ERROR_DBG_CONTROL_C                 = 693
ERROR_DBG_PRINTEXCEPTION_C          = 694
ERROR_DBG_RIPEXCEPTION              = 695
ERROR_DBG_CONTROL_BREAK             = 696
ERROR_DBG_COMMAND_EXCEPTION         = 697
ERROR_DBG_EXCEPTION_HANDLED         = 766
ERROR_DBG_CONTINUE                  = 767

ERROR_DEBUGGER_INACTIVE             = 1284

#--- Structures ---------------------------------------------------------------

# typedef struct _LSA_UNICODE_STRING {
#   USHORT Length;
#   USHORT MaximumLength;
#   PWSTR Buffer;
# } LSA_UNICODE_STRING,
#  *PLSA_UNICODE_STRING,
#  UNICODE_STRING,
#  *PUNICODE_STRING;
class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          USHORT),
        ("MaximumLength",   USHORT),
        ("Buffer",          PVOID),
    ]

# From MSDN:
#
# typedef struct _GUID {
#   DWORD Data1;
#   WORD Data2;
#   WORD Data3;
#   BYTE Data4[8];
# } GUID;
class GUID(Structure):
    _fields_ = [
        ("Data1",   DWORD),
        ("Data2",   WORD),
        ("Data3",   WORD),
        ("Data4",   BYTE * 8),
]

# From MSDN:
#
# typedef struct _LIST_ENTRY {
#     struct _LIST_ENTRY *Flink;
#     struct _LIST_ENTRY *Blink;
# } LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
class LIST_ENTRY(Structure):
    pass
LIST_ENTRY._fields_ = [
        ("Flink",   PVOID),     # POINTER(LIST_ENTRY)
        ("Blink",   PVOID),     # POINTER(LIST_ENTRY)
]
