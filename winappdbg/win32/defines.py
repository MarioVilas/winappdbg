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

sizeof      = ctypes.sizeof
POINTER     = ctypes.POINTER
Structure   = ctypes.Structure
Union       = ctypes.Union

try:
    callable
except NameError:
    def callable(obj):
        return hasattr(obj, '__call__')

class GuessStringType(object):
    """
    Decorator that guesses the correct version (A or W) to call
    based on the types of the strings passed as parameters.

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
LPVOID      = ctypes.c_void_p
LPSTR       = ctypes.c_char_p
LPWSTR      = ctypes.c_wchar_p
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
BOOL        = DWORD
BOOLEAN     = BYTE
UCHAR       = BYTE
ULONG32     = DWORD
DWORD32     = DWORD
ULONG64     = QWORD
DWORD64     = QWORD
HANDLE      = DWORD
HWND        = DWORD
HMODULE     = DWORD
HINSTANCE   = DWORD
HRESULT     = DWORD
HLOCAL      = DWORD
HGLOBAL     = DWORD
NTSTATUS    = DWORD
KAFFINITY   = LONG
KPRIORITY   = LONG
TCHAR       = CHAR
SIZE_T      = DWORD
PVOID       = LPVOID
PPVOID      = POINTER(PVOID)
RVA         = DWORD
RVA64       = QWORD

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

#--- Constants ----------------------------------------------------------------

NULL        = 0
INFINITE    = -1
TRUE        = 1
FALSE       = 0

# http://blogs.msdn.com/oldnewthing/archive/2004/08/26/220873.aspx
ANYSIZE_ARRAY = 1

INVALID_HANDLE_VALUE = -1 #0xFFFFFFFF

MAX_MODULE_NAME32   = 255
MAX_PATH            = 260

# Error codes
# TODO maybe add more error codes?
ERROR_SUCCESS               = 0
ERROR_FILE_NOT_FOUND        = 2
ERROR_PATH_NOT_FOUND        = 3
ERROR_ACCESS_DENIED         = 5
ERROR_INVALID_HANDLE        = 6
ERROR_NOT_ENOUGH_MEMORY     = 8
ERROR_INVALID_DRIVE         = 15
ERROR_NO_MORE_FILES         = 18
ERROR_HANDLE_EOF            = 38
ERROR_HANDLE_DISK_FULL      = 39
ERROR_NOT_SUPPORTED         = 50
ERROR_FILE_EXISTS           = 80
ERROR_INVALID_PARAMETER     = 87
ERROR_BUFFER_OVERFLOW       = 111
ERROR_DISK_FULL             = 112
ERROR_CALL_NOT_IMPLEMENTED  = 120
ERROR_SEM_TIMEOUT           = 121
ERROR_INSUFFICIENT_BUFFER   = 122
ERROR_INVALID_NAME          = 123
ERROR_MOD_NOT_FOUND         = 126
ERROR_PROC_NOT_FOUND        = 127
ERROR_DIR_NOT_EMPTY         = 145
ERROR_BAD_THREADID_ADDR     = 159
ERROR_BAD_ARGUMENTS         = 160
ERROR_BAD_PATHNAME          = 161
ERROR_ALREADY_EXISTS        = 183
ERROR_INVALID_FLAG_NUMBER   = 186
ERROR_FILENAME_EXCED_RANGE  = 206
WAIT_TIMEOUT                = 258
ERROR_NO_MORE_ITEMS         = 259
ERROR_PARTIAL_COPY          = 299
ERROR_INVALID_ADDRESS       = 487
ERROR_THREAD_NOT_IN_PROCESS = 566
ERROR_CONTROL_C_EXIT        = 572
ERROR_UNHANDLED_EXCEPTION   = 574
ERROR_ASSERTION_FAILURE     = 668
ERROR_WOW_ASSERTION         = 670

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
