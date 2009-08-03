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

from defines import *

#--- SYSTEM_INFO structure, GetSystemInfo() and GetNativeSystemInfo() ---------

PROCESSOR_ARCHITECTURE_INTEL    = 0
PROCESSOR_ARCHITECTURE_IA64     = 6
PROCESSOR_ARCHITECTURE_AMD64    = 9
PROCESSOR_ARCHITECTURE_UNKNOWN  = 0xffff

# typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } ;
#   }     ;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO;

class _SYSTEM_INFO_OEM_ID_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",  WORD),
        ("wReserved",               WORD),
]

class _SYSTEM_INFO_OEM_ID(Union):
    _fields_ = [
        ("dwOemId",  DWORD),
        ("w",        _SYSTEM_INFO_OEM_ID_STRUCT),
]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("id",                              _SYSTEM_INFO_OEM_ID),
        ("dwPageSize",                      DWORD),
        ("lpMinimumApplicationAddress",     LPVOID),
        ("lpMaximumApplicationAddress",     LPVOID),
        ("dwActiveProcessorMask",           DWORD_PTR),
        ("dwNumberOfProcessors",            DWORD),
        ("dwProcessorType",                 DWORD),
        ("dwAllocationGranularity",         DWORD),
        ("wProcessorLevel",                 WORD),
        ("wProcessorRevision",              WORD),
    ]
LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)

# void WINAPI GetSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetSystemInfo():
    _GetSystemInfo = windll.kernel32.GetSystemInfo
    _GetSystemInfo.argtypes = [LPSYSTEM_INFO]
    _GetSystemInfo.restype = None

    sysinfo = SYSTEM_INFO()
    _GetSystemInfo(ctypes.byref(sysinfo))
    return sysinfo

# void WINAPI GetNativeSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetNativeSystemInfo():
    _GetNativeSystemInfo = windll.kernel32.GetNativeSystemInfo
    _GetNativeSystemInfo.argtypes = [LPSYSTEM_INFO]
    _GetNativeSystemInfo.restype = None

    sysinfo = SYSTEM_INFO()
    _GetNativeSystemInfo(ctypes.byref(sysinfo))
    return sysinfo

#--- CONTEXT structure and constants ------------------------------------------

import context_i386
import context_amd64

from context_i386  import CONTEXT_i386, CONTEXT_i486
from context_amd64 import CONTEXT_AMD64

def get_arch():
    try:
        si = GetNativeSystemInfo()
    except Exception:
        try:
            si = GetSystemInfo()
        except Exception:
            return 'unknown'
    wProcessorArchitecture = si.id.w.wProcessorArchitecture
    if wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL:
        return 'i386'
    if wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64:
        return 'amd64'
    if wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64:
        return 'ia64'
    return 'unknown'
arch = get_arch()
if   arch == 'i386':
    from context_i386 import *
elif arch == 'amd64':
    from context_amd64 import *
elif arch == 'ia64':
    from context_ia64 import *
del arch
del get_arch

#--- Constants ----------------------------------------------------------------

STILL_ACTIVE = 259

WAIT_TIMEOUT        = 0x102
WAIT_FAILED         = -1
WAIT_OBJECT_0       = 0

EXCEPTION_NONCONTINUABLE        = 0x1       # Noncontinuable exception
EXCEPTION_MAXIMUM_PARAMETERS    = 15        # maximum number of exception parameters
MAXIMUM_WAIT_OBJECTS            = 64        # Maximum number of wait objects
MAXIMUM_SUSPEND_COUNT           = 0x7f      # Maximum times thread can be suspended

FORMAT_MESSAGE_ALLOCATE_BUFFER  = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM      = 0x00001000

GR_GDIOBJECTS  = 0
GR_USEROBJECTS = 1

PROCESS_NAME_NATIVE = 1

# LoadLibraryEx constants
DONT_RESOLVE_DLL_REFERENCES         = 0x00000001
LOAD_LIBRARY_AS_DATAFILE            = 0x00000002
LOAD_WITH_ALTERED_SEARCH_PATH       = 0x00000008
LOAD_IGNORE_CODE_AUTHZ_LEVEL        = 0x00000010
LOAD_LIBRARY_AS_IMAGE_RESOURCE      = 0x00000020
LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE  = 0x00000040

# SetSearchPathMode flags
# TODO I couldn't find these constants :(
##BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE     = ???
##BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE    = ???
##BASE_SEARCH_PATH_PERMANENT                  = ???

# Console control events
CTRL_C_EVENT        = 0
CTRL_BREAK_EVENT    = 1
CTRL_CLOSE_EVENT    = 2
CTRL_LOGOFF_EVENT   = 5
CTRL_SHUTDOWN_EVENT = 6

# Standard access rights
DELETE                      = (0x00010000L)
READ_CONTROL                = (0x00020000L)
WRITE_DAC                   = (0x00040000L)
WRITE_OWNER                 = (0x00080000L)
SYNCHRONIZE                 = (0x00100000L)
STANDARD_RIGHTS_REQUIRED    = (0x000F0000L)
STANDARD_RIGHTS_READ        = (READ_CONTROL)
STANDARD_RIGHTS_WRITE       = (READ_CONTROL)
STANDARD_RIGHTS_EXECUTE     = (READ_CONTROL)
STANDARD_RIGHTS_ALL         = (0x001F0000L)
SPECIFIC_RIGHTS_ALL         = (0x0000FFFFL)

# Process access rights for OpenProcess
PROCESS_TERMINATE         = (0x0001)
PROCESS_CREATE_THREAD     = (0x0002)
PROCESS_SET_SESSIONID     = (0x0004)
PROCESS_VM_OPERATION      = (0x0008)
PROCESS_VM_READ           = (0x0010)
PROCESS_VM_WRITE          = (0x0020)
PROCESS_DUP_HANDLE        = (0x0040)
PROCESS_CREATE_PROCESS    = (0x0080)
PROCESS_SET_QUOTA         = (0x0100)
PROCESS_SET_INFORMATION   = (0x0200)
PROCESS_QUERY_INFORMATION = (0x0400)
PROCESS_SUSPEND_RESUME    = (0x0800)
PROCESS_ALL_ACCESS        = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)

# Process priority classes

IDLE_PRIORITY_CLASS         = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS       = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS         = 0x00000080
REALTIME_PRIORITY_CLASS     = 0x00000100

PROCESS_MODE_BACKGROUND_BEGIN   = 0x00100000
PROCESS_MODE_BACKGROUND_END     = 0x00200000

# dwCreationFlag values

DEBUG_PROCESS                     = 0x00000001
DEBUG_ONLY_THIS_PROCESS           = 0x00000002

CREATE_SUSPENDED                  = 0x00000004

DETACHED_PROCESS                  = 0x00000008

CREATE_NEW_CONSOLE                = 0x00000010

NORMAL_PRIORITY_CLASS             = 0x00000020
IDLE_PRIORITY_CLASS               = 0x00000040
HIGH_PRIORITY_CLASS               = 0x00000080
REALTIME_PRIORITY_CLASS           = 0x00000100

CREATE_NEW_PROCESS_GROUP          = 0x00000200
CREATE_UNICODE_ENVIRONMENT        = 0x00000400

CREATE_SEPARATE_WOW_VDM           = 0x00000800
CREATE_SHARED_WOW_VDM             = 0x00001000
CREATE_FORCEDOS                   = 0x00002000

BELOW_NORMAL_PRIORITY_CLASS       = 0x00004000
ABOVE_NORMAL_PRIORITY_CLASS       = 0x00008000
STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000

CREATE_BREAKAWAY_FROM_JOB         = 0x01000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL  = 0x02000000

CREATE_DEFAULT_ERROR_MODE         = 0x04000000
CREATE_NO_WINDOW                  = 0x08000000

PROFILE_USER                      = 0x10000000
PROFILE_KERNEL                    = 0x20000000
PROFILE_SERVER                    = 0x40000000

CREATE_IGNORE_SYSTEM_DEFAULT      = 0x80000000

THREAD_BASE_PRIORITY_LOWRT  = 15    # value that gets a thread to LowRealtime-1
THREAD_BASE_PRIORITY_MAX    = 2     # maximum thread base priority boost
THREAD_BASE_PRIORITY_MIN    = (-2)  # minimum thread base priority boost
THREAD_BASE_PRIORITY_IDLE   = (-15) # value that gets a thread to idle

THREAD_PRIORITY_LOWEST          = THREAD_BASE_PRIORITY_MIN
THREAD_PRIORITY_BELOW_NORMAL    = (THREAD_PRIORITY_LOWEST+1)
THREAD_PRIORITY_NORMAL          = 0
THREAD_PRIORITY_HIGHEST         = THREAD_BASE_PRIORITY_MAX
THREAD_PRIORITY_ABOVE_NORMAL    = (THREAD_PRIORITY_HIGHEST-1)
THREAD_PRIORITY_ERROR_RETURN    = (0xFFFFFFFFL)

THREAD_PRIORITY_TIME_CRITICAL   = THREAD_BASE_PRIORITY_LOWRT
THREAD_PRIORITY_IDLE            = THREAD_BASE_PRIORITY_IDLE

# Memory access
SECTION_QUERY                = 0x0001
SECTION_MAP_WRITE            = 0x0002
SECTION_MAP_READ             = 0x0004
SECTION_MAP_EXECUTE          = 0x0008
SECTION_EXTEND_SIZE          = 0x0010
SECTION_MAP_EXECUTE_EXPLICIT = 0x0020 # not included in SECTION_ALL_ACCESS

SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                             SECTION_MAP_WRITE |      \
                             SECTION_MAP_READ |       \
                             SECTION_MAP_EXECUTE |    \
                             SECTION_EXTEND_SIZE)
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD            = 0x100
PAGE_NOCACHE          = 0x200
PAGE_WRITECOMBINE     = 0x400
MEM_COMMIT           = 0x1000
MEM_RESERVE          = 0x2000
MEM_DECOMMIT         = 0x4000
MEM_RELEASE          = 0x8000
MEM_FREE            = 0x10000
MEM_PRIVATE         = 0x20000
MEM_MAPPED          = 0x40000
MEM_RESET           = 0x80000
MEM_TOP_DOWN       = 0x100000
MEM_WRITE_WATCH    = 0x200000
MEM_PHYSICAL       = 0x400000
MEM_LARGE_PAGES  = 0x20000000
MEM_4MB_PAGES    = 0x80000000
SEC_FILE           = 0x800000
SEC_IMAGE         = 0x1000000
SEC_RESERVE       = 0x4000000
SEC_COMMIT        = 0x8000000
SEC_NOCACHE      = 0x10000000
SEC_LARGE_PAGES  = 0x80000000
MEM_IMAGE         = SEC_IMAGE
WRITE_WATCH_FLAG_RESET = 0x01
FILE_MAP_ALL_ACCESS = 0xF001F

SECTION_QUERY                   = 0x0001
SECTION_MAP_WRITE               = 0x0002
SECTION_MAP_READ                = 0x0004
SECTION_MAP_EXECUTE             = 0x0008
SECTION_EXTEND_SIZE             = 0x0010
SECTION_MAP_EXECUTE_EXPLICIT    = 0x0020 # not included in SECTION_ALL_ACCESS

SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                 SECTION_MAP_WRITE |      \
                 SECTION_MAP_READ |       \
                 SECTION_MAP_EXECUTE |    \
                 SECTION_EXTEND_SIZE)

FILE_MAP_COPY       = SECTION_QUERY
FILE_MAP_WRITE      = SECTION_MAP_WRITE
FILE_MAP_READ       = SECTION_MAP_READ
FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS
FILE_MAP_EXECUTE    = SECTION_MAP_EXECUTE_EXPLICIT  # not included in FILE_MAP_ALL_ACCESS

GENERIC_READ                     = 0x80000000
GENERIC_WRITE                    = 0x40000000
GENERIC_EXECUTE                  = 0x20000000
GENERIC_ALL                      = 0x10000000

FILE_SHARE_READ                  = 0x00000001
FILE_SHARE_WRITE                 = 0x00000002
FILE_SHARE_DELETE                = 0x00000004

CREATE_NEW                       = 1
CREATE_ALWAYS                    = 2
OPEN_EXISTING                    = 3
OPEN_ALWAYS                      = 4
TRUNCATE_EXISTING                = 5

FILE_ATTRIBUTE_READONLY          = 0x00000001
FILE_ATTRIBUTE_NORMAL            = 0x00000080
FILE_ATTRIBUTE_TEMPORARY         = 0x00000100

FILE_FLAG_WRITE_THROUGH          = 0x80000000
FILE_FLAG_NO_BUFFERING           = 0x20000000
FILE_FLAG_RANDOM_ACCESS          = 0x10000000
FILE_FLAG_SEQUENTIAL_SCAN        = 0x08000000
FILE_FLAG_DELETE_ON_CLOSE        = 0x04000000
FILE_FLAG_OVERLAPPED             = 0x40000000

FILE_ATTRIBUTE_READONLY          = 0x00000001
FILE_ATTRIBUTE_HIDDEN            = 0x00000002
FILE_ATTRIBUTE_SYSTEM            = 0x00000004
FILE_ATTRIBUTE_DIRECTORY         = 0x00000010
FILE_ATTRIBUTE_ARCHIVE           = 0x00000020
FILE_ATTRIBUTE_DEVICE            = 0x00000040
FILE_ATTRIBUTE_NORMAL            = 0x00000080
FILE_ATTRIBUTE_TEMPORARY         = 0x00000100

# Debug events
EXCEPTION_DEBUG_EVENT       = 1
CREATE_THREAD_DEBUG_EVENT   = 2
CREATE_PROCESS_DEBUG_EVENT  = 3
EXIT_THREAD_DEBUG_EVENT     = 4
EXIT_PROCESS_DEBUG_EVENT    = 5
LOAD_DLL_DEBUG_EVENT        = 6
UNLOAD_DLL_DEBUG_EVENT      = 7
OUTPUT_DEBUG_STRING_EVENT   = 8
RIP_EVENT                   = 9

# Status codes
STATUS_WAIT_0                   = 0x00000000L
STATUS_ABANDONED_WAIT_0         = 0x00000080L
STATUS_USER_APC                 = 0x000000C0L
STATUS_TIMEOUT                  = 0x00000102L
STATUS_PENDING                  = 0x00000103L
DBG_EXCEPTION_HANDLED           = 0x00010001L
DBG_CONTINUE                    = 0x00010002L
DBG_EXCEPTION_NOT_HANDLED       = 0x80010001L
STATUS_SEGMENT_NOTIFICATION     = 0x40000005L
##DBG_TERMINATE_THREAD            = 0x40010003L
##DBG_TERMINATE_PROCESS           = 0x40010004L
##DBG_CONTROL_C                   = 0x40010005L
##DBG_CONTROL_BREAK               = 0x40010008L
##DBG_COMMAND_EXCEPTION           = 0x40010009L
STATUS_GUARD_PAGE_VIOLATION     = 0x80000001L
STATUS_DATATYPE_MISALIGNMENT    = 0x80000002L
STATUS_BREAKPOINT               = 0x80000003L
STATUS_SINGLE_STEP              = 0x80000004L
STATUS_INVALID_INFO_CLASS       = 0xC0000003L
STATUS_ACCESS_VIOLATION         = 0xC0000005L
STATUS_IN_PAGE_ERROR            = 0xC0000006L
STATUS_INVALID_HANDLE           = 0xC0000008L
STATUS_NO_MEMORY                = 0xC0000017L
STATUS_ILLEGAL_INSTRUCTION      = 0xC000001DL
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025L
STATUS_INVALID_DISPOSITION      = 0xC0000026L
STATUS_ARRAY_BOUNDS_EXCEEDED    = 0xC000008CL
STATUS_FLOAT_DENORMAL_OPERAND   = 0xC000008DL
STATUS_FLOAT_DIVIDE_BY_ZERO     = 0xC000008EL
STATUS_FLOAT_INEXACT_RESULT     = 0xC000008FL
STATUS_FLOAT_INVALID_OPERATION  = 0xC0000090L
STATUS_FLOAT_OVERFLOW           = 0xC0000091L
STATUS_FLOAT_STACK_CHECK        = 0xC0000092L
STATUS_FLOAT_UNDERFLOW          = 0xC0000093L
STATUS_INTEGER_DIVIDE_BY_ZERO   = 0xC0000094L
STATUS_INTEGER_OVERFLOW         = 0xC0000095L
STATUS_PRIVILEGED_INSTRUCTION   = 0xC0000096L
STATUS_STACK_OVERFLOW           = 0xC00000FDL
STATUS_CONTROL_C_EXIT           = 0xC000013AL
STATUS_FLOAT_MULTIPLE_FAULTS    = 0xC00002B4L
STATUS_FLOAT_MULTIPLE_TRAPS     = 0xC00002B5L
STATUS_REG_NAT_CONSUMPTION      = 0xC00002C9L
STATUS_SXS_EARLY_DEACTIVATION   = 0xC015000FL
STATUS_SXS_INVALID_DEACTIVATION = 0xC0150010L

STATUS_STACK_BUFFER_OVERRUN     = 0xC0000409L
STATUS_WX86_BREAKPOINT          = 0x4000001FL
STATUS_HEAP_CORRUPTION          = 0xC0000374L

STATUS_POSSIBLE_DEADLOCK        = 0xC0000194L

STATUS_UNWIND_CONSOLIDATE       = 0x80000029L

# Exception codes

EXCEPTION_ACCESS_VIOLATION          = STATUS_ACCESS_VIOLATION
EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_BREAKPOINT                = STATUS_BREAKPOINT
EXCEPTION_DATATYPE_MISALIGNMENT     = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_FLT_DENORMAL_OPERAND      = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO        = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT        = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION     = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW              = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK           = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW             = STATUS_FLOAT_UNDERFLOW
EXCEPTION_ILLEGAL_INSTRUCTION       = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR             = STATUS_IN_PAGE_ERROR
EXCEPTION_INT_DIVIDE_BY_ZERO        = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW              = STATUS_INTEGER_OVERFLOW
EXCEPTION_INVALID_DISPOSITION       = STATUS_INVALID_DISPOSITION
EXCEPTION_NONCONTINUABLE_EXCEPTION  = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_PRIV_INSTRUCTION          = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_SINGLE_STEP               = STATUS_SINGLE_STEP
EXCEPTION_STACK_OVERFLOW            = STATUS_STACK_OVERFLOW

EXCEPTION_GUARD_PAGE                = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE            = STATUS_INVALID_HANDLE
EXCEPTION_POSSIBLE_DEADLOCK         = STATUS_POSSIBLE_DEADLOCK

CONTROL_C_EXIT                      = STATUS_CONTROL_C_EXIT

DBG_CONTROL_C                       = 0x40010005L
MS_VC_EXCEPTION                     = 0x406D1388L

# Access violation types
ACCESS_VIOLATION_TYPE_READ      = EXCEPTION_READ_FAULT
ACCESS_VIOLATION_TYPE_WRITE     = EXCEPTION_WRITE_FAULT
ACCESS_VIOLATION_TYPE_DEP       = EXCEPTION_EXECUTE_FAULT

# DuplicateHandle constants
DUPLICATE_CLOSE_SOURCE      = 0x00000001
DUPLICATE_SAME_ACCESS       = 0x00000002

# GetFinalPathNameByHandle constants
FILE_NAME_NORMALIZED        = 0x0
FILE_NAME_OPENED            = 0x8
VOLUME_NAME_DOS             = 0x0
VOLUME_NAME_GUID            = 0x1
VOLUME_NAME_NONE            = 0x4
VOLUME_NAME_NT              = 0x2

#--- Handle wrappers ----------------------------------------------------------

class Handle (object):
    """
    Encapsulates Win32 handles to avoid leaking them.

    @see: L{ProcessHandle}, L{ThreadHandle}, L{FileHandle}
    """

    def __init__(self, aHandle = None, bOwnership = True):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle value.

        @type  bOwnership: bool
        @param bOwnership:
           C{True} if we own the handle and we need to close it.
           C{False} if someone else will be calling L{CloseHandle}.
        """
        super(Handle, self).__init__()
        self.value      = self._normalize(aHandle)
        self.bOwnership = bOwnership

    def __del__(self):
        """
        Closes the Win32 handle when the Python object is destroyed.
        """
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self):
        """
        Duplicates the Win32 handle when copying the Python object.

        @rtype:  L{Handle}
        @return: A new handle to the same Win32 object.
        """
        return self.dup()

    def __deepcopy__(self):
        """
        Duplicates the Win32 handle when copying the Python object.

        @rtype:  L{Handle}
        @return: A new handle to the same win32 object.
        """
        return self.dup()

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Handle object to an API call.
        """
        return HANDLE(self.value)

    @staticmethod
    def from_param(value):
        """
        Compatibility with ctypes.
        Allows passing transparently a Handle object to an API call.

        @type  value: int
        @param value: Numeric handle value.
        """
        return HANDLE(value)

    def close(self):
        """
        Closes the Win32 handle.
        """
        if self.bOwnership and self.value not in (None, INVALID_HANDLE_VALUE):
            try:
                CloseHandle(self.value)
            finally:
                self.value = None

    def dup(self):
        """
        @rtype:  L{Handle}
        @return: A new handle to the same Win32 object.
        """
        return DuplicateHandle(self.value)

    @staticmethod
    def _normalize(value):
        """
        Normalize handle values.
        """
        if value is None:
            value = 0
        elif hasattr(value, 'value'):
            value = value.value
        else:
            value = long(value)
        return value

    def wait(self, dwMilliseconds = None):
        """
        Wait for the Win32 object to be signaled.

        @type  dwMilliseconds: int
        @param dwMilliseconds: (Optional) Timeout value in milliseconds.
            Use C{INFINITE} or C{None} for no timeout.
        """
        if dwMilliseconds is None:
            dwMilliseconds = INFINITE
        r = WaitForSingleObject(self.value, dwMilliseconds)
        if r != WAIT_OBJECT_0:
            raise ctypes.WinError(r)

class ProcessHandle (Handle):
    """
    Win32 process handle.

    @see: L{Handle}
    """

    def get_pid(self):
        """
        @rtype:  int
        @return: Process global ID.
        """
        return GetProcessId(self.value)

class ThreadHandle (Handle):
    """
    Win32 thread handle.

    @see: L{Handle}
    """

    def get_tid(self):
        """
        @rtype:  int
        @return: Thread global ID.
        """
        return GetThreadId(self.value)

# TODO
# maybe add file mapping support here?
class FileHandle (Handle):
    """
    Win32 file handle.

    @see: L{Handle}
    """

    def get_filename(self):
        """
        @rtype:  None or str
        @return: Name of the open file, or C{None} if unavailable.
        """
        #
        # XXX BUG
        #
        # This code truncates the first two bytes of the path.
        # It seems to be the expected behavior of NtQueryInformationFile.
        #
        # My guess is it only returns the NT pathname, without the device name.
        # It's like dropping the drive letter in a Win32 pathname.
        #
        # Note that using the "official" GetFileInformationByHandleEx
        # API introduced in Vista doesn't change the results!
        #
        dwBufferSize      = 0x1004
        lpFileInformation = ctypes.create_string_buffer(dwBufferSize)
        try:
            GetFileInformationByHandleEx(self.value,
                                        FILE_INFO_BY_HANDLE_CLASS.FileNameInfo,
                                        lpFileInformation, dwBufferSize)
        except AttributeError:
            from ntdll import NtQueryInformationFile, \
                              FileNameInformation, \
                              FILE_NAME_INFORMATION
            NtQueryInformationFile(self.value,
                                   FileNameInformation,
                                   lpFileInformation,
                                   dwBufferSize)
        FileName = unicode(lpFileInformation.raw[sizeof(DWORD):], 'U16')
        FileName = ctypes.create_unicode_buffer(FileName).value
        if not FileName:
            FileName = None
        return FileName

#--- Structure wrappers -------------------------------------------------------

class ProcessInformation (object):
    """
    Process information object returned by L{CreateProcess}.
    """

    def __init__(self, pi):
        self.hProcess    = ProcessHandle(pi.hProcess)
        self.hThread     = ThreadHandle(pi.hThread)
        self.dwProcessId = pi.dwProcessId
        self.dwThreadId  = pi.dwThreadId

class MemoryBasicInformation (object):
    """
    Memory information object returned by L{VirtualQueryEx}.
    """

    READABLE = (
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READONLY           |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    COPY_ON_WRITE = (
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_WRITECOPY
    )

    EXECUTABLE = (
                PAGE_EXECUTE            |
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    EXECUTABLE_AND_WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    def __init__(self, mbi):
        self.BaseAddress        = mbi.BaseAddress
        self.AllocationBase     = mbi.AllocationBase
        self.AllocationProtect  = mbi.AllocationProtect
        self.RegionSize         = mbi.RegionSize
        self.State              = mbi.State
        self.Protect            = mbi.Protect
        self.Type               = mbi.Type

    def is_free(self):
        return self.State == MEM_FREE

    def is_reserved(self):
        return self.State == MEM_RESERVED

    def is_commited(self):
        return self.State == MEM_COMMIT

    def is_guard(self):
        return self.is_commited() and self.Protect & PAGE_GUARD

    def has_content(self):
        return self.is_commited() and not self.Protect & (PAGE_GUARD | PAGE_NOACCESS)

    def is_readable(self):
        return self.has_content() and self.Protect & self.READABLE

    def is_writeable(self):
        return self.has_content() and self.Protect & self.WRITEABLE

    def is_copy_on_write(self):
        return self.has_content() and self.Protect & self.COPY_ON_WRITE

    def is_executable(self):
        return self.has_content() and self.Protect & self.EXECUTABLE

    def is_executable_and_writeable(self):
        return self.has_content() and self.Protect & self.EXECUTABLE_AND_WRITEABLE

#--- OVERLAPPED structure -----------------------------------------------------

# typedef struct _OVERLAPPED {
#   ULONG_PTR Internal;
#   ULONG_PTR InternalHigh;
#   union {
#     struct {
#       DWORD Offset;
#       DWORD OffsetHigh;
#     } ;
#     PVOID Pointer;
#   } ;
#   HANDLE    hEvent;
# }OVERLAPPED, *LPOVERLAPPED;
class _OVERLAPPED_STRUCT(Structure):
    _pack_ = 1
    _fields_ = [
        ('Offset',          DWORD),
        ('OffsetHigh',      DWORD),
    ]
class _OVERLAPPED_UNION(Union):
    _pack_ = 1
    _fields_ = [
        ('s',               _OVERLAPPED_STRUCT),
        ('Pointer',         PVOID),
    ]
class OVERLAPPED(Structure):
    _pack_ = 1
    _fields_ = [
        ('Internal',        ULONG_PTR),
        ('InternalHigh',    ULONG_PTR),
        ('u',               _OVERLAPPED_UNION),
        ('hEvent',          HANDLE),
    ]
LPOVERLAPPED = POINTER(OVERLAPPED)

#--- SECURITY_ATTRIBUTES structure --------------------------------------------

# typedef struct _SECURITY_ATTRIBUTES {
#     DWORD nLength;
#     LPVOID lpSecurityDescriptor;
#     BOOL bInheritHandle;
# } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
class SECURITY_ATTRIBUTES(Structure):
    _pack_ = 1
    _fields_ = [
        ('nLength',                 DWORD),
        ('lpSecurityDescriptor',    LPVOID),
        ('bInheritHandle',          BOOL),
    ]
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

#--- VS_FIXEDFILEINFO structure -----------------------------------------------

# struct VS_FIXEDFILEINFO {
#   DWORD dwSignature;
#   DWORD dwStrucVersion;
#   DWORD dwFileVersionMS;
#   DWORD dwFileVersionLS;
#   DWORD dwProductVersionMS;
#   DWORD dwProductVersionLS;
#   DWORD dwFileFlagsMask;
#   DWORD dwFileFlags;
#   DWORD dwFileOS;
#   DWORD dwFileType;
#   DWORD dwFileSubtype;
#   DWORD dwFileDateMS;
#   DWORD dwFileDateLS;
# };
class VS_FIXEDFILEINFO (Structure):
    _fields_ = [
        ("dwSignature",             DWORD),     # 0xFEEF04BD
        ("dwStrucVersion",          DWORD),
        ("dwFileVersionMS",         DWORD),
        ("dwFileVersionLS",         DWORD),
        ("dwProductVersionMS",      DWORD),
        ("dwProductVersionLS",      DWORD),
        ("dwFileFlagsMask",         DWORD),
        ("dwFileFlags",             DWORD),
        ("dwFileOS",                DWORD),
        ("dwFileType",              DWORD),
        ("dwFileSubtype",           DWORD),
        ("dwFileDateMS",            DWORD),
        ("dwFileDateLS",            DWORD),
    ]

#--- OSVERSIONINFO and OSVERSIONINFOEX structures and constants ---------------

VER_PLATFORM_WIN32s                 = 0
VER_PLATFORM_WIN32_WINDOWS          = 1
VER_PLATFORM_WIN32_NT               = 2

VER_SUITE_BACKOFFICE                = 0x00000004
VER_SUITE_BLADE                     = 0x00000400
VER_SUITE_COMPUTE_SERVER            = 0x00004000
VER_SUITE_DATACENTER                = 0x00000080
VER_SUITE_ENTERPRISE                = 0x00000002
VER_SUITE_EMBEDDEDNT                = 0x00000040
VER_SUITE_PERSONAL                  = 0x00000200
VER_SUITE_SINGLEUSERTS              = 0x00000100
VER_SUITE_SMALLBUSINESS             = 0x00000001
VER_SUITE_SMALLBUSINESS_RESTRICTED  = 0x00000020
VER_SUITE_STORAGE_SERVER            = 0x00002000
VER_SUITE_TERMINAL                  = 0x00000010
VER_SUITE_WH_SERVER                 = 0x00008000

VER_NT_DOMAIN_CONTROLLER            = 0x0000002
VER_NT_SERVER                       = 0x0000003
VER_NT_WORKSTATION                  = 0x0000001

VER_BUILDNUMBER                     = 0x0000004
VER_MAJORVERSION                    = 0x0000002
VER_MINORVERSION                    = 0x0000001
VER_PLATFORMID                      = 0x0000008
VER_PRODUCT_TYPE                    = 0x0000080
VER_SERVICEPACKMAJOR                = 0x0000020
VER_SERVICEPACKMINOR                = 0x0000010
VER_SUITENAME                       = 0x0000040

VER_EQUAL                           = 1
VER_GREATER                         = 2
VER_GREATER_EQUAL                   = 3
VER_LESS                            = 4
VER_LESS_EQUAL                      = 5
VER_AND                             = 6
VER_OR                              = 7

# typedef struct _OSVERSIONINFO {
#   DWORD dwOSVersionInfoSize;
#   DWORD dwMajorVersion;
#   DWORD dwMinorVersion;
#   DWORD dwBuildNumber;
#   DWORD dwPlatformId;
#   TCHAR szCSDVersion[128];
# }OSVERSIONINFO;
class OSVERSIONINFOA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion",      DWORD),
        ("dwMinorVersion",      DWORD),
        ("dwBuildNumber",       DWORD),
        ("dwPlatformId",        DWORD),
        ("szCSDVersion",        CHAR * 128),
    ]
class OSVERSIONINFOW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion",      DWORD),
        ("dwMinorVersion",      DWORD),
        ("dwBuildNumber",       DWORD),
        ("dwPlatformId",        DWORD),
        ("szCSDVersion",        WCHAR * 128),
    ]

# typedef struct _OSVERSIONINFOEX {
#   DWORD dwOSVersionInfoSize;
#   DWORD dwMajorVersion;
#   DWORD dwMinorVersion;
#   DWORD dwBuildNumber;
#   DWORD dwPlatformId;
#   TCHAR szCSDVersion[128];
#   WORD  wServicePackMajor;
#   WORD  wServicePackMinor;
#   WORD  wSuiteMask;
#   BYTE  wProductType;
#   BYTE  wReserved;
# }OSVERSIONINFOEX, *POSVERSIONINFOEX, *LPOSVERSIONINFOEX;
class OSVERSIONINFOEXA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion",      DWORD),
        ("dwMinorVersion",      DWORD),
        ("dwBuildNumber",       DWORD),
        ("dwPlatformId",        DWORD),
        ("szCSDVersion",        CHAR * 128),
        ("wServicePackMajor",   WORD),
        ("wServicePackMinor",   WORD),
        ("wSuiteMask",          WORD),
        ("wProductType",        BYTE),
        ("wReserved",           BYTE),
    ]
class OSVERSIONINFOEXW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion",      DWORD),
        ("dwMinorVersion",      DWORD),
        ("dwBuildNumber",       DWORD),
        ("dwPlatformId",        DWORD),
        ("szCSDVersion",        WCHAR * 128),
        ("wServicePackMajor",   WORD),
        ("wServicePackMinor",   WORD),
        ("wSuiteMask",          WORD),
        ("wProductType",        BYTE),
        ("wReserved",           BYTE),
    ]

LPOSVERSIONINFOA    = POINTER(OSVERSIONINFOA)
LPOSVERSIONINFOW    = POINTER(OSVERSIONINFOW)
LPOSVERSIONINFOEXA  = POINTER(OSVERSIONINFOEXA)
LPOSVERSIONINFOEXW  = POINTER(OSVERSIONINFOEXW)
POSVERSIONINFOA     = LPOSVERSIONINFOA
POSVERSIONINFOW     = LPOSVERSIONINFOW
POSVERSIONINFOEXA   = LPOSVERSIONINFOEXA
POSVERSIONINFOEXW   = LPOSVERSIONINFOA

#--- GetSystemMetrics constants -----------------------------------------------

SM_CXSCREEN             = 0
SM_CYSCREEN             = 1
SM_CXVSCROLL            = 2
SM_CYHSCROLL            = 3
SM_CYCAPTION            = 4
SM_CXBORDER             = 5
SM_CYBORDER             = 6
SM_CXDLGFRAME           = 7
SM_CYDLGFRAME           = 8
SM_CYVTHUMB             = 9
SM_CXHTHUMB             = 10
SM_CXICON               = 11
SM_CYICON               = 12
SM_CXCURSOR             = 13
SM_CYCURSOR             = 14
SM_CYMENU               = 15
SM_CXFULLSCREEN         = 16
SM_CYFULLSCREEN         = 17
SM_CYKANJIWINDOW        = 18
SM_MOUSEPRESENT         = 19
SM_CYVSCROLL            = 20
SM_CXHSCROLL            = 21
SM_DEBUG                = 22
SM_SWAPBUTTON           = 23
SM_RESERVED1            = 24
SM_RESERVED2            = 25
SM_RESERVED3            = 26
SM_RESERVED4            = 27
SM_CXMIN                = 28
SM_CYMIN                = 29
SM_CXSIZE               = 30
SM_CYSIZE               = 31
SM_CXFRAME              = 32
SM_CYFRAME              = 33
SM_CXMINTRACK           = 34
SM_CYMINTRACK           = 35
SM_CXDOUBLECLK          = 36
SM_CYDOUBLECLK          = 37
SM_CXICONSPACING        = 38
SM_CYICONSPACING        = 39
SM_MENUDROPALIGNMENT    = 40
SM_PENWINDOWS           = 41
SM_DBCSENABLED          = 42
SM_CMOUSEBUTTONS        = 43

SM_CXFIXEDFRAME         = SM_CXDLGFRAME     # ;win40 name change
SM_CYFIXEDFRAME         = SM_CYDLGFRAME     # ;win40 name change
SM_CXSIZEFRAME          = SM_CXFRAME        # ;win40 name change
SM_CYSIZEFRAME          = SM_CYFRAME        # ;win40 name change

SM_SECURE               = 44
SM_CXEDGE               = 45
SM_CYEDGE               = 46
SM_CXMINSPACING         = 47
SM_CYMINSPACING         = 48
SM_CXSMICON             = 49
SM_CYSMICON             = 50
SM_CYSMCAPTION          = 51
SM_CXSMSIZE             = 52
SM_CYSMSIZE             = 53
SM_CXMENUSIZE           = 54
SM_CYMENUSIZE           = 55
SM_ARRANGE              = 56
SM_CXMINIMIZED          = 57
SM_CYMINIMIZED          = 58
SM_CXMAXTRACK           = 59
SM_CYMAXTRACK           = 60
SM_CXMAXIMIZED          = 61
SM_CYMAXIMIZED          = 62
SM_NETWORK              = 63
SM_CLEANBOOT            = 67
SM_CXDRAG               = 68
SM_CYDRAG               = 69
SM_SHOWSOUNDS           = 70
SM_CXMENUCHECK          = 71  # Use instead of GetMenuCheckMarkDimensions()!
SM_CYMENUCHECK          = 72
SM_SLOWMACHINE          = 73
SM_MIDEASTENABLED       = 74
SM_MOUSEWHEELPRESENT    = 75
SM_XVIRTUALSCREEN       = 76
SM_YVIRTUALSCREEN       = 77
SM_CXVIRTUALSCREEN      = 78
SM_CYVIRTUALSCREEN      = 79
SM_CMONITORS            = 80
SM_SAMEDISPLAYFORMAT    = 81
SM_IMMENABLED           = 82
SM_CXFOCUSBORDER        = 83
SM_CYFOCUSBORDER        = 84
SM_TABLETPC             = 86
SM_MEDIACENTER          = 87
SM_STARTER              = 88
SM_SERVERR2             = 89
SM_MOUSEHORIZONTALWHEELPRESENT = 91
SM_CXPADDEDBORDER       = 92

SM_CMETRICS             = 93

SM_REMOTESESSION        = 0x1000
SM_SHUTTINGDOWN         = 0x2000
SM_REMOTECONTROL        = 0x2001
SM_CARETBLINKINGENABLED = 0x2002

#--- THREADNAME_INFO structure ------------------------------------------------

# typedef struct tagTHREADNAME_INFO
# {
#    DWORD dwType; // Must be 0x1000.
#    LPCSTR szName; // Pointer to name (in user addr space).
#    DWORD dwThreadID; // Thread ID (-1=caller thread).
#    DWORD dwFlags; // Reserved for future use, must be zero.
# } THREADNAME_INFO;
class THREADNAME_INFO(Structure):
    _fields_ = [
        ("dwType",      DWORD),     # 0x1000
        ("szName",      LPVOID),    # remote pointer
        ("dwThreadID",  DWORD),     # -1 usually
        ("dwFlags",     DWORD),     # 0
    ]

#--- MEMORY_BASIC_INFORMATION structure ---------------------------------------

# typedef struct _MEMORY_BASIC_INFORMATION32 {
#     DWORD BaseAddress;
#     DWORD AllocationBase;
#     DWORD AllocationProtect;
#     DWORD RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;
class MEMORY_BASIC_INFORMATION32(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseAddress',         DWORD),         # remote pointer
        ('AllocationBase',      DWORD),         # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          DWORD),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]

# typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64 {
#     ULONGLONG BaseAddress;
#     ULONGLONG AllocationBase;
#     DWORD     AllocationProtect;
#     DWORD     __alignment1;
#     ULONGLONG RegionSize;
#     DWORD     State;
#     DWORD     Protect;
#     DWORD     Type;
#     DWORD     __alignment2;
# } MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;
class MEMORY_BASIC_INFORMATION64(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseAddress',         ULONGLONG),     # remote pointer
        ('AllocationBase',      ULONGLONG),     # remote pointer
        ('AllocationProtect',   DWORD),
        ('__alignment1',        DWORD),
        ('RegionSize',          ULONGLONG),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
        ('__alignment2',        DWORD),
    ]

# typedef struct _MEMORY_BASIC_INFORMATION {
#     PVOID BaseAddress;
#     PVOID AllocationBase;
#     DWORD AllocationProtect;
#     SIZE_T RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
if sizeof(SIZE_T) == sizeof(DWORD):
    class MEMORY_BASIC_INFORMATION(MEMORY_BASIC_INFORMATION32):
        pass
elif sizeof(SIZE_T) == sizeof(DWORD64):
    class MEMORY_BASIC_INFORMATION(MEMORY_BASIC_INFORMATION64):
        pass
else:
    class MEMORY_BASIC_INFORMATION(Structure):
        _fields_ = [
            ('BaseAddress',         SIZE_T),    # remote pointer
            ('AllocationBase',      SIZE_T),    # remote pointer
            ('AllocationProtect',   DWORD),
            ('RegionSize',          SIZE_T),
            ('State',               DWORD),
            ('Protect',             DWORD),
            ('Type',                DWORD),
        ]
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)

#--- BY_HANDLE_FILE_INFORMATION structure -------------------------------------

# typedef struct _FILETIME {
#    DWORD dwLowDateTime;
#    DWORD dwHighDateTime;
# } FILETIME, *PFILETIME;
class FILETIME(Structure):
    _pack_ = 1
    _fields_ = [
        ('dwLowDateTime',       DWORD),
        ('dwHighDateTime',      DWORD),
    ]

# typedef struct _BY_HANDLE_FILE_INFORMATION {
#   DWORD dwFileAttributes;
#   FILETIME ftCreationTime;
#   FILETIME ftLastAccessTime;
#   FILETIME ftLastWriteTime;
#   DWORD dwVolumeSerialNumber;
#   DWORD nFileSizeHigh;
#   DWORD nFileSizeLow;
#   DWORD nNumberOfLinks;
#   DWORD nFileIndexHigh;
#   DWORD nFileIndexLow;
# } BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION;
class BY_HANDLE_FILE_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ('dwFileAttributes',        DWORD),
        ('ftCreationTime',          FILETIME),
        ('ftLastAccessTime',        FILETIME),
        ('ftLastWriteTime',         FILETIME),
        ('dwVolumeSerialNumber',    DWORD),
        ('nFileSizeHigh',           DWORD),
        ('nFileSizeLow',            DWORD),
        ('nNumberOfLinks',          DWORD),
        ('nFileIndexHigh',          DWORD),
        ('nFileIndexLow',           DWORD),
    ]
LPBY_HANDLE_FILE_INFORMATION = ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)

# typedef enum _FILE_INFO_BY_HANDLE_CLASS {
#   FileBasicInfo = 0,
#   FileStandardInfo = 1,
#   FileNameInfo = 2,
#   FileRenameInfo = 3,
#   FileDispositionInfo = 4,
#   FileAllocationInfo = 5,
#   FileEndOfFileInfo = 6,
#   FileStreamInfo = 7,
#   FileCompressionInfo = 8,
#   FileAttributeTagInfo = 9,
#   FileIdBothDirectoryInfo = 10,
#   FileIdBothDirectoryRestartInfo = 11,
#   FileIoPriorityHintInfo = 12,
#   MaximumFileInfoByHandlesClass = 13
# } FILE_INFO_BY_HANDLE_CLASS, *PFILE_INFO_BY_HANDLE_CLASS;
class FILE_INFO_BY_HANDLE_CLASS(object):
    FileBasicInfo                   = 0
    FileStandardInfo                = 1
    FileNameInfo                    = 2
    FileRenameInfo                  = 3
    FileDispositionInfo             = 4
    FileAllocationInfo              = 5
    FileEndOfFileInfo               = 6
    FileStreamInfo                  = 7
    FileCompressionInfo             = 8
    FileAttributeTagInfo            = 9
    FileIdBothDirectoryInfo         = 10
    FileIdBothDirectoryRestartInfo  = 11
    FileIoPriorityHintInfo          = 12
    MaximumFileInfoByHandlesClass   = 13

# typedef struct _FILE_NAME_INFO {
#   DWORD  FileNameLength;
#   WCHAR FileName[1];
# } FILE_NAME_INFO, *PFILE_NAME_INFO;
##class FILE_NAME_INFO(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ('FileNameLength',  DWORD),
##        ('FileName',        WCHAR * 1),
##    ]

# TO DO: add more structures used by GetFileInformationByHandleEx()

#--- PROCESS_INFORMATION structure --------------------------------------------

# typedef struct _PROCESS_INFORMATION {
#     HANDLE hProcess;
#     HANDLE hThread;
#     DWORD dwProcessId;
#     DWORD dwThreadId;
# } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
class PROCESS_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)

#--- STARTUPINFO and STARTUPINFOEX structures ---------------------------------

# typedef struct _STARTUPINFO {
#     DWORD   cb;
#     LPSTR   lpReserved;
#     LPSTR   lpDesktop;
#     LPSTR   lpTitle;
#     DWORD   dwX;
#     DWORD   dwY;
#     DWORD   dwXSize;
#     DWORD   dwYSize;
#     DWORD   dwXCountChars;
#     DWORD   dwYCountChars;
#     DWORD   dwFillAttribute;
#     DWORD   dwFlags;
#     WORD    wShowWindow;
#     WORD    cbReserved2;
#     LPBYTE  lpReserved2;
#     HANDLE  hStdInput;
#     HANDLE  hStdOutput;
#     HANDLE  hStdError;
# } STARTUPINFO, *LPSTARTUPINFO;
class STARTUPINFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPVOID),    # LPSTR
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       DWORD),
        ('hStdOutput',      DWORD),
        ('hStdError',       DWORD),
    ]
LPSTARTUPINFO = POINTER(STARTUPINFO)

# typedef struct _STARTUPINFOEX {
#   STARTUPINFO StartupInfo;
#   PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
# } STARTUPINFOEX,  *LPSTARTUPINFOEX;
class STARTUPINFOEX(Structure):
    _pack_ = 1
    _fields_ = [
        ('StartupInfo',     STARTUPINFO),
        ('lpAttributeList', LPVOID),
    ]
LPSTARTUPINFOEX = POINTER(STARTUPINFOEX)

#--- JIT_DEBUG_INFO structure -------------------------------------------------

# typedef struct _JIT_DEBUG_INFO {
#     DWORD dwSize;
#     DWORD dwProcessorArchitecture;
#     DWORD dwThreadID;
#     DWORD dwReserved0;
#     ULONG64 lpExceptionAddress;
#     ULONG64 lpExceptionRecord;
#     ULONG64 lpContextRecord;
# } JIT_DEBUG_INFO, *LPJIT_DEBUG_INFO;
class JIT_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwSize',                  DWORD),
        ('dwProcessorArchitecture', DWORD),
        ('dwThreadID',              DWORD),
        ('dwReserved0',             DWORD),
        ('lpExceptionAddress',      ULONG64),
        ('lpExceptionRecord',       ULONG64),
        ('lpContextRecord',         ULONG64),
    ]
JIT_DEBUG_INFO32 = JIT_DEBUG_INFO
JIT_DEBUG_INFO64 = JIT_DEBUG_INFO

LPJIT_DEBUG_INFO   = ctypes.POINTER(JIT_DEBUG_INFO)
LPJIT_DEBUG_INFO32 = ctypes.POINTER(JIT_DEBUG_INFO32)
LPJIT_DEBUG_INFO64 = ctypes.POINTER(JIT_DEBUG_INFO64)

#--- DEBUG_EVENT structure ----------------------------------------------------

# typedef struct _EXCEPTION_RECORD32 {
#     DWORD ExceptionCode;
#     DWORD ExceptionFlags;
#     DWORD ExceptionRecord;
#     DWORD ExceptionAddress;
#     DWORD NumberParameters;
#     DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;
class EXCEPTION_RECORD32(Structure):
    _fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         DWORD),
        ('ExceptionAddress',        DWORD),
        ('NumberParameters',        DWORD),
        ('ExceptionInformation',    DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

PEXCEPTION_RECORD32 = POINTER(EXCEPTION_RECORD32)

# typedef struct _EXCEPTION_RECORD64 {
#     DWORD    ExceptionCode;
#     DWORD ExceptionFlags;
#     DWORD64 ExceptionRecord;
#     DWORD64 ExceptionAddress;
#     DWORD NumberParameters;
#     DWORD __unusedAlignment;
#     DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;
class EXCEPTION_RECORD64(Structure):
    _fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         DWORD64),
        ('ExceptionAddress',        DWORD64),
        ('NumberParameters',        DWORD),
        ('__unusedAlignment',       DWORD),
        ('ExceptionInformation',    DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

PEXCEPTION_RECORD64 = POINTER(EXCEPTION_RECORD64)

if sizeof(SIZE_T) == sizeof(DWORD):
    EXCEPTION_RECORD = EXCEPTION_RECORD32
elif sizeof(SIZE_T) == sizeof(DWORD64):
    EXCEPTION_RECORD = EXCEPTION_RECORD64
else:
    # typedef struct _EXCEPTION_RECORD {
    #     DWORD ExceptionCode;
    #     DWORD ExceptionFlags;
    #     LPVOID ExceptionRecord;
    #     LPVOID ExceptionAddress;
    #     DWORD NumberParameters;
    #     LPVOID ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    # } EXCEPTION_RECORD, *PEXCEPTION_RECORD;
    class EXCEPTION_RECORD(Structure):
        _fields_ = [
            ('ExceptionCode',           DWORD),
            ('ExceptionFlags',          DWORD),
            ('ExceptionRecord',         LPVOID),
            ('ExceptionAddress',        LPVOID),
            ('NumberParameters',        DWORD),
            ('ExceptionInformation',    LPVOID * EXCEPTION_MAXIMUM_PARAMETERS),
        ]
PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)

# typedef struct _EXCEPTION_DEBUG_INFO {
#   EXCEPTION_RECORD ExceptionRecord;
#   DWORD dwFirstChance;
# } EXCEPTION_DEBUG_INFO;
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ('ExceptionRecord',     EXCEPTION_RECORD),
        ('dwFirstChance',       DWORD),
    ]

# typedef struct _CREATE_THREAD_DEBUG_INFO {
#   HANDLE hThread;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
# } CREATE_THREAD_DEBUG_INFO;
class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('hThread',             HANDLE),
        ('lpThreadLocalBase',   LPVOID),
        ('lpStartAddress',      LPVOID),
    ]

# typedef struct _CREATE_PROCESS_DEBUG_INFO {
#   HANDLE hFile;
#   HANDLE hProcess;
#   HANDLE hThread;
#   LPVOID lpBaseOfImage;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } CREATE_PROCESS_DEBUG_INFO;
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('hProcess',                HANDLE),
        ('hThread',                 HANDLE),
        ('lpBaseOfImage',           LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpThreadLocalBase',       LPVOID),
        ('lpStartAddress',          LPVOID),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _EXIT_THREAD_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_THREAD_DEBUG_INFO;
class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _EXIT_PROCESS_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_PROCESS_DEBUG_INFO;
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _LOAD_DLL_DEBUG_INFO {
#   HANDLE hFile;
#   LPVOID lpBaseOfDll;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } LOAD_DLL_DEBUG_INFO;
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('lpBaseOfDll',             LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _UNLOAD_DLL_DEBUG_INFO {
#   LPVOID lpBaseOfDll;
# } UNLOAD_DLL_DEBUG_INFO;
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('lpBaseOfDll',         LPVOID),
    ]

# typedef struct _OUTPUT_DEBUG_STRING_INFO {
#   LPSTR lpDebugStringData;
#   WORD fUnicode;
#   WORD nDebugStringLength;
# } OUTPUT_DEBUG_STRING_INFO;
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ('lpDebugStringData',   LPVOID),    # don't use LPSTR
        ('fUnicode',            WORD),
        ('nDebugStringLength',  WORD),
    ]

# typedef struct _RIP_INFO {
#     DWORD dwError;
#     DWORD dwType;
# } RIP_INFO, *LPRIP_INFO;
class RIP_INFO(Structure):
    _fields_ = [
        ('dwError',             DWORD),
        ('dwType',              DWORD),
    ]

# typedef struct _DEBUG_EVENT {
#   DWORD dwDebugEventCode;
#   DWORD dwProcessId;
#   DWORD dwThreadId;
#   union {
#     EXCEPTION_DEBUG_INFO Exception;
#     CREATE_THREAD_DEBUG_INFO CreateThread;
#     CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
#     EXIT_THREAD_DEBUG_INFO ExitThread;
#     EXIT_PROCESS_DEBUG_INFO ExitProcess;
#     LOAD_DLL_DEBUG_INFO LoadDll;
#     UNLOAD_DLL_DEBUG_INFO UnloadDll;
#     OUTPUT_DEBUG_STRING_INFO DebugString;
#     RIP_INFO RipInfo;
#   } u;
# } DEBUG_EVENT;.
class _DEBUG_EVENT_UNION_(Union):
    _fields_ = [
        ('Exception',           EXCEPTION_DEBUG_INFO),
        ('CreateThread',        CREATE_THREAD_DEBUG_INFO),
        ('CreateProcessInfo',   CREATE_PROCESS_DEBUG_INFO),
        ('ExitThread',          EXIT_THREAD_DEBUG_INFO),
        ('ExitProcess',         EXIT_PROCESS_DEBUG_INFO),
        ('LoadDll',             LOAD_DLL_DEBUG_INFO),
        ('UnloadDll',           UNLOAD_DLL_DEBUG_INFO),
        ('DebugString',         OUTPUT_DEBUG_STRING_INFO),
        ('RipInfo',             RIP_INFO),
    ]
class DEBUG_EVENT(Structure):
    _fields_ = [
        ('dwDebugEventCode',    DWORD),
        ('dwProcessId',         DWORD),
        ('dwThreadId',          DWORD),
        ('u',                   _DEBUG_EVENT_UNION_),
    ]
LPDEBUG_EVENT = ctypes.POINTER(DEBUG_EVENT)

#--- WOW64 CONTEXT structure and constants ------------------------------------

# Value of SegCs in a Wow64 thread when running in 32 bits mode
WOW64_CS32 = 0x23

WOW64_CONTEXT_i386 = 0x00010000L
WOW64_CONTEXT_i486 = 0x00010000L

WOW64_CONTEXT_CONTROL               = (WOW64_CONTEXT_i386 | 0x00000001L)
WOW64_CONTEXT_INTEGER               = (WOW64_CONTEXT_i386 | 0x00000002L)
WOW64_CONTEXT_SEGMENTS              = (WOW64_CONTEXT_i386 | 0x00000004L)
WOW64_CONTEXT_FLOATING_POINT        = (WOW64_CONTEXT_i386 | 0x00000008L)
WOW64_CONTEXT_DEBUG_REGISTERS       = (WOW64_CONTEXT_i386 | 0x00000010L)
WOW64_CONTEXT_EXTENDED_REGISTERS    = (WOW64_CONTEXT_i386 | 0x00000020L)

WOW64_CONTEXT_FULL                  = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)
WOW64_CONTEXT_ALL                   = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS)

WOW64_SIZE_OF_80387_REGISTERS       = 80
WOW64_MAXIMUM_SUPPORTED_EXTENSION   = 512

class WOW64_FLOATING_SAVE_AREA (context_i386.FLOATING_SAVE_AREA):
    pass

class WOW64_CONTEXT (context_i386.CONTEXT):
    pass

class WOW64_LDT_ENTRY (context_i386.LDT_ENTRY):
    pass

PWOW64_FLOATING_SAVE_AREA   = POINTER(WOW64_FLOATING_SAVE_AREA)
PWOW64_CONTEXT              = POINTER(WOW64_CONTEXT)
PWOW64_LDT_ENTRY            = POINTER(WOW64_LDT_ENTRY)

#--- Toolhelp library defines and structures ----------------------------------

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

# typedef struct tagTHREADENTRY32 {
#   DWORD dwSize;
#   DWORD cntUsage;
#   DWORD th32ThreadID;
#   DWORD th32OwnerProcessID;
#   LONG tpBasePri;
#   LONG tpDeltaPri;
#   DWORD dwFlags;
# } THREADENTRY32,  *PTHREADENTRY32;
class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          LONG),
        ('tpDeltaPri',         LONG),
        ('dwFlags',            DWORD),
    ]
LPTHREADENTRY32 = ctypes.POINTER(THREADENTRY32)

# typedef struct tagPROCESSENTRY32 {
#    DWORD dwSize;
#    DWORD cntUsage;
#    DWORD th32ProcessID;
#    ULONG_PTR th32DefaultHeapID;
#    DWORD th32ModuleID;
#    DWORD cntThreads;
#    DWORD th32ParentProcessID;
#    LONG pcPriClassBase;
#    DWORD dwFlags;
#    TCHAR szExeFile[MAX_PATH];
# } PROCESSENTRY32,  *PPROCESSENTRY32;
class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   LPVOID),    # remote pointer
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * 260),
    ]
LPPROCESSENTRY32 = ctypes.POINTER(PROCESSENTRY32)

# typedef struct tagMODULEENTRY32 {
#   DWORD dwSize;
#   DWORD th32ModuleID;
#   DWORD th32ProcessID;
#   DWORD GlblcntUsage;
#   DWORD ProccntUsage;
#   BYTE* modBaseAddr;
#   DWORD modBaseSize;
#   HMODULE hModule;
#   TCHAR szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR szExePath[MAX_PATH];
# } MODULEENTRY32,  *PMODULEENTRY32;
class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   LPVOID),  # BYTE*
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]
LPMODULEENTRY32 = ctypes.POINTER(MODULEENTRY32)

# typedef struct tagHEAPENTRY32 {
#   SIZE_T    dwSize;
#   HANDLE    hHandle;
#   ULONG_PTR dwAddress;
#   SIZE_T    dwBlockSize;
#   DWORD     dwFlags;
#   DWORD     dwLockCount;
#   DWORD     dwResvd;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
# } HEAPENTRY32,
# *PHEAPENTRY32;
class HEAPENTRY32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("hHandle",         HANDLE),
        ("dwAddress",       LPVOID),    # remote pointer
        ("dwBlockSize",     SIZE_T),
        ("dwFlags",         DWORD),
        ("dwLockCount",     DWORD),
        ("dwResvd",         DWORD),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      LPVOID),    # remote pointer
]
LPHEAPENTRY32 = ctypes.POINTER(HEAPENTRY32)

# typedef struct tagHEAPLIST32 {
#   SIZE_T    dwSize;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
#   DWORD     dwFlags;
# } HEAPLIST32,
#  *PHEAPLIST32;
class HEAPLIST32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      LPVOID),    # remote pointer
        ("dwFlags",         DWORD),
]
LPHEAPLIST32 = POINTER(HEAPLIST32)

#--- kernel32.dll -------------------------------------------------------------

# DWORD WINAPI GetLastError(void);
def GetLastError():
    _GetLastError = windll.kernel32.GetLastError
    _GetLastError.argtypes = []
    _GetLastError.restype = DWORD
    return _GetLastError()

# void WINAPI SetLastError(
#   __in  DWORD dwErrCode
# );
def SetLastError(dwErrCode):
    _SetLastError = windll.kernel32.SetLastError
    _SetLastError.argtypes = [DWORD]
    _SetLastError.restype = None
    _SetLastError(dwErrCode)

# void WINAPI SetLastErrorEx(
#   __in  DWORD dwErrCode,
#   __in  DWORD dwType
# );
def SetLastErrorEx(dwErrCode, dwType):
    _SetLastErrorEx = windll.kernel32.SetLastErrorEx
    _SetLastErrorEx.argtypes = [DWORD, DWORD]
    _SetLastErrorEx.restype = None
    _SetLastErrorEx(dwErrCode, dwType)

# BOOL WINAPI CloseHandle(
#   __in  HANDLE hObject
# );
def CloseHandle(hHandle):
    if isinstance(hHandle, Handle):
        # Prevents the handle from being closed without notifying the Handle object.
        hHandle.close()
    else:
        _CloseHandle = windll.kernel32.CloseHandle
        _CloseHandle.argtypes = [HANDLE]
        _CloseHandle.restype = bool
        _CloseHandle.errcheck = RaiseIfZero
        _CloseHandle(hHandle)

# BOOL WINAPI DuplicateHandle(
#   __in   HANDLE hSourceProcessHandle,
#   __in   HANDLE hSourceHandle,
#   __in   HANDLE hTargetProcessHandle,
#   __out  LPHANDLE lpTargetHandle,
#   __in   DWORD dwDesiredAccess,
#   __in   BOOL bInheritHandle,
#   __in   DWORD dwOptions
# );
def DuplicateHandle(hSourceHandle, hSourceProcessHandle = None, hTargetProcessHandle = None, dwDesiredAccess = STANDARD_RIGHTS_ALL, bInheritHandle = False, dwOptions = DUPLICATE_SAME_ACCESS):
    _DuplicateHandle = windll.kernel32.DuplicateHandle
    _DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD]
    _DuplicateHandle.restype = bool
    _DuplicateHandle.errcheck = RaiseIfZero

    if hSourceProcessHandle is None:
        hSourceProcessHandle = GetCurrentProcess()
    if hTargetProcessHandle is None:
        hTargetProcessHandle = hSourceProcessHandle
    lpTargetHandle = HANDLE(INVALID_HANDLE_VALUE)
    _DuplicateHandle(hSourceHandle, hSourceProcessHandle, hTargetProcessHandle, byref(lpTargetHandle), dwDesiredAccess, bool(bInheritHandle), dwOptions)
    return Handle(lpTargetHandle.value)

# void WINAPI OutputDebugString(
#   __in_opt  LPCTSTR lpOutputString
# );
def OutputDebugStringA(lpOutputString):
    _OutputDebugStringA = windll.kernel32.OutputDebugStringA
    _OutputDebugStringA.argtypes = [LPSTR]
    _OutputDebugStringA.restype = None
    _OutputDebugStringA(lpOutputString)

def OutputDebugStringW(lpOutputString):
    _OutputDebugStringW = windll.kernel32.OutputDebugStringW
    _OutputDebugStringW.argtypes = [LPWSTR]
    _OutputDebugStringW.restype = None
    _OutputDebugStringW(lpOutputString)

OutputDebugString = GuessStringType(OutputDebugStringA, OutputDebugStringW)

# BOOL WINAPI SetDllDirectory(
#   __in_opt  LPCTSTR lpPathName
# );
def SetDllDirectoryA(lpPathName):
    _SetDllDirectoryA = windll.kernel32.SetDllDirectoryA
    _SetDllDirectoryA.argytpes = [LPSTR]
    _SetDllDirectoryA.restype = bool
    _SetDllDirectoryA.errcheck = RaiseIfZero
    _SetDllDirectoryA(lpPathName)

def SetDllDirectoryW(lpPathName):
    _SetDllDirectoryW = windll.kernel32.SetDllDirectoryW
    _SetDllDirectoryW.argytpes = [LPWSTR]
    _SetDllDirectoryW.restype = bool
    _SetDllDirectoryW.errcheck = RaiseIfZero
    _SetDllDirectoryW(lpPathName)

SetDllDirectory = GuessStringType(SetDllDirectoryA, SetDllDirectoryW)

# HMODULE WINAPI LoadLibrary(
#   __in  LPCTSTR lpFileName
# );
def LoadLibraryA(pszLibrary):
    _LoadLibraryA = windll.kernel32.LoadLibraryA
    _LoadLibraryA.argtypes = LPSTR
    _LoadLibraryA.restype = HMODULE
    hModule = _LoadLibraryA(pszLibrary)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

def LoadLibraryW(pszLibrary):
    _LoadLibraryW = windll.kernel32.LoadLibraryW
    _LoadLibraryW.argtypes = LPWSTR
    _LoadLibraryW.restype = HMODULE
    hModule = _LoadLibraryW(pszLibrary)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

LoadLibrary = GuessStringType(LoadLibraryA, LoadLibraryW)

# HMODULE WINAPI LoadLibraryEx(
#   __in        LPCTSTR lpFileName,
#   __reserved  HANDLE hFile,
#   __in        DWORD dwFlags
# );
def LoadLibraryExA(pszLibrary, dwFlags = 0):
    _LoadLibraryExA = windll.kernel32.LoadLibraryExA
    _LoadLibraryExA.argtypes = LPSTR, HANDLE, DWORD
    _LoadLibraryExA.restype = HMODULE
    hModule = _LoadLibraryExA(pszLibrary, NULL, dwFlags)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

def LoadLibraryExW(pszLibrary, dwFlags = 0):
    _LoadLibraryExW = windll.kernel32.LoadLibraryExW
    _LoadLibraryExW.argtypes = LPWSTR, HANDLE, DWORD
    _LoadLibraryExW.restype = HMODULE
    hModule = _LoadLibraryExW(pszLibrary, NULL, dwFlags)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

LoadLibraryEx = GuessStringType(LoadLibraryExA, LoadLibraryExW)

# HMODULE WINAPI GetModuleHandle(
#   __in_opt  LPCTSTR lpModuleName
# );
def GetModuleHandleA(lpModuleName):
    _GetModuleHandleA = windll.kernel32.GetModuleHandleA
    _GetModuleHandleA.argtypes = [LPSTR]
    _GetModuleHandleA.restype = HMODULE
    hModule = _GetModuleHandleA(lpModuleName)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

def GetModuleHandleW(lpModuleName):
    _GetModuleHandleW = windll.kernel32.GetModuleHandleW
    _GetModuleHandleW.argtypes = [LPWSTR]
    _GetModuleHandleW.restype = HMODULE
    hModule = _GetModuleHandleW(lpModuleName)
    if hModule == NULL:
        raise ctypes.WinError()
    return hModule

GetModuleHandle = GuessStringType(GetModuleHandleA, GetModuleHandleW)

# FARPROC WINAPI GetProcAddress(
#   __in  HMODULE hModule,
#   __in  LPCSTR lpProcName
# );
def GetProcAddress(hModule, lpProcName):
    _GetProcAddress = windll.kernel32.GetProcAddress
    _GetProcAddress.argtypes = [HMODULE, LPVOID]
    _GetProcAddress.restype = LPVOID

    try:
        lpProcName = ctypes.c_char_p(lpProcName)
    except TypeError:
        lpProcName = LPVOID(lpProcName)
        if lpProcName.value & (~0xFFFF):
            raise ValueError, 'Ordinal number too large: %d' % lpProcName.value
    return _GetProcAddress(hModule, lpProcName)

# BOOL WINAPI FreeLibrary(
#   __in  HMODULE hModule
# );
def FreeLibrary(hModule):
    _FreeLibrary = windll.kernel32.FreeLibrary
    _FreeLibrary.argtypes = [HMODULE]
    _FreeLibrary.restype = bool
    _FreeLibrary.errcheck = RaiseIfZero
    _FreeLibrary(hModule)

# BOOL WINAPI QueryFullProcessImageName(
#   __in     HANDLE hProcess,
#   __in     DWORD dwFlags,
#   __out    LPTSTR lpExeName,
#   __inout  PDWORD lpdwSize
# );
def QueryFullProcessImageNameA(hProcess, dwFlags = 0):
    _QueryFullProcessImageNameA = windll.kernel32.QueryFullProcessImageNameA
    _QueryFullProcessImageNameA.argtypes = [HANDLE, DWORD, LPSTR, PDWORD]
    _QueryFullProcessImageNameA.restype = bool

    lpdwSize = DWORD(0)
    _QueryFullProcessImageNameA(hProcess, dwFlags, None, ctypes.byref(lpdwSize))
    if lpdwSize.value == 0:
        raise ctypes.WinError()
    lpExeName = ctypes.create_string_buffer('', lpdwSize.value + 1)
    success = _QueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, ctypes.byref(lpdwSize))
    if not success:
        raise ctypes.WinError()
    return lpExeName.value

def QueryFullProcessImageNameW(hProcess, dwFlags = 0):
    _QueryFullProcessImageNameW = windll.kernel32.QueryFullProcessImageNameW
    _QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, PDWORD]
    _QueryFullProcessImageNameW.restype = bool

    lpdwSize = DWORD(0)
    _QueryFullProcessImageNameW(hProcess, dwFlags, None, ctypes.byref(lpdwSize))
    if lpdwSize.value == 0:
        raise ctypes.WinError()
    lpExeName = ctypes.create_unicode_buffer(u'', lpdwSize.value + 1)
    success = _QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, ctypes.byref(lpdwSize))
    if not success:
        raise ctypes.WinError()
    return lpExeName.value

QueryFullProcessImageName = GuessStringType(QueryFullProcessImageNameA, QueryFullProcessImageNameW)

# DWORD WINAPI GetLogicalDriveStrings(
#   __in   DWORD nBufferLength,
#   __out  LPTSTR lpBuffer
# );
def GetLogicalDriveStringsA():
    _GetLogicalDriveStringsA = windll.kernel32.GetLogicalDriveStringsA
    _GetLogicalDriveStringsA.argtypes = [DWORD, LPSTR]
    _GetLogicalDriveStringsA.restype = DWORD
    _GetLogicalDriveStringsA.errcheck = RaiseIfZero

    nBufferLength = 0x1000
    lpBuffer = ctypes.create_string_buffer('', nBufferLength)
    _GetLogicalDriveStringsA(nBufferLength, ctypes.byref(lpBuffer))
    return lpBuffer.value

def GetLogicalDriveStringsW():
    _GetLogicalDriveStringsW = windll.kernel32.GetLogicalDriveStringsW
    _GetLogicalDriveStringsW.argtypes = [DWORD, LPWSTR]
    _GetLogicalDriveStringsW.restype = DWORD
    _GetLogicalDriveStringsW.errcheck = RaiseIfZero

    nBufferLength = 0x1000
    lpBuffer = ctypes.create_unicode_buffer('', nBufferLength)
    _GetLogicalDriveStringsW(nBufferLength, ctypes.byref(lpBuffer))
    return lpBuffer.value

GetLogicalDriveStrings = GuessStringType(GetLogicalDriveStringsA, GetLogicalDriveStringsW)

# DWORD WINAPI QueryDosDevice(
#   __in_opt  LPCTSTR lpDeviceName,
#   __out     LPTSTR lpTargetPath,
#   __in      DWORD ucchMax
# );
def QueryDosDeviceA(lpDeviceName = None):
    _QueryDosDeviceA = windll.kernel32.QueryDosDeviceA
    _QueryDosDeviceA.argtypes = [LPSTR, LPSTR, DWORD]
    _QueryDosDeviceA.restype = DWORD
    _QueryDosDeviceA.errcheck = RaiseIfZero

    if not lpDeviceName:
        lpDeviceName = None
    ucchMax = 0x1000
    lpTargetPath = ctypes.create_string_buffer('', ucchMax)
    _QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax)
    return lpTargetPath.value

def QueryDosDeviceW(lpDeviceName):
    _QueryDosDeviceW = windll.kernel32.QueryDosDeviceW
    _QueryDosDeviceW.argtypes = [LPWSTR, LPWSTR, DWORD]
    _QueryDosDeviceW.restype = DWORD
    _QueryDosDeviceW.errcheck = RaiseIfZero

    if not lpDeviceName:
        lpDeviceName = None
    ucchMax = 0x1000
    lpTargetPath = ctypes.create_unicode_buffer(u'', ucchMax)
    _QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax)
    return lpTargetPath.value

QueryDosDevice = GuessStringType(QueryDosDeviceA, QueryDosDeviceW)

# LPVOID WINAPI MapViewOfFile(
#   __in  HANDLE hFileMappingObject,
#   __in  DWORD dwDesiredAccess,
#   __in  DWORD dwFileOffsetHigh,
#   __in  DWORD dwFileOffsetLow,
#   __in  SIZE_T dwNumberOfBytesToMap
# );
def MapViewOfFile(hFileMappingObject, dwDesiredAccess = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, dwFileOffsetHigh = 0, dwFileOffsetLow = 0, dwNumberOfBytesToMap = 0):
    _MapViewOfFile = windll.kernel32.MapViewOfFile
    _MapViewOfFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, SIZE_T]
    _MapViewOfFile.restype = LPVOID
    lpBaseAddress = _MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
    if lpBaseAddress == NULL:
        raise ctypes.WinError()
    return lpBaseAddress

# BOOL WINAPI UnmapViewOfFile(
#   __in  LPCVOID lpBaseAddress
# );
def UnmapViewOfFile(lpBaseAddress):
    _UnmapViewOfFile = windll.kernel32.UnmapViewOfFile
    _UnmapViewOfFile.argtypes = [LPVOID]
    _UnmapViewOfFile.restype = bool
    _UnmapViewOfFile.errcheck = RaiseIfZero
    _UnmapViewOfFile(lpBaseAddress)

# HANDLE WINAPI OpenFileMapping(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  LPCTSTR lpName
# );
def OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName):
    _OpenFileMappingA = windll.kernel32.OpenFileMappingA
    _OpenFileMappingA.argtypes = [DWORD, BOOL, LPSTR]
    _OpenFileMappingA.restype = HANDLE
    hFileMappingObject = _OpenFileMappingA(dwDesiredAccess, bool(bInheritHandle), lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)

def OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName):
    _OpenFileMappingW = windll.kernel32.OpenFileMappingW
    _OpenFileMappingW.argtypes = [DWORD, BOOL, LPWSTR]
    _OpenFileMappingW.restype = HANDLE
    hFileMappingObject = _OpenFileMappingW(dwDesiredAccess, bool(bInheritHandle), lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)

OpenFileMapping = GuessStringType(OpenFileMappingA, OpenFileMappingW)

# HANDLE WINAPI CreateFileMapping(
#   __in      HANDLE hFile,
#   __in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
#   __in      DWORD flProtect,
#   __in      DWORD dwMaximumSizeHigh,
#   __in      DWORD dwMaximumSizeLow,
#   __in_opt  LPCTSTR lpName
# );
def CreateFileMappingA(hFile, lpAttributes = None, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = None):
    _CreateFileMappingA = windll.kernel32.CreateFileMappingA
    _CreateFileMappingA.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD, LPSTR]
    _CreateFileMappingA.restype = HANDLE

    if lpAttributes:
        lpAttributes = ctypes.pointer(lpAttributes)
    if not lpName:
        lpName = None
    hFileMappingObject = _CreateFileMappingA(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)

def CreateFileMappingW(hFile, lpAttributes = None, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = None):
    _CreateFileMappingW = windll.kernel32.CreateFileMappingW
    _CreateFileMappingW.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD, LPWSTR]
    _CreateFileMappingW.restype = HANDLE

    if lpAttributes:
        lpAttributes = ctypes.pointer(lpAttributes)
    if not lpName:
        lpName = None
    hFileMappingObject = _CreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)

CreateFileMapping = GuessStringType(CreateFileMappingA, CreateFileMappingW)

# HANDLE WINAPI CreateFile(
#   __in      LPCTSTR lpFileName,
#   __in      DWORD dwDesiredAccess,
#   __in      DWORD dwShareMode,
#   __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   __in      DWORD dwCreationDisposition,
#   __in      DWORD dwFlagsAndAttributes,
#   __in_opt  HANDLE hTemplateFile
# );
def CreateFileA(lpFileName, dwDesiredAccess = GENERIC_ALL, dwShareMode = 0, lpSecurityAttributes = None, dwCreationDisposition = OPEN_ALWAYS, dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL, hTemplateFile = None):
    _CreateFileA = windll.kernel32.CreateFileA
    _CreateFileA.argtypes = [LPSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]
    _CreateFileA.restype = HANDLE

    if not lpFileName:
        lpFileName = None
    if lpSecurityAttributes:
        lpSecurityAttributes = ctypes.pointer(lpSecurityAttributes)
    hFile = _CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFile)

def CreateFileW(lpFileName, dwDesiredAccess = GENERIC_ALL, dwShareMode = 0, lpSecurityAttributes = None, dwCreationDisposition = OPEN_ALWAYS, dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL, hTemplateFile = None):
    _CreateFileW = windll.kernel32.CreateFileW
    _CreateFileW.argtypes = [LPWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]
    _CreateFileW.restype = HANDLE

    if not lpFileName:
        lpFileName = None
    if lpSecurityAttributes:
        lpSecurityAttributes = ctypes.pointer(lpSecurityAttributes)
    hFile = _CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFile)

CreateFile = GuessStringType(CreateFileA, CreateFileW)

# BOOL WINAPI FlushFileBuffers(
#   __in  HANDLE hFile
# );
def FlushFileBuffers(hFile):
    _FlushFileBuffers = windll.kernel32.FlushFileBuffers
    _FlushFileBuffers.argtypes = [HANDLE]
    _FlushFileBuffers.restype = bool
    _FlushFileBuffers.errcheck = RaiseIfZero
    _FlushFileBuffers(hFile)

# BOOL WINAPI FlushViewOfFile(
#   __in  LPCVOID lpBaseAddress,
#   __in  SIZE_T dwNumberOfBytesToFlush
# );
def FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush = 0):
    _FlushViewOfFile = windll.kernel32.FlushViewOfFile
    _FlushViewOfFile.argtypes = [LPVOID, SIZE_T]
    _FlushViewOfFile.restype = bool
    _FlushViewOfFile.errcheck = RaiseIfZero
    _FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush)

# DWORD WINAPI SearchPath(
#   __in_opt   LPCTSTR lpPath,
#   __in       LPCTSTR lpFileName,
#   __in_opt   LPCTSTR lpExtension,
#   __in       DWORD nBufferLength,
#   __out      LPTSTR lpBuffer,
#   __out_opt  LPTSTR *lpFilePart
# );
def SearchPathA(lpPath, lpFileName, lpExtension):
    _SearchPathA = windll.kernel32.SearchPathA
    _SearchPathA.argtypes = [LPSTR, LPSTR, LPSTR, DWORD, LPSTR, ctypes.POINTER(LPSTR)]
    _SearchPathA.restype = DWORD
    _SearchPathA.errcheck = RaiseIfZero

    if not lpPath:
        lpPath = None
    if not lpExtension:
        lpExtension = None
    nBufferLength = _SearchPathA(lpPath, lpFileName, lpExtension, 0, None, None)
    lpBuffer = ctypes.create_string_buffer('', nBufferLength + 1)
    lpFilePart = LPSTR()
    nCount = _SearchPathA(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, ctypes.byref(lpFilePart))
    lpFilePart = lpFilePart.value
    lpBuffer = lpBuffer.value
    if lpBuffer == '':
        if GetLastError() == 0:
            SetLastError(ERROR_FILE_NOT_FOUND)
        raise ctypes.WinError()
    return (lpBuffer, lpFilePart)

def SearchPathW(lpPath, lpFileName, lpExtension):
    _SearchPathW = windll.kernel32.SearchPathW
    _SearchPathW.argtypes = [LPWSTR, LPWSTR, LPWSTR, DWORD, LPWSTR, POINTER(LPWSTR)]
    _SearchPathW.restype = DWORD
    _SearchPathW.errcheck = RaiseIfZero

    if not lpPath:
        lpPath = None
    if not lpExtension:
        lpExtension = None
    nBufferLength = _SearchPathW(lpPath, lpFileName, lpExtension, 0, None, None)
    lpBuffer = ctypes.create_unicode_buffer(u'', nBufferLength + 1)
    lpFilePart = LPWSTR()
    nCount = _SearchPathW(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, ctypes.byref(lpFilePart))
    lpFilePart = lpFilePart.value
    lpBuffer = lpBuffer.value
    if lpBuffer == u'':
        if GetLastError() == 0:
            SetLastError(ERROR_FILE_NOT_FOUND)
        raise ctypes.WinError()
    return (lpBuffer, lpFilePart)

SearchPath = GuessStringType(SearchPathA, SearchPathW)

# BOOL SetSearchPathMode(
#   __in  DWORD Flags
# );
def SetSearchPathMode(Flags):
    _SetSearchPathMode = windll.kernel32.SetSearchPathMode
    _SetSearchPathMode.argtypes = [DWORD]
    _SetSearchPathMode.restype = bool
    _SetSearchPathMode.errcheck = RaiseIfZero
    _SetSearchPathMode(Flags)

# BOOL WINAPI DeviceIoControl(
#   __in         HANDLE hDevice,
#   __in         DWORD dwIoControlCode,
#   __in_opt     LPVOID lpInBuffer,
#   __in         DWORD nInBufferSize,
#   __out_opt    LPVOID lpOutBuffer,
#   __in         DWORD nOutBufferSize,
#   __out_opt    LPDWORD lpBytesReturned,
#   __inout_opt  LPOVERLAPPED lpOverlapped
# );
def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpOverlapped):
    _DeviceIoControl = windll.kernel32.DeviceIoControl
    _DeviceIoControl.argtypes = [HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED]
    _DeviceIoControl.restype = bool
    _DeviceIoControl.errcheck = RaiseIfZero

    if not lpInBuffer:
        lpInBuffer = None
    if not lpOutBuffer:
        lpOutBuffer = None
    if lpOverlapped:
        lpOverlapped = ctypes.pointer(lpOverlapped)
    lpBytesReturned = DWORD(0)
    _DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, ctypes.byref(lpBytesReturned), lpOverlapped)
    return lpBytesReturned.value

# BOOL GetFileInformationByHandle(
#   HANDLE hFile,
#   LPBY_HANDLE_FILE_INFORMATION lpFileInformation
# );
def GetFileInformationByHandle(hFile):
    _GetFileInformationByHandle = windll.kernel32.GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = [HANDLE, LPBY_HANDLE_FILE_INFORMATION]
    _GetFileInformationByHandle.restype = bool
    _GetFileInformationByHandle.errcheck = RaiseIfZero

    lpFileInformation = BY_HANDLE_FILE_INFORMATION()
    _GetFileInformationByHandle(hFile, ctypes.byref(lpFileInformation))
    return lpFileInformation

# BOOL WINAPI GetFileInformationByHandleEx(
#   __in   HANDLE hFile,
#   __in   FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
#   __out  LPVOID lpFileInformation,
#   __in   DWORD dwBufferSize
# );
def GetFileInformationByHandleEx(hFile, FileInformationClass, lpFileInformation, dwBufferSize):
    _GetFileInformationByHandleEx = windll.kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [HANDLE, DWORD, LPVOID, DWORD]
    _GetFileInformationByHandleEx.restype = bool
    _GetFileInformationByHandleEx.errcheck = RaiseIfZero
    # XXX TODO
    # support each FileInformationClass so the function can allocate the
    # corresponding structure for the lpFileInformation parameter
    _GetFileInformationByHandleEx(hFile, FileInformationClass, ctypes.byref(lpFileInformation), dwBufferSize)

# DWORD WINAPI GetFinalPathNameByHandle(
#   __in   HANDLE hFile,
#   __out  LPTSTR lpszFilePath,
#   __in   DWORD cchFilePath,
#   __in   DWORD dwFlags
# );
def GetFinalPathNameByHandleA(hFile, dwFlags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS):
    _GetFinalPathNameByHandleA = windll.kernel32.GetFinalPathNameByHandleA
    _GetFinalPathNameByHandleA.argtypes = [HANDLE, LPSTR, DWORD, DWORD]
    _GetFinalPathNameByHandleA.restype = DWORD

    cchFilePath = _GetFinalPathNameByHandleA(hFile, None, 0, dwFlags)
    if cchFilePath == 0:
        raise ctypes.WinError()
    lpszFilePath = ctypes.create_string_buffer('', cchFilePath + 1)
    nCopied = _GetFinalPathNameByHandleA(hFile, lpszFilePath, cchFilePath, dwFlags)
    if nCopied <= 0 or nCopied > cchFilePath:
        raise ctypes.WinError()
    return lpszFilePath.value

def GetFinalPathNameByHandleW(hFile, dwFlags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS):
    _GetFinalPathNameByHandleW = windll.kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [HANDLE, LPWSTR, DWORD, DWORD]
    _GetFinalPathNameByHandleW.restype = DWORD

    cchFilePath = _GetFinalPathNameByHandleW(hFile, None, 0, dwFlags)
    if cchFilePath == 0:
        raise ctypes.WinError()
    lpszFilePath = ctypes.create_unicode_buffer(u'', cchFilePath + 1)
    nCopied = _GetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags)
    if nCopied <= 0 or nCopied > cchFilePath:
        raise ctypes.WinError()
    return lpszFilePath.value

GetFinalPathNameByHandle = GuessStringType(GetFinalPathNameByHandleA, GetFinalPathNameByHandleW)

# DWORD GetFullPathName(
#   LPCTSTR lpFileName,
#   DWORD nBufferLength,
#   LPTSTR lpBuffer,
#   LPTSTR* lpFilePart
# );
def GetFullPathNameA(lpFileName):
    _GetFullPathNameA = windll.kernel32.GetFullPathNameA
    _GetFullPathNameA.argtypes = [LPSTR, DWORD, LPSTR, ctypes.POINTER(LPSTR)]
    _GetFullPathNameA.restype = DWORD

    nBufferLength = _GetFullPathNameA(lpFileName, 0, None, None)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer   = ctypes.create_string_buffer('', nBufferLength + 1)
    lpFilePart = LPSTR
    nCopied = _GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, ctypes.byref(lpFilePart))
    if nCopied > nBufferLength or nCopied == 0:
        raise ctypes.WinError()
    return lpBuffer.value, lpFilePart.value

def GetFullPathNameW(lpFileName):
    _GetFullPathNameW = windll.kernel32.GetFullPathNameW
    _GetFullPathNameW.argtypes = [LPWSTR, DWORD, LPWSTR, POINTER(LPWSTR)]
    _GetFullPathNameW.restype = DWORD

    nBufferLength = _GetFullPathNameW(lpFileName, 0, None, None)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer   = ctypes.create_unicode_buffer(u'', nBufferLength + 1)
    lpFilePart = LPSTR
    nCopied = _GetFullPathNameW(lpFileName, nBufferLength, lpBuffer, ctypes.byref(lpFilePart))
    if nCopied > nBufferLength or nCopied == 0:
        raise ctypes.WinError()
    return lpBuffer.value, lpFilePart.value

GetFullPathName = GuessStringType(GetFullPathNameA, GetFullPathNameW)

# DWORD WINAPI GetTempPath(
#   __in   DWORD nBufferLength,
#   __out  LPTSTR lpBuffer
# );
def GetTempPathA():
    _GetTempPathA = windll.kernel32.GetTempPathA
    _GetTempPathA.argtypes = [DWORD, LPSTR]
    _GetTempPathA.restype = DWORD

    nBufferLength = _GetTempPathA(0, None)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_string_buffer('', nBufferLength)
    nCopied = _GetTempPathA(nBufferLength, lpBuffer)
    if nCopied > nBufferLength or nCopied == 0:
        raise ctypes.WinError()
    return lpBuffer.value

def GetTempPathW():
    _GetTempPathW = windll.kernel32.GetTempPathW
    _GetTempPathW.argtypes = [DWORD, LPSTR]
    _GetTempPathW.restype = DWORD

    nBufferLength = _GetTempPathW(0, None)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_unicode_buffer(u'', nBufferLength)
    nCopied = _GetTempPathW(nBufferLength, lpBuffer)
    if nCopied > nBufferLength or nCopied == 0:
        raise ctypes.WinError()
    return lpBuffer.value

GetTempPath = GuessStringType(GetTempPathA, GetTempPathW)

# UINT WINAPI GetTempFileName(
#   __in   LPCTSTR lpPathName,
#   __in   LPCTSTR lpPrefixString,
#   __in   UINT uUnique,
#   __out  LPTSTR lpTempFileName
# );
def GetTempFileNameA(lpPathName = None, lpPrefixString = "TMP", uUnique = 0):
    _GetTempFileNameA = windll.kernel32.GetTempFileNameA
    _GetTempFileNameA.argtypes = [LPSTR, LPSTR, UINT, LPSTR]
    _GetTempFileNameA.restype = UINT

    if lpPathName is None:
        lpPathName = GetTempPathA()
    lpTempFileName = ctypes.create_string_buffer('', MAX_PATH)
    uUnique = _GetTempFileNameA(lpPathName, lpPrefixString, uUnique, lpTempFileName)
    if uUnique == 0:
        raise ctypes.WinError()
    return lpTempFileName.value, uUnique

def GetTempFileNameW(lpPathName = None, lpPrefixString = u"TMP", uUnique = 0):
    _GetTempFileNameW = windll.kernel32.GetTempFileNameW
    _GetTempFileNameW.argtypes = [LPSTR, LPSTR, UINT, LPSTR]
    _GetTempFileNameW.restype = UINT

    if lpPathName is None:
        lpPathName = GetTempPathW()
    lpTempFileName = ctypes.create_unicode_buffer(u'', MAX_PATH)
    uUnique = _GetTempFileNameW(lpPathName, lpPrefixString, uUnique, lpTempFileName)
    if uUnique == 0:
        raise ctypes.WinError()
    return lpTempFileName.value, uUnique

GetTempFileName = GuessStringType(GetTempFileNameA, GetTempFileNameW)

# HLOCAL WINAPI LocalFree(
#   __in  HLOCAL hMem
# );
def LocalFree(hMem):
    _LocalFree = windll.kernel32.LocalFree
    _LocalFree.argtypes = [HLOCAL]
    _LocalFree.restype = HLOCAL

    result = _LocalFree(hMem)
    if result != NULL:
        ctypes.WinError()

# BOOL WINAPI HandlerRoutine(
#   __in  DWORD dwCtrlType
# );
PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(BOOL, DWORD)

# BOOL WINAPI SetConsoleCtrlHandler(
#   __in_opt  PHANDLER_ROUTINE HandlerRoutine,
#   __in      BOOL Add
# );
def SetConsoleCtrlHandler(HandlerRoutine = None, Add = True):
    _SetConsoleCtrlHandler = windll.kernel32.SetConsoleCtrlHandler
    _SetConsoleCtrlHandler.argtypes = [PHANDLER_ROUTINE, BOOL]
    _SetConsoleCtrlHandler.restype = bool
    _SetConsoleCtrlHandler.errcheck = RaiseIfZero

    if callable(HandlerRoutine):
        HandlerRoutine = PHANDLER_ROUTINE(HandlerRoutine)
    elif not HandlerRoutine:
        HandlerRoutine = None
    else:
        raise ValueError, "Bad argument for HandlerRoutine: %r" % HandlerRoutine
    _SetConsoleCtrlHandler(HandlerRoutine, bool(Add))

# BOOL WINAPI GenerateConsoleCtrlEvent(
#   __in  DWORD dwCtrlEvent,
#   __in  DWORD dwProcessGroupId
# );
def GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId):
    _GenerateConsoleCtrlEvent = windll.kernel32.GenerateConsoleCtrlEvent
    _GenerateConsoleCtrlEvent.argtypes = [DWORD, DWORD]
    _GenerateConsoleCtrlEvent.restype = bool
    _GenerateConsoleCtrlEvent.errcheck = RaiseIfZero
    _GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId)

# DWORD WINAPI WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD dwMilliseconds
# );
def WaitForSingleObject(hHandle, dwMilliseconds = INFINITE):
    _WaitForSingleObject = windll.kernel32.WaitForSingleObject
    _WaitForSingleObject.argtypes = [HANDLE, DWORD]
    _WaitForSingleObject.restype = DWORD

    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    if dwMilliseconds != INFINITE:
        r = _WaitForSingleObject(hHandle, dwMilliseconds)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = _WaitForSingleObject(hHandle, 100)
            if r == WAIT_FAILED:
                raise ctypes.WinError()
            if r != WAIT_TIMEOUT:
                break
    return r

# DWORD WINAPI WaitForSingleObjectEx(
#   HANDLE hHandle,
#   DWORD dwMilliseconds,
#   BOOL bAlertable
# );
def WaitForSingleObjectEx(hHandle, dwMilliseconds = INFINITE, bAlertable = True):
    _WaitForSingleObjectEx = windll.kernel32.WaitForSingleObjectEx
    _WaitForSingleObjectEx.argtypes = [HANDLE, DWORD, BOOL]
    _WaitForSingleObjectEx.restype = DWORD

    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    if dwMilliseconds != INFINITE:
        r = _WaitForSingleObjectEx(hHandle, dwMilliseconds, bool(bAlertable))
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = _WaitForSingleObjectEx(hHandle, 100, bool(bAlertable))
            if r == WAIT_FAILED:
                raise ctypes.WinError()
            if r != WAIT_TIMEOUT:
                break
    return r

# DWORD WINAPI WaitForMultipleObjects(
#   DWORD nCount,
#   const HANDLE *lpHandles,
#   BOOL bWaitAll,
#   DWORD dwMilliseconds
# );
def WaitForMultipleObjects(handles, bWaitAll = False, dwMilliseconds = INFINITE):
    _WaitForMultipleObjects = windll.kernel32.WaitForMultipleObjects
    _WaitForMultipleObjects.argtypes = [DWORD, ctypes.POINTER(HANDLE), BOOL, DWORD]
    _WaitForMultipleObjects.restype = DWORD

    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    nCount          = len(handles)
    lpHandlesType   = HANDLE * nCount
    lpHandles       = lpHandlesType(*handles)
    if dwMilliseconds != INFINITE:
        r = _WaitForMultipleObjects(ctypes.byref(lpHandles), bool(bWaitAll), dwMilliseconds)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = _WaitForMultipleObjects(ctypes.byref(lpHandles), bool(bWaitAll), 100)
            if r == WAIT_FAILED:
                raise ctypes.WinError()
            if r != WAIT_TIMEOUT:
                break
    return r

# DWORD WINAPI WaitForMultipleObjectsEx(
#   DWORD nCount,
#   const HANDLE *lpHandles,
#   BOOL bWaitAll,
#   DWORD dwMilliseconds,
#   BOOL bAlertable
# );
def WaitForMultipleObjectsEx(handles, bWaitAll = False, dwMilliseconds = INFINITE):
    _WaitForMultipleObjectsEx = windll.kernel32.WaitForMultipleObjectsEx
    _WaitForMultipleObjectsEx.argtypes = [DWORD, ctypes.POINTER(HANDLE), BOOL, DWORD]
    _WaitForMultipleObjectsEx.restype = DWORD

    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    nCount          = len(handles)
    lpHandlesType   = HANDLES * nCount
    lpHandles       = lpHandlesType(*handles)
    if dwMilliseconds != INFINITE:
        r = _WaitForMultipleObjectsEx(ctypes.byref(lpHandles), bool(bWaitAll), dwMilliseconds, bool(bAlertable))
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = _WaitForMultipleObjectsEx(ctypes.byref(lpHandles), bool(bWaitAll), 100, bool(bAlertable))
            if r == WAIT_FAILED:
                raise ctypes.WinError()
            if r != WAIT_TIMEOUT:
                break
    return r

# BOOL WaitForDebugEvent(
#   LPDEBUG_EVENT lpDebugEvent,
#   DWORD dwMilliseconds
# );
def WaitForDebugEvent(dwMilliseconds = INFINITE):
    _WaitForDebugEvent = windll.kernel32.WaitForDebugEvent
    _WaitForDebugEvent.argtypes = [LPDEBUG_EVENT, DWORD]
    _WaitForDebugEvent.restype = DWORD

    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    lpDebugEvent                  = DEBUG_EVENT()
    lpDebugEvent.dwDebugEventCode = 0
    lpDebugEvent.dwProcessId      = 0
    lpDebugEvent.dwThreadId       = 0
    if dwMilliseconds != INFINITE:
        success = _WaitForDebugEvent(ctypes.byref(lpDebugEvent), dwMilliseconds)
        if success == 0:
            raise ctypes.WinError()
    else:
        while 1:
            success = _WaitForDebugEvent(ctypes.byref(lpDebugEvent), 100)
            if success != 0:
                break
            code = GetLastError()
            if code not in (ERROR_SEM_TIMEOUT, WAIT_TIMEOUT):
                raise ctypes.WinError(code)
    return lpDebugEvent

# BOOL ContinueDebugEvent(
#   DWORD dwProcessId,
#   DWORD dwThreadId,
#   DWORD dwContinueStatus
# );
def ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED):
    _ContinueDebugEvent = windll.kernel32.ContinueDebugEvent
    _ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
    _ContinueDebugEvent.restype = bool
    _ContinueDebugEvent.errcheck = RaiseIfZero
    _ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)

# BOOL WINAPI FlushInstructionCache(
#   __in  HANDLE hProcess,
#   __in  LPCVOID lpBaseAddress,
#   __in  SIZE_T dwSize
# );
def FlushInstructionCache(hProcess, lpBaseAddress = None, dwSize = 0):
    # http://blogs.msdn.com/oldnewthing/archive/2003/12/08/55954.aspx#55958
    _FlushInstructionCache = windll.kernel32.FlushInstructionCache
    _FlushInstructionCache.argtypes = [HANDLE, LPVOID, SIZE_T]
    _FlushInstructionCache.restype = bool
    _FlushInstructionCache.errcheck = RaiseIfZero
    _FlushInstructionCache(hProcess, lpBaseAddress, dwSize)

# BOOL DebugActiveProcess(
#   DWORD dwProcessId
# );
def DebugActiveProcess(dwProcessId):
    _DebugActiveProcess = windll.kernel32.DebugActiveProcess
    _DebugActiveProcess.argtypes = [DWORD]
    _DebugActiveProcess.restype = bool
    _DebugActiveProcess.errcheck = RaiseIfZero
    _DebugActiveProcess(dwProcessId)

# BOOL DebugActiveProcessStop(
#   DWORD dwProcessId
# );
def DebugActiveProcessStop(dwProcessId):
    _DebugActiveProcessStop = windll.kernel32.DebugActiveProcessStop
    _DebugActiveProcessStop.argtypes = [DWORD]
    _DebugActiveProcessStop.restype = bool
    _DebugActiveProcessStop.errcheck = RaiseIfZero
    _DebugActiveProcessStop(dwProcessId)

# BOOL WINAPI CreateProcess(
#   __in_opt     LPCTSTR lpApplicationName,
#   __inout_opt  LPTSTR lpCommandLine,
#   __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
#   __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   __in         BOOL bInheritHandles,
#   __in         DWORD dwCreationFlags,
#   __in_opt     LPVOID lpEnvironment,
#   __in_opt     LPCTSTR lpCurrentDirectory,
#   __in         LPSTARTUPINFO lpStartupInfo,
#   __out        LPPROCESS_INFORMATION lpProcessInformation
# );
def CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None):
    _CreateProcessA = windll.kernel32.CreateProcessA
    _CreateProcessA.argtypes = [LPSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION]
    _CreateProcessA.restype = bool
    _CreateProcessA.errcheck = RaiseIfZero

    if not lpApplicationName:
        lpApplicationName   = None
    if not lpCommandLine:
        lpCommandLine       = None
    else:
        lpCommandLine       = ctypes.create_string_buffer(lpCommandLine, MAX_PATH)
    if not lpEnvironment:
        lpEnvironment       = None
    else:
        lpEnvironment       = ctypes.create_string_buffer(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = None
    if not lpProcessAttributes:
        lpProcessAttributes = None
    else:
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    if not lpStartupInfo:
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    lpProcessInformation              = PROCESS_INFORMATION()
    lpProcessInformation.hProcess     = INVALID_HANDLE_VALUE
    lpProcessInformation.hThread      = INVALID_HANDLE_VALUE
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0
    _CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bool(bInheritHandles), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

def CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None):
    _CreateProcessW = windll.kernel32.CreateProcessW
    _CreateProcessW.argtypes = [LPWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION]
    _CreateProcessW.restype = bool
    _CreateProcessW.errcheck = RaiseIfZero

    if not lpApplicationName:
        lpApplicationName   = None
    if not lpCommandLine:
        lpCommandLine       = None
    else:
        lpCommandLine       = ctypes.create_unicode_buffer(lpCommandLine, MAX_PATH)
    if not lpEnvironment:
        lpEnvironment       = None
    else:
        lpEnvironment       = ctypes.create_unicode_buffer(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = None
    if not lpProcessAttributes:
        lpProcessAttributes = None
    else:
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    if not lpStartupInfo:
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    lpProcessInformation              = PROCESS_INFORMATION()
    lpProcessInformation.hProcess     = INVALID_HANDLE_VALUE
    lpProcessInformation.hThread      = INVALID_HANDLE_VALUE
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0
    _CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bool(bInheritHandles), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

CreateProcess = GuessStringType(CreateProcessA, CreateProcessW)

# BOOL WINAPI CreateProcessAsUser(
#   __in_opt     HANDLE hToken,
#   __in_opt     LPCTSTR lpApplicationName,
#   __inout_opt  LPTSTR lpCommandLine,
#   __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
#   __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   __in         BOOL bInheritHandles,
#   __in         DWORD dwCreationFlags,
#   __in_opt     LPVOID lpEnvironment,
#   __in_opt     LPCTSTR lpCurrentDirectory,
#   __in         LPSTARTUPINFO lpStartupInfo,
#   __out        LPPROCESS_INFORMATION lpProcessInformation
# );
def CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None):
    _CreateProcessAsUserA = windll.kernel32.CreateProcessAsUserA
    _CreateProcessAsUserA.argtypes = [HANDLE, LPSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION]
    _CreateProcessAsUserA.restype = bool
    _CreateProcessAsUserA.errcheck = RaiseIfZero

    if not lpApplicationName:
        lpApplicationName   = None
    if not lpCommandLine:
        lpCommandLine       = None
    else:
        lpCommandLine       = ctypes.create_string_buffer(lpCommandLine, MAX_PATH)
    if not lpEnvironment:
        lpEnvironment       = None
    else:
        lpEnvironment       = ctypes.create_string_buffer(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = None
    if not lpProcessAttributes:
        lpProcessAttributes = None
    else:
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    if not lpStartupInfo:
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    lpProcessInformation              = PROCESS_INFORMATION()
    lpProcessInformation.hProcess     = INVALID_HANDLE_VALUE
    lpProcessInformation.hThread      = INVALID_HANDLE_VALUE
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0
    _CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bool(bInheritHandles), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

def CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None):
    _CreateProcessAsUserW = windll.kernel32.CreateProcessAsUserW
    _CreateProcessAsUserW.argtypes = [HANDLE, LPWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION]
    _CreateProcessAsUserW.restype = bool
    _CreateProcessAsUserW.errcheck = RaiseIfZero

    if not lpApplicationName:
        lpApplicationName   = None
    if not lpCommandLine:
        lpCommandLine       = None
    else:
        lpCommandLine       = ctypes.create_unicode_buffer(lpCommandLine, MAX_PATH)
    if not lpEnvironment:
        lpEnvironment       = None
    else:
        lpEnvironment       = ctypes.create_unicode_buffer(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = None
    if not lpProcessAttributes:
        lpProcessAttributes = None
    else:
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    if not lpStartupInfo:
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    lpProcessInformation              = PROCESS_INFORMATION()
    lpProcessInformation.hProcess     = INVALID_HANDLE_VALUE
    lpProcessInformation.hThread      = INVALID_HANDLE_VALUE
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0
    _CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bool(bInheritHandles), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

CreateProcessAsUser = GuessStringType(CreateProcessAsUserA, CreateProcessAsUserW)

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
    _OpenProcess = windll.kernel32.OpenProcess
    _OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    _OpenProcess.restype = HANDLE

    hProcess = _OpenProcess(dwDesiredAccess, bool(bInheritHandle), dwProcessId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return ProcessHandle(hProcess)

# HANDLE WINAPI OpenThread(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwThreadId
# );
def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    _OpenThread = windll.kernel32.OpenThread
    _OpenThread.argtypes = [DWORD, BOOL, DWORD]
    _OpenThread.restype = HANDLE

    hProcess = _OpenThread(dwDesiredAccess, bool(bInheritHandle), dwThreadId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return ThreadHandle(hProcess)

# DWORD WINAPI SuspendThread(
#   __in  HANDLE hThread
# );
def SuspendThread(hThread):
    _SuspendThread = windll.kernel32.SuspendThread
    _SuspendThread.argtypes = [HANDLE]
    _SuspendThread.restype = DWORD

    previousCount = _SuspendThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount

# DWORD WINAPI ResumeThread(
#   __in  HANDLE hThread
# );
def ResumeThread(hThread):
    _ResumeThread = windll.kernel32.ResumeThread
    _ResumeThread.argtypes = [HANDLE]
    _ResumeThread.restype = DWORD

    previousCount = _ResumeThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount

# BOOL WINAPI TerminateThread(
#   __inout  HANDLE hThread,
#   __in     DWORD dwExitCode
# );
def TerminateThread(hThread, dwExitCode = 0):
    _TerminateThread = windll.kernel32.TerminateThread
    _TerminateThread.argtypes = [HANDLE, DWORD]
    _TerminateThread.restype = bool
    _TerminateThread.errcheck = RaiseIfZero
    _TerminateThread(hThread, dwExitCode)

# BOOL WINAPI TerminateProcess(
#   __inout  HANDLE hProcess,
#   __in     DWORD dwExitCode
# );
def TerminateProcess(hProcess, dwExitCode = 0):
    _TerminateProcess = windll.kernel32.TerminateProcess
    _TerminateProcess.argtypes = [HANDLE, DWORD]
    _TerminateProcess.restype = bool
    _TerminateProcess.errcheck = RaiseIfZero
    _TerminateProcess(hProcess, dwExitCode)

# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );
def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
    _ReadProcessMemory = windll.kernel32.ReadProcessMemory
    _ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    _ReadProcessMemory.restype = bool

    lpBuffer            = ctypes.create_string_buffer('', nSize)
    lpNumberOfBytesRead = SIZE_T(0)
    success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return str(lpBuffer.raw)[:lpNumberOfBytesRead.value]

# BOOL WINAPI WriteProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __in   LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesWritten
# );
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer):
    _WriteProcessMemory = windll.kernel32.WriteProcessMemory
    _WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
    _WriteProcessMemory.restype = bool

    nSize                   = len(lpBuffer)
    lpBuffer                = ctypes.create_string_buffer(lpBuffer)
    lpNumberOfBytesWritten  = SIZE_T(0)
    success = _WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesWritten))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return lpNumberOfBytesWritten.value

# LPVOID WINAPI VirtualAllocEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPVOID lpAddress,
#   __in      SIZE_T dwSize,
#   __in      DWORD flAllocationType,
#   __in      DWORD flProtect
# );
def VirtualAllocEx(hProcess, lpAddress = 0, dwSize = 0x1000, flAllocationType = MEM_COMMIT | MEM_RESERVE, flProtect = PAGE_EXECUTE_READWRITE):
    _VirtualAllocEx = windll.kernel32.VirtualAllocEx
    _VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
    _VirtualAllocEx.restype = LPVOID

    lpAddress = _VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if lpAddress == NULL:
        raise ctypes.WinError()
    return lpAddress

# SIZE_T WINAPI VirtualQueryEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPCVOID lpAddress,
#   __out     PMEMORY_BASIC_INFORMATION lpBuffer,
#   __in      SIZE_T dwLength
# );
def VirtualQueryEx(hProcess, lpAddress):
    _VirtualQueryEx = windll.kernel32.VirtualQueryEx
    _VirtualQueryEx.argtypes = [HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
    _VirtualQueryEx.restype = SIZE_T

    lpBuffer  = MEMORY_BASIC_INFORMATION()
    dwLength  = sizeof(MEMORY_BASIC_INFORMATION)
    success   = _VirtualQueryEx(hProcess, lpAddress, ctypes.byref(lpBuffer), dwLength)
    if success == 0:
        raise ctypes.WinError()
    return MemoryBasicInformation(lpBuffer)

# BOOL WINAPI VirtualProtectEx(
#   __in   HANDLE hProcess,
#   __in   LPVOID lpAddress,
#   __in   SIZE_T dwSize,
#   __in   DWORD flNewProtect,
#   __out  PDWORD lpflOldProtect
# );
def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect = PAGE_EXECUTE_READWRITE):
    _VirtualProtectEx = windll.kernel32.VirtualProtectEx
    _VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, PDWORD]
    _VirtualProtectEx.restype = bool
    _VirtualProtectEx.errcheck = RaiseIfZero

    flOldProtect = DWORD(0)
    _VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, ctypes.byref(flOldProtect))
    return flOldProtect.value

# BOOL WINAPI VirtualFreeEx(
#   __in  HANDLE hProcess,
#   __in  LPVOID lpAddress,
#   __in  SIZE_T dwSize,
#   __in  DWORD dwFreeType
# );
def VirtualFreeEx(hProcess, lpAddress, dwSize = 0, dwFreeType = MEM_RELEASE):
    _VirtualFreeEx = windll.kernel32.VirtualFreeEx
    _VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]
    _VirtualFreeEx.restype = bool
    _VirtualFreeEx.errcheck = RaiseIfZero
    _VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)

# BOOL WINAPI GetThreadSelectorEntry(
#   __in   HANDLE hThread,
#   __in   DWORD dwSelector,
#   __out  LPLDT_ENTRY lpSelectorEntry
# );
def GetThreadSelectorEntry(hThread, dwSelector):
    _GetThreadSelectorEntry = windll.kernel32.GetThreadSelectorEntry
    _GetThreadSelectorEntry.argtypes = [HANDLE, DWORD, LPLDT_ENTRY]
    _GetThreadSelectorEntry.restype = bool
    _GetThreadSelectorEntry.errcheck = RaiseIfZero

    ldt = LDT_ENTRY()
    _GetThreadSelectorEntry(hThread, dwSelector, ctypes.byref(ldt))
    return ldt

# HANDLE WINAPI CreateRemoteThread(
#   __in   HANDLE hProcess,
#   __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   __in   SIZE_T dwStackSize,
#   __in   LPTHREAD_START_ROUTINE lpStartAddress,
#   __in   LPVOID lpParameter,
#   __in   DWORD dwCreationFlags,
#   __out  LPDWORD lpThreadId
# );
def CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags):
    _CreateRemoteThread = windll.kernel32.CreateRemoteThread
    _CreateRemoteThread.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
    _CreateRemoteThread.restype = HANDLE

    if not lpThreadAttributes:
        lpThreadAttributes = None
    else:
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    dwThreadId = DWORD(0)
    hThread = _CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, ctypes.byref(dwThreadId))
    if hThread == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return ThreadHandle(hThread), dwThreadId.value

# HANDLE WINAPI GetCurrentProcess(void);
def GetCurrentProcess():
    _GetCurrentProcess = windll.kernel32.GetCurrentProcess
    _GetCurrentProcess.argtypes = []
    _GetCurrentProcess.restype = HANDLE
    return _GetCurrentProcess()

# HANDLE WINAPI GetCurrentThread(void);
def GetCurrentThread():
    GetCurrentThread = windll.kernel32.GetCurrentThread
    _GetCurrentThread.argtypes = []
    _GetCurrentThread.restype = HANDLE
    return _GetCurrentThread()

# DWORD WINAPI GetProcessId(
#   __in  HANDLE hProcess
# );
def GetProcessId(hProcess):
    _GetProcessId = windll.kernel32.GetProcessId
    _GetProcessId.argtypes = [HANDLE]
    _GetProcessId.restype = DWORD
    _GetProcessId.errcheck = RaiseIfZero
    return _GetProcessId(hProcess)

# DWORD WINAPI GetThreadId(
#   __in  HANDLE hThread
# );
def GetThreadId(hThread):
    _GetThreadId = windll.kernel32._GetThreadId
    _GetThreadId.argtypes = [HANDLE]
    _GetThreadId.restype = DWORD

    dwThreadId = _GetThreadId(hThread)
    if dwThreadId == 0:
        raise ctypes.WinError()
    return dwThreadId

# DWORD WINAPI GetProcessIdOfThread(
#   __in  HANDLE hThread
# );
def GetProcessIdOfThread(hThread):
    _GetProcessIdOfThread = windll.kernel32.GetProcessIdOfThread
    _GetProcessIdOfThread.argtypes = [HANDLE]
    _GetProcessIdOfThread.restype = DWORD

    dwProcessId = _GetProcessIdOfThread(hThread)
    if dwProcessId == 0:
        raise ctypes.WinError()
    return dwProcessId

# BOOL WINAPI GetExitCodeProcess(
#   __in   HANDLE hProcess,
#   __out  LPDWORD lpExitCode
# );
def GetExitCodeProcess(hProcess):
    _GetExitCodeProcess = windll.kernel32.GetExitCodeProcess
    _GetExitCodeProcess.argtypes = [HANDLE]
    _GetExitCodeProcess.restype = bool
    _GetExitCodeProcess.errcheck = RaiseIfZero

    lpExitCode = DWORD(0)
    _GetExitCodeProcess(hProcess, ctypes.byref(lpExitCode))
    return lpExitCode.value

# BOOL WINAPI GetExitCodeThread(
#   __in   HANDLE hThread,
#   __out  LPDWORD lpExitCode
# );
def GetExitCodeThread(hThread):
    _GetExitCodeThread = windll.kernel32.GetExitCodeThread
    _GetExitCodeThread.argtypes = [HANDLE]
    _GetExitCodeThread.restype = bool
    _GetExitCodeThread.errcheck = RaiseIfZero

    lpExitCode = DWORD(0)
    _GetExitCodeThread(hThread, ctypes.byref(lpExitCode))
    return lpExitCode.value

# DWORD WINAPI GetProcessVersion(
#   __in  DWORD ProcessId
# );
def GetProcessVersion(ProcessId):
    _GetProcessVersion = windll.kernel32.GetProcessVersion
    _GetProcessVersion.argtypes = [DWORD]
    _GetProcessVersion.restype = DWORD

    retval = _GetProcessVersion(ProcessId)
    if retval == 0:
        raise ctypes.WinError()
    return retval

# DWORD WINAPI GetPriorityClass(
#   __in  HANDLE hProcess
# );
def GetPriorityClass(hProcess):
    _GetPriorityClass = windll.kernel32.GetPriorityClass
    _GetPriorityClass.argtypes = [HANDLE]
    _GetPriorityClass.restype = DWORD

    retval = _GetPriorityClass(hProcess)
    if retval == 0:
        raise ctypes.WinError()
    return retval

# BOOL WINAPI SetPriorityClass(
#   __in  HANDLE hProcess,
#   __in  DWORD dwPriorityClass
# );
def SetPriorityClass(hProcess, dwPriorityClass = NORMAL_PRIORITY_CLASS):
    _SetPriorityClass = windll.kernel32.SetPriorityClass
    _SetPriorityClass.argtypes = [HANDLE, DWORD]
    _SetPriorityClass.restype = bool
    _SetPriorityClass.errcheck = RaiseIfZero
    _SetPriorityClass(hProcess, dwPriorityClass)

# BOOL WINAPI GetProcessPriorityBoost(
#   __in   HANDLE hProcess,
#   __out  PBOOL pDisablePriorityBoost
# );
def GetProcessPriorityBoost(hProcess):
    _GetProcessPriorityBoost = windll.kernel32.GetProcessPriorityBoost
    _GetProcessPriorityBoost.argtypes = [HANDLE, PBOOL]
    _GetProcessPriorityBoost.restype = bool
    _GetProcessPriorityBoost.errcheck = RaiseIfZero

    pDisablePriorityBoost = BOOL(False)
    _GetProcessPriorityBoost(hProcess, ctypes.byref(pDisablePriorityBoost))
    return bool(pDisablePriorityBoost.value)

# BOOL WINAPI SetProcessPriorityBoost(
#   __in  HANDLE hProcess,
#   __in  BOOL DisablePriorityBoost
# );
def SetProcessPriorityBoost(hProcess, DisablePriorityBoost):
    _SetProcessPriorityBoost = windll.kernel32.SetProcessPriorityBoost
    _SetProcessPriorityBoost.argtypes = [HANDLE, BOOL]
    _SetProcessPriorityBoost.restype = bool
    _SetProcessPriorityBoost.errcheck = RaiseIfZero
    _SetProcessPriorityBoost(hProcess, bool(DisablePriorityBoost))

# BOOL WINAPI GetProcessAffinityMask(
#   __in   HANDLE hProcess,
#   __out  PDWORD_PTR lpProcessAffinityMask,
#   __out  PDWORD_PTR lpSystemAffinityMask
# );
def GetProcessAffinityMask(hProcess):
    _GetProcessAffinityMask = windll.kernel32.GetProcessAffinityMask
    _GetProcessAffinityMask.argtypes = [HANDLE, PDWORD_PTR, PDWORD_PTR]
    _GetProcessAffinityMask.restype = bool
    _GetProcessAffinityMask.errcheck = RaiseIfZero

    lpProcessAffinityMask = DWORD_PTR(NULL)
    lpSystemAffinityMask  = DWORD_PTR(NULL)
    _GetProcessAffinityMask(hProcess, ctypes.byref(lpProcessAffinityMask), ctypes.byref(lpSystemAffinityMask))
    return lpProcessAffinityMask.value, lpSystemAffinityMask.value

# BOOL WINAPI SetProcessAffinityMask(
#   __in  HANDLE hProcess,
#   __in  DWORD_PTR dwProcessAffinityMask
# );
def SetProcessAffinityMask(hProcess, dwProcessAffinityMask):
    _SetProcessAffinityMask = windll.kernel32.SetProcessAffinityMask
    _SetProcessAffinityMask.argtypes = [HANDLE, DWORD_PTR]
    _SetProcessAffinityMask.restype = bool
    _SetProcessAffinityMask.errcheck = RaiseIfZero
    _SetProcessAffinityMask(hProcess, dwProcessAffinityMask)

# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL pbDebuggerPresent
# );
def CheckRemoteDebuggerPresent(hProcess):
    _CheckRemoteDebuggerPresent = windll.kernel32.CheckRemoteDebuggerPresent
    _CheckRemoteDebuggerPresent.argtypes = [HANDLE, PBOOL]
    _CheckRemoteDebuggerPresent.restype = bool
    _CheckRemoteDebuggerPresent.errcheck = RaiseIfZero

    pbDebuggerPresent = BOOL(0)
    _CheckRemoteDebuggerPresent(hProcess, ctypes.byref(pbDebuggerPresent))
    return bool(pbDebuggerPresent.value)

# BOOL DebugSetProcessKillOnExit(
#   BOOL KillOnExit
# );
def DebugSetProcessKillOnExit(KillOnExit):
    _DebugSetProcessKillOnExit = windll.kernel32.DebugSetProcessKillOnExit
    _DebugSetProcessKillOnExit.argtypes = [BOOL]
    _DebugSetProcessKillOnExit.restype = bool
    _DebugSetProcessKillOnExit.errcheck = RaiseIfZero
    _DebugSetProcessKillOnExit(bool(KillOnExit))

# BOOL DebugBreakProcess(
#   HANDLE Process
# );
def DebugBreakProcess(hProcess):
    _DebugBreakProcess = windll.kernel32.DebugBreakProcess
    _DebugBreakProcess.argtypes = [HANDLE]
    _DebugBreakProcess.restype = bool
    _DebugBreakProcess.errcheck = RaiseIfZero
    _DebugBreakProcess(hProcess)

# BOOL WINAPI GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  LPCONTEXT lpContext
# );
def GetThreadContext(hThread, ContextFlags = CONTEXT_ALL):
    _GetThreadContext = windll.kernel32.GetThreadContext
    _GetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    _GetThreadContext.restype = bool
    _GetThreadContext.errcheck = RaiseIfZero

    lpContext = CONTEXT()
    lpContext.ContextFlags = ContextFlags
    _GetThreadContext(hThread, ctypes.byref(lpContext))
    return lpContext.to_dict()

# BOOL WINAPI SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const CONTEXT* lpContext
# );
def SetThreadContext(hThread, lpContext):
    _SetThreadContext = windll.kernel32.SetThreadContext
    _SetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    _SetThreadContext.restype = bool
    _SetThreadContext.errcheck = RaiseIfZero

    if isinstance(lpContext, dict):
        lpContext = CONTEXT.from_dict(lpContext)
    _SetThreadContext(hThread, ctypes.byref(lpContext))

# HANDLE WINAPI CreateToolhelp32Snapshot(
#   __in  DWORD dwFlags,
#   __in  DWORD th32ProcessID
# );
def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    _CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    _CreateToolhelp32Snapshot.restype = HANDLE

    hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hSnapshot)

# BOOL WINAPI Process32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPPROCESSENTRY32 lppe
# );
def Process32First(hSnapshot):
    _Process32First = windll.kernel32.Process32First
    _Process32First.argtypes = [HANDLE, LPPROCESSENTRY32]
    _Process32First.restype = bool

    pe        = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = _Process32First(hSnapshot, ctypes.byref(pe))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

# BOOL WINAPI Process32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPPROCESSENTRY32 lppe
# );
def Process32Next(hSnapshot, pe = None):
    _Process32Next = windll.kernel32.Process32Next
    _Process32Next.argtypes = [HANDLE, LPPROCESSENTRY32]
    _Process32Next.restype = bool

    if pe is None:
        pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = _Process32Next(hSnapshot, ctypes.byref(pe))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

# BOOL WINAPI Thread32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPTHREADENTRY32 lpte
# );
def Thread32First(hSnapshot):
    _Thread32First = windll.kernel32.Thread32First
    _Thread32First.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32First.restype = bool

    te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32First(hSnapshot, ctypes.byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Thread32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPTHREADENTRY32 lpte
# );
def Thread32Next(hSnapshot, te = None):
    _Thread32Next = windll.kernel32.Thread32Next
    _Thread32Next.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32Next.restype = bool

    if te is None:
        te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32Next(hSnapshot, ctypes.byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Module32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPMODULEENTRY32 lpme
# );
def Module32First(hSnapshot):
    _Module32First = windll.kernel32.Module32First
    _Module32First.argtypes = [HANDLE, LPMODULEENTRY32]
    _Module32First.restype = bool

    me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = _Module32First(hSnapshot, ctypes.byref(me))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return me

# BOOL WINAPI Module32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPMODULEENTRY32 lpme
# );
def Module32Next(hSnapshot, me = None):
    _Module32Next = windll.kernel32.Module32Next
    _Module32Next.argtypes = [HANDLE, LPMODULEENTRY32]
    _Module32Next.restype = bool

    if me is None:
        me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = _Module32Next(hSnapshot, ctypes.byref(me))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return me

# BOOL WINAPI Heap32First(
#   __inout  LPHEAPENTRY32 lphe,
#   __in     DWORD th32ProcessID,
#   __in     ULONG_PTR th32HeapID
# );
def Heap32First(th32ProcessID, th32HeapID):
    _Heap32First = windll.kernel32.Heap32First
    _Heap32First.argtypes = [LPHEAPENTRY32, DWORD, LPVOID]
    _Heap32First.restype = bool

    he = HEAPENTRY32()
    he.dwSize = sizeof(HEAPENTRY32)
    success = _Heap32First(ctypes.byref(he), th32ProcessID, th32HeapID)
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return he

# BOOL WINAPI Heap32Next(
#   __out  LPHEAPENTRY32 lphe
# );
def Heap32Next(he):
    _Heap32Next = windll.kernel32.Heap32Next
    _Heap32Next.argtypes = [LPHEAPENTRY32]
    _Heap32Next.restype = bool

    he.dwSize = sizeof(HEAPENTRY32)
    success = _Heap32Next(ctypes.byref(he))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return he

# BOOL WINAPI Heap32ListFirst(
#   __in     HANDLE hSnapshot,
#   __inout  LPHEAPLIST32 lphl
# );
def Heap32ListFirst(hSnapshot):
    _Heap32ListFirst = windll.kernel32.Heap32ListFirst
    _Heap32ListFirst.argtypes = [HANDLE, LPHEAPLIST32]
    _Heap32ListFirst.restype = bool

    hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = _Heap32ListFirst(hSnapshot, ctypes.byref(hl))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return hl

# BOOL WINAPI Heap32ListNext(
#   __in     HANDLE hSnapshot,
#   __out  LPHEAPLIST32 lphl
# );
def Heap32ListNext(hSnapshot, hl = None):
    _Heap32ListNext = windll.kernel32.Heap32ListNext
    _Heap32ListNext.argtypes = [HANDLE, LPHEAPLIST32]
    _Heap32ListNext.restype = bool

    if hl is None:
        hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = _Heap32ListNext(hSnapshot, ctypes.byref(hl))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return hl

# BOOL WINAPI Toolhelp32ReadProcessMemory(
#   __in   DWORD th32ProcessID,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T cbRead,
#   __out  SIZE_T lpNumberOfBytesRead
# );
def Toolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, cbRead):
    _Toolhelp32ReadProcessMemory = windll.kernel32.Toolhelp32ReadProcessMemory
    _Toolhelp32ReadProcessMemory.argtypes = [DWORD, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    _Toolhelp32ReadProcessMemory.restype = bool

    lpBuffer            = ctypes.create_string_buffer('', cbRead)
    lpNumberOfBytesRead = SIZE_T(0)
    success = _Toolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, lpBuffer, cbRead, ctypes.byref(lpNumberOfBytesRead))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return str(lpBuffer.raw)[:lpNumberOfBytesRead.value]

# DWORD WINAPI GetCurrentProcessorNumber(void);
def GetCurrentProcessorNumber():
    _GetCurrentProcessorNumber = windll.kernel32.GetCurrentProcessorNumber
    _GetCurrentProcessorNumber.argtypes = []
    _GetCurrentProcessorNumber.restype = DWORD
    _GetCurrentProcessorNumber.errcheck = RaiseIfZero
    return _GetCurrentProcessorNumber()

# VOID WINAPI FlushProcessWriteBuffers(void);
def FlushProcessWriteBuffers():
    _FlushProcessWriteBuffers = windll.kernel32.FlushProcessWriteBuffers
    _FlushProcessWriteBuffers.argtypes = []
    _FlushProcessWriteBuffers.restype = None
    _FlushProcessWriteBuffers()

# BOOL WINAPI GetLogicalProcessorInformation(
#   __out    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer,
#   __inout  PDWORD ReturnLength
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms683194(VS.85).aspx

# BOOL WINAPI GetProcessIoCounters(
#   __in   HANDLE hProcess,
#   __out  PIO_COUNTERS lpIoCounters
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms683218(VS.85).aspx

# DWORD WINAPI GetGuiResources(
#   __in  HANDLE hProcess,
#   __in  DWORD uiFlags
# );
def GetGuiResources(hProcess, uiFlags = GR_GDIOBJECTS):
    _GetGuiResources = windll.kernel32.GetGuiResources
    _GetGuiResources.argtypes = [HANDLE, DWORD]
    _GetGuiResources.restype = DWORD

    dwCount = _GetGuiResources(hProcess, uiFlags)
    if dwCount == 0:
        errcode = GetLastError()
        if errcode != ERROR_SUCCESS:
            raise ctypes.WinError(errcode)
    return dwCount

# BOOL WINAPI GetProcessHandleCount(
#   __in     HANDLE hProcess,
#   __inout  PDWORD pdwHandleCount
# );
def GetProcessHandleCount(hProcess):
    _GetProcessHandleCount = windll.kernel32.GetProcessHandleCount
    _GetProcessHandleCount.argtypes = [HANDLE, PDWORD]
    _GetProcessHandleCount.restype = DWORD
    _GetProcessHandleCount.errcheck = RaiseIfZero

    pdwHandleCount = DWORD(0)
    _GetProcessHandleCount(hProcess, ctypes.byref(pdwHandleCount))
    return pdwHandleCount.value

# BOOL WINAPI GetProcessTimes(
#   __in   HANDLE hProcess,
#   __out  LPFILETIME lpCreationTime,
#   __out  LPFILETIME lpExitTime,
#   __out  LPFILETIME lpKernelTime,
#   __out  LPFILETIME lpUserTime
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms683223(VS.85).aspx

# DWORD WINAPI GetVersion(void);
def GetVersion():
    _GetVersion = windll.kernel32.GetVersion
    _GetVersion.argtypes = []
    _GetVersion.restype = DWORD
    _GetVersion.errcheck = RaiseIfZero

    # See the example code here:
    # http://msdn.microsoft.com/en-us/library/ms724439(VS.85).aspx

    dwVersion       = _GetVersion()
    dwMajorVersion  = dwVersion & 0x000000FF
    dwMinorVersion  = (dwVersion & 0x0000FF00) >> 8
    if (dwVersion & 0x80000000) == 0:
        dwBuild     = (dwVersion & 0x7FFF0000) >> 16
    else:
        dwBuild     = None
    return int(dwMajorVersion), int(dwMinorVersion), int(dwBuild)

# BOOL WINAPI GetVersionEx(
#   __inout  LPOSVERSIONINFO lpVersionInfo
# );
def GetVersionExA():
    _GetVersionExA = windll.kernel32.GetVersionExA
    _GetVersionExA.argtypes = [LPVOID]
    _GetVersionExA.restype = bool
    _GetVersionExA.errcheck = RaiseIfZero

    osi = OSVERSIONINFOEXA()
    osi.dwOSVersionInfoSize = sizeof(osi)
    try:
        _GetVersionExA(ctypes.byref(osi))
    except WindowsError:
        osi = OSVERSIONINFOA()
        osi.dwOSVersionInfoSize = sizeof(osi)
        _GetVersionExA(ctypes.byref(osi))
    return osi

def GetVersionExW():
    _GetVersionExW = windll.kernel32.GetVersionExW
    _GetVersionExW.argtypes = [LPVOID]
    _GetVersionExW.restype = bool
    _GetVersionExW.errcheck = RaiseIfZero

    osi = OSVERSIONINFOEXW()
    osi.dwOSVersionInfoSize = sizeof(osi)
    try:
        _GetVersionExW(ctypes.byref(osi))
    except WindowsError:
        osi = OSVERSIONINFOW()
        osi.dwOSVersionInfoSize = sizeof(osi)
        _GetVersionExW(ctypes.byref(osi))
    return osi

GetVersionEx = GuessStringType(GetVersionExA, GetVersionExW)

# BOOL WINAPI VerifyVersionInfo(
#   __in  LPOSVERSIONINFOEX lpVersionInfo,
#   __in  DWORD dwTypeMask,
#   __in  DWORDLONG dwlConditionMask
# );
def VerifyVersionInfo(lpVersionInfo, dwTypeMask, dwlConditionMask):
    if isinstance(lpVersionInfo, OSVERSIONINFOEXA):
        return VerifyVersionInfoA(lpVersionInfo, dwTypeMask, dwlConditionMask)
    if isinstance(lpVersionInfo, OSVERSIONINFOEXW):
        return VerifyVersionInfoW(lpVersionInfo, dwTypeMask, dwlConditionMask)
    raise TypeError, "Bad OSVERSIONINFOEX structure"

def VerifyVersionInfoA(lpVersionInfo, dwTypeMask, dwlConditionMask):
    _VerifyVersionInfoA = windll.kernel32.VerifyVersionInfoA
    _VerifyVersionInfoA.argtypes = [LPOSVERSIONINFOEXA, DWORD, DWORDLONG]
    _VerifyVersionInfoA.restype = bool
    return _VerifyVersionInfoA(ctypes.byref(lpVersionInfo), dwTypeMask, dwlConditionMask)

def VerifyVersionInfoW(lpVersionInfo, dwTypeMask, dwlConditionMask):
    _VerifyVersionInfoW = windll.kernel32.VerifyVersionInfoW
    _VerifyVersionInfoW.argtypes = [LPOSVERSIONINFOEXW, DWORD, DWORDLONG]
    _VerifyVersionInfoW.restype = bool
    return _VerifyVersionInfoW(ctypes.byref(lpVersionInfo), dwTypeMask, dwlConditionMask)

# ULONGLONG WINAPI VerSetConditionMask(
#   __in  ULONGLONG dwlConditionMask,
#   __in  DWORD dwTypeBitMask,
#   __in  BYTE dwConditionMask
# );
def VerSetConditionMask(dwlConditionMask, dwTypeBitMask, dwConditionMask):
    _VerSetConditionMask = windll.kernel32.VerSetConditionMask
    _VerSetConditionMask.argtypes = [ULONGLONG, DWORD, BYTE]
    _VerSetConditionMask.restype = ULONGLONG
    return _VerSetConditionMask(dwlConditionMask, dwTypeBitMask, dwConditionMask)

# int WINAPI GetSystemMetrics(
#   __in  int nIndex
# );
def GetSystemMetrics(nIndex):
    _GetSystemMetrics = windll.kernel32.GetSystemMetrics
    _GetSystemMetrics.argtypes = [ctypes.c_int]
    _GetSystemMetrics.restype = [ctypes.c_int]
    return _GetSystemMetrics(nIndex)

#------------------------------------------------------------------------------
# Wow64

# BOOL WINAPI IsWow64Process(
#   __in   HANDLE hProcess,
#   __out  PBOOL Wow64Process
# );
def IsWow64Process(hProcess):
    _IsWow64Process = windll.kernel32.IsWow64Process
    _IsWow64Process.argtypes = [HANDLE, PBOOL]
    _IsWow64Process.restype = BOOL
    _IsWow64Process.errcheck = RaiseIfZero

    Wow64Process = BOOL(FALSE)
    _IsWow64Process(hProcess, ctypes.byref(Wow64Process))
    return bool(Wow64Process)

# BOOL Wow64GetThreadSelectorEntry(
#   __in   HANDLE hThread,
#   __in   DWORD dwSelector,
#   __out  PWOW64_LDT_ENTRY lpSelectorEntry
# );
def Wow64GetThreadSelectorEntry(hThread, dwSelector):
    _Wow64GetThreadSelectorEntry = windll.kernel32.Wow64GetThreadSelectorEntry
    _Wow64GetThreadSelectorEntry.argtypes = [HANDLE, DWORD, PWOW64_LDT_ENTRY]
    _Wow64GetThreadSelectorEntry.restype = bool
    _Wow64GetThreadSelectorEntry.errcheck = RaiseIfZero

    lpSelectorEntry = WOW64_LDT_ENTRY()
    _Wow64GetThreadSelectorEntry(hThread, dwSelector, ctypes.byref(lpSelectorEntry))
    return lpSelectorEntry

# DWORD WINAPI Wow64ResumeThread(
#   __in  HANDLE hThread
# );
def Wow64ResumeThread(hThread):
    _Wow64ResumeThread = windll.kernel32.Wow64ResumeThread
    _Wow64ResumeThread.argtypes = [HANDLE]
    _Wow64ResumeThread.restype = DWORD

    previousCount = _Wow64ResumeThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount

# DWORD WINAPI Wow64SuspendThread(
#   __in  HANDLE hThread
# );
def Wow64SuspendThread(hThread):
    _Wow64SuspendThread = windll.kernel32.Wow64SuspendThread
    _Wow64SuspendThread.argtypes = [HANDLE]
    _Wow64SuspendThread.restype = DWORD

    previousCount = _Wow64SuspendThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount

# XXX TODO Use this http://www.nynaeve.net/Code/GetThreadWow64Context.cpp
# Also see http://www.woodmann.com/forum/archive/index.php/t-11162.html

# BOOL WINAPI Wow64GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  PWOW64_CONTEXT lpContext
# );
def Wow64GetThreadContext(hThread, ContextFlags = WOW64_CONTEXT_ALL):
    _Wow64GetThreadContext = windll.kernel32.Wow64GetThreadContext
    _Wow64GetThreadContext.argtypes = [HANDLE, PWOW64_CONTEXT]
    _Wow64GetThreadContext.restype = bool
    _Wow64GetThreadContext.errcheck = RaiseIfZero

    lpContext = CONTEXT()
    lpContext.ContextFlags = ContextFlags
    _Wow64GetThreadContext(hThread, ctypes.byref(lpContext))
    return lpContext.to_dict()

# BOOL WINAPI Wow64SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const WOW64_CONTEXT *lpContext
# );
def Wow64SetThreadContext(hThread, lpContext):
    _Wow64SetThreadContext = windll.kernel32.Wow64SetThreadContext
    _Wow64SetThreadContext.argtypes = [HANDLE, PWOW64_CONTEXT]
    _Wow64SetThreadContext.restype = bool
    _Wow64SetThreadContext.errcheck = RaiseIfZero

    if isinstance(lpContext, dict):
        lpContext = WOW64_CONTEXT.from_dict(lpContext)
    _Wow64SetThreadContext(hThread, ctypes.byref(lpContext))

#==============================================================================
# Mark functions that Psyco cannot compile.
# In your programs, don't use psyco.full().
# Call psyco.bind() on your main function instead.

try:
    import psyco
    psyco.cannotcompile(WaitForDebugEvent)
    psyco.cannotcompile(WaitForSingleObject)
    psyco.cannotcompile(WaitForSingleObjectEx)
    psyco.cannotcompile(WaitForMultipleObjects)
    psyco.cannotcompile(WaitForMultipleObjectsEx)
except ImportError:
    pass
