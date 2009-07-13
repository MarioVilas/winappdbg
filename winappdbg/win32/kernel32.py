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

# The following values specify the type of access in the first parameter
# of the exception record whan the exception code specifies an access
# violation.
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch

# Access violation types
ACCESS_VIOLATION_TYPE_READ      = EXCEPTION_READ_FAULT
ACCESS_VIOLATION_TYPE_WRITE     = EXCEPTION_WRITE_FAULT
ACCESS_VIOLATION_TYPE_DEP       = EXCEPTION_EXECUTE_FAULT

# DuplicateHandle constants
DUPLICATE_CLOSE_SOURCE      = 0x00000001
DUPLICATE_SAME_ACCESS       = 0x00000002

#--- Handle wrappers ----------------------------------------------------------

class Handle (object):
    """
    Encapsulates Win32 handles to avoid leaking them.

    @see: L{ProcessHandle}, L{ThreadHandle}, L{FileHandle}
    """

    def __init__(self, aHandle = None, bOwnership = True):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle object.

        @type  bOwnership: bool
        @param bOwnership:
           C{True} if we own the handle and we need to close it.
           C{False} if someone else will be calling L{CloseHandle}.
        """
        super(Handle, self).__init__()
        if aHandle is not None and type(aHandle) not in (type(0), type(0L)):
            raise TypeError, "Invalid type for handle value: %s" % type(aHandle)
        if aHandle == INVALID_HANDLE_VALUE:
            aHandle = None
        self.value      = aHandle
        self.bOwnership = bool(bOwnership)

    def __del__(self):
        """
        Closes the Win32 handle when the Python object is destroyed.
        """
        try:
            self.close()
        except WindowsError:
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

    @classmethod
    def from_param(cls, value):
        """
        Compatibility with ctypes.
        Allows receiving transparently a Handle object from an API call.
        """
        return cls(value)

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Handle object to an API call.
        """
        return long(self.value)

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
        hHandle = DuplicateHandle(self.value)
        return self.__class__(hHandle, bOwnership = True)

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
        @return: Name of the open file, or C{None} on error.
        """

        # XXX TO DO update wrapper to avoid using ctypes objects
        dwBufferSize      = 0x1004
        lpFileInformation = ctypes.create_string_buffer(dwBufferSize)
        try:
            GetFileInformationByHandleEx(self.value,
                                         FILE_INFO_BY_HANDLE_CLASS.FileNameInfo,
                                         lpFileInformation, dwBufferSize)
        except AttributeError:
            return None
        FileNameLength = struct.unpack('<L', lpFileInformation.raw[:4])[0] + 1
        FileName = str(lpFileInformation.raw[4:FileNameLength+4])
        FileName = FileName.replace('\x00', '')
        if FileName:
            return FileName
        return None

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
        self.BaseAddress        = mbi.BaseAddress.value
        self.AllocationBase     = mbi.AllocationBase.value
        self.AllocationProtect  = mbi.AllocationProtect
        self.RegionSize         = mbi.RegionSize
        self.State              = mbi.State
        self.Protect            = mbi.Protect
        self.Type               = mbi.Type

        if not self.BaseAddress:
            self.BaseAddress    = 0
        if not self.AllocationBase:
            self.AllocationBase = 0

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

#--- SYSTEM_INFO structure ----------------------------------------------------

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

#--- MEMORY_BASIC_INFORMATION structure ---------------------------------------

# typedef struct _MEMORY_BASIC_INFORMATION {
#     PVOID BaseAddress;
#     PVOID AllocationBase;
#     DWORD AllocationProtect;
#     SIZE_T RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
class MEMORY_BASIC_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseAddress',         LPVOID),    # remote pointer
        ('AllocationBase',      LPVOID),    # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          DWORD),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]

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
class FILE_INFO_BY_HANDLE_CLASS:
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
        ('lpReserved',      DWORD),     # LPSTR
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
        ('lpReserved2',     DWORD),     # LPBYTE
        ('hStdInput',       DWORD),
        ('hStdOutput',      DWORD),
        ('hStdError',       DWORD),
    ]

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

#--- DEBUG_EVENT structure ----------------------------------------------------

# XXX
# Important note!
# Don't use LPVOID or any of the pointer types for REMOTE pointers,
# because we don't want ctypes to tinker with them, since they are
# not valid addresses within the current process address space.

# typedef struct _EXCEPTION_RECORD {
#   DWORD ExceptionCode;
#   DWORD ExceptionFlags;
#   struct _EXCEPTION_RECORD* ExceptionRecord;
#   PVOID ExceptionAddress;
#   DWORD NumberParameters;
#   DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD;
class EXCEPTION_RECORD(Structure):
    _pack_ = 1
EXCEPTION_RECORD._fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         POINTER(EXCEPTION_RECORD)),
        ('ExceptionAddress',        LPVOID),
        ('NumberParameters',        DWORD),
        ('ExceptionInformation',    DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)

# typedef struct _EXCEPTION_DEBUG_INFO {
#   EXCEPTION_RECORD ExceptionRecord;
#   DWORD dwFirstChance;
# } EXCEPTION_DEBUG_INFO;
class EXCEPTION_DEBUG_INFO(Structure):
    _pack_ = 1
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
    _pack_ = 1
    _fields_ = [
        ('hThread',             DWORD),
        ('lpThreadLocalBase',   DWORD),
        ('lpStartAddress',      DWORD),
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
    _pack_ = 1
    _fields_ = [
        ('hFile',                   HANDLE),
        ('hProcess',                HANDLE),
        ('hThread',                 HANDLE),
        ('lpBaseOfImage',           DWORD),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpThreadLocalBase',       DWORD),
        ('lpStartAddress',          DWORD),
        ('lpImageName',             DWORD),
        ('fUnicode',                WORD),
    ]

# typedef struct _EXIT_THREAD_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_THREAD_DEBUG_INFO;
class EXIT_THREAD_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _EXIT_PROCESS_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_PROCESS_DEBUG_INFO;
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _pack_ = 1
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
    _pack_ = 1
    _fields_ = [
        ('hFile',                   HANDLE),
        ('lpBaseOfDll',             DWORD),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpImageName',             DWORD),
        ('fUnicode',                WORD),
    ]

# typedef struct _UNLOAD_DLL_DEBUG_INFO {
#   LPVOID lpBaseOfDll;
# } UNLOAD_DLL_DEBUG_INFO;
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('lpBaseOfDll',         DWORD),
    ]

# typedef struct _OUTPUT_DEBUG_STRING_INFO {
#   LPSTR lpDebugStringData;
#   WORD fUnicode;
#   WORD nDebugStringLength;
# } OUTPUT_DEBUG_STRING_INFO;
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('lpDebugStringData',   DWORD),    # don't use LPSTR
        ('fUnicode',            WORD),
        ('nDebugStringLength',  WORD),
    ]

# typedef struct _RIP_INFO {
#     DWORD dwError;
#     DWORD dwType;
# } RIP_INFO, *LPRIP_INFO;
class RIP_INFO(Structure):
    _pack_ = 1
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
    _pack_ = 1
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
    _pack_ = 1
    _fields_ = [
        ('dwDebugEventCode',    DWORD),
        ('dwProcessId',         DWORD),
        ('dwThreadId',          DWORD),
        ('u',                   _DEBUG_EVENT_UNION_),
    ]

#--- LDT_ENTRY structure (for x86 only) ---------------------------------------

# typedef struct _LDT_ENTRY {
#   WORD LimitLow;
#   WORD BaseLow;
#   union {
#     struct {
#       BYTE BaseMid;
#       BYTE Flags1;
#       BYTE Flags2;
#       BYTE BaseHi;
#     } Bytes;
#     struct {
#       DWORD BaseMid  :8;
#       DWORD Type  :5;
#       DWORD Dpl  :2;
#       DWORD Pres  :1;
#       DWORD LimitHi  :4;
#       DWORD Sys  :1;
#       DWORD Reserved_0  :1;
#       DWORD Default_Big  :1;
#       DWORD Granularity  :1;
#       DWORD BaseHi  :8;
#     } Bits;
#   } HighWord;
# } LDT_ENTRY,
#  *PLDT_ENTRY;

class _LDT_ENTRY_BYTES_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         BYTE),
        ('Flags1',          BYTE),
        ('Flags2',          BYTE),
        ('BaseHi',          BYTE),
    ]

class _LDT_ENTRY_BITS_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         DWORD,  8),
        ('Type',            DWORD,  5),
        ('Dpl',             DWORD,  2),
        ('Pres',            DWORD,  1),
        ('LimitHi',         DWORD,  4),
        ('Sys',             DWORD,  1),
        ('Reserved_0',      DWORD,  1),
        ('Default_Big',     DWORD,  1),
        ('Granularity',     DWORD,  1),
        ('BaseHi',          DWORD,  8),
    ]

class _LDT_ENTRY_HIGHWORD_(Union):
    _pack_ = 1
    _fields_ = [
        ('Bytes',           _LDT_ENTRY_BYTES_),
        ('Bits',            _LDT_ENTRY_BITS_),
    ]

class LDT_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('LimitLow',        WORD),
        ('BaseLow',         WORD),
        ('HighWord',        _LDT_ENTRY_HIGHWORD_),
    ]

class WOW64_LDT_ENTRY (LDT_ENTRY):
    pass

#--- CONTEXT structure and constants (for x86 only) ---------------------------

SIZE_OF_80387_REGISTERS     = 80

CONTEXT_i386                = 0x00010000    # this assumes that i386 and
CONTEXT_i486                = 0x00010000    # i486 have identical context records

CONTEXT_CONTROL             = (CONTEXT_i386 | 0x00000001L) # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER             = (CONTEXT_i386 | 0x00000002L) # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS            = (CONTEXT_i386 | 0x00000004L) # DS, ES, FS, GS
CONTEXT_FLOATING_POINT      = (CONTEXT_i386 | 0x00000008L) # 387 state
CONTEXT_DEBUG_REGISTERS     = (CONTEXT_i386 | 0x00000010L) # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS  = (CONTEXT_i386 | 0x00000020L) # cpu specific extensions

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                CONTEXT_EXTENDED_REGISTERS)

MAXIMUM_SUPPORTED_EXTENSION = 512

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

# typedef struct _FLOATING_SAVE_AREA {
#     DWORD   ControlWord;
#     DWORD   StatusWord;
#     DWORD   TagWord;
#     DWORD   ErrorOffset;
#     DWORD   ErrorSelector;
#     DWORD   DataOffset;
#     DWORD   DataSelector;
#     BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
#     DWORD   Cr0NpxState;
# } FLOATING_SAVE_AREA;
class FLOATING_SAVE_AREA(Structure):
    _pack_ = 1
    _fields_ = [
        ('ControlWord',     DWORD),
        ('StatusWord',      DWORD),
        ('TagWord',         DWORD),
        ('ErrorOffset',     DWORD),
        ('ErrorSelector',   DWORD),
        ('DataOffset',      DWORD),
        ('DataSelector',    DWORD),
        ('RegisterArea',    BYTE * SIZE_OF_80387_REGISTERS),
        ('Cr0NpxState',     DWORD),
    ]

    _integer_members = ('ControlWord', 'StatusWord', 'TagWord', 'ErrorOffset', 'ErrorSelector', 'DataOffset', 'DataSelector', 'Cr0NpxState')

    @classmethod
    def from_dict(cls, fsa):
        'Instance a new structure from a Python dictionary.'
        fsa = dict(fsa)
        s = cls()
        for key in cls._integer_members:
            setattr(s, key, fsa.get(key))
        ra = fsa.get('RegisterArea', None)
        if ra is not None:
            for index in xrange(0, SIZE_OF_80387_REGISTERS):
                s.RegisterArea[index] = ra[index]
        return s

    def to_dict(self):
        'Convert a structure into a Python dictionary.'
        fsa = dict()
        for key in self._integer_members:
            fsa[key] = getattr(self, key)
        ra = [ self.RegisterArea[index] for index in xrange(0, SIZE_OF_80387_REGISTERS) ]
        ra = tuple(ra)
        fsa['RegisterArea'] = ra
        return fsa

# typedef struct _CONTEXT {
#     DWORD ContextFlags;
#     DWORD   Dr0;
#     DWORD   Dr1;
#     DWORD   Dr2;
#     DWORD   Dr3;
#     DWORD   Dr6;
#     DWORD   Dr7;
#     FLOATING_SAVE_AREA FloatSave;
#     DWORD   SegGs;
#     DWORD   SegFs;
#     DWORD   SegEs;
#     DWORD   SegDs;
#     DWORD   Edi;
#     DWORD   Esi;
#     DWORD   Ebx;
#     DWORD   Edx;
#     DWORD   Ecx;
#     DWORD   Eax;
#     DWORD   Ebp;
#     DWORD   Eip;
#     DWORD   SegCs;
#     DWORD   EFlags;
#     DWORD   Esp;
#     DWORD   SegSs;
#     BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
# } CONTEXT;
class CONTEXT(Structure):
    _pack_ = 1

    # Context Frame
    #
    #  This frame has a several purposes: 1) it is used as an argument to
    #  NtContinue, 2) is is used to constuct a call frame for APC delivery,
    #  and 3) it is used in the user level thread creation routines.
    #
    #  The layout of the record conforms to a standard call frame.

    _fields_ = [

        # The flags values within this flag control the contents of
        # a CONTEXT record.
        #
        # If the context record is used as an input parameter, then
        # for each portion of the context record controlled by a flag
        # whose value is set, it is assumed that that portion of the
        # context record contains valid context. If the context record
        # is being used to modify a threads context, then only that
        # portion of the threads context will be modified.
        #
        # If the context record is used as an IN OUT parameter to capture
        # the context of a thread, then only those portions of the thread's
        # context corresponding to set flags will be returned.
        #
        # The context record is never used as an OUT only parameter.

        ('ContextFlags',        DWORD),

        # This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        # set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        # included in CONTEXT_FULL.

        ('Dr0',                 DWORD),
        ('Dr1',                 DWORD),
        ('Dr2',                 DWORD),
        ('Dr3',                 DWORD),
        ('Dr6',                 DWORD),
        ('Dr7',                 DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_FLOATING_POINT.

        ('FloatSave',           FLOATING_SAVE_AREA),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_SEGMENTS.

        ('SegGs',               DWORD),
        ('SegFs',               DWORD),
        ('SegEs',               DWORD),
        ('SegDs',               DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_INTEGER.

        ('Edi',                 DWORD),
        ('Esi',                 DWORD),
        ('Ebx',                 DWORD),
        ('Edx',                 DWORD),
        ('Ecx',                 DWORD),
        ('Eax',                 DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_CONTROL.

        ('Ebp',                 DWORD),
        ('Eip',                 DWORD),
        ('SegCs',               DWORD),         # MUST BE SANITIZED
        ('EFlags',              DWORD),         # MUST BE SANITIZED
        ('Esp',                 DWORD),
        ('SegSs',               DWORD),

        # This section is specified/returned if the ContextFlags word
        # contains the flag CONTEXT_EXTENDED_REGISTERS.
        # The format and contexts are processor specific.

        ('ExtendedRegisters',   BYTE * MAXIMUM_SUPPORTED_EXTENSION),
    ]

    _ctx_debug   = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')
    _ctx_segs    = ('SegGs', 'SegFs', 'SegEs', 'SegDs', )
    _ctx_int     = ('Edi', 'Esi', 'Ebx', 'Edx', 'Ecx', 'Eax')
    _ctx_ctrl    = ('Ebp', 'Eip', 'SegCs', 'EFlags', 'Esp', 'SegSs')

    @classmethod
    def from_dict(cls, ctx):
        'Instance a new structure from a Python dictionary.'
        ctx = dict(ctx)
        s = cls()
        ContextFlags = ctx['ContextFlags']
        setattr(s, 'ContextFlags', ContextFlags)
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in s._ctx_debug:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT:
            fsa = ctx['FloatSave']
            s.FloatSave = FLOATING_SAVE_AREA.from_dict(fsa)
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in s._ctx_segs:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in s._ctx_int:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in s._ctx_ctrl:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS:
            er = ctx['ExtendedRegisters']
            for index in xrange(0, MAXIMUM_SUPPORTED_EXTENSION):
                s.ExtendedRegisters[index] = er[index]
        return s

    def to_dict(self):
        'Convert a structure into a Python dictionary.'
        ctx = dict()
        ContextFlags = self.ContextFlags
        ctx['ContextFlags'] = ContextFlags
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in self._ctx_debug:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT:
            ctx['FloatSave'] = self.FloatSave.to_dict()
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in self._ctx_segs:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in self._ctx_int:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in self._ctx_ctrl:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS:
            er = [ self.ExtendedRegisters[index] for index in xrange(0, MAXIMUM_SUPPORTED_EXTENSION) ]
            er = tuple(er)
            ctx['ExtendedRegisters'] = er
        return ctx

PCONTEXT = POINTER(CONTEXT)

class WOW64_FLOATING_SAVE_AREA (FLOATING_SAVE_AREA):
    pass

class WOW64_CONTEXT (CONTEXT):
    pass

PWOW64_CONTEXT = POINTER(WOW64_CONTEXT)

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
        ("modBaseAddr",   LPVOID),
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]

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

#--- kernel32.dll -------------------------------------------------------------

# DWORD WINAPI GetLastError(void);
def GetLastError():
    return ctypes.windll.kernel32.GetLastError()

# void WINAPI SetLastError(
#   __in  DWORD dwErrCode
# );
def SetLastError(dwErrCode):
    ctypes.windll.kernel32.SetLastError(dwErrCode)

# void WINAPI SetLastErrorEx(
#   __in  DWORD dwErrCode,
#   __in  DWORD dwType
# );
def SetLastErrorEx(dwErrCode, dwType):
    ctypes.windll.kernel32.SetLastErrorEx(dwErrCode, dwType)

# BOOL WINAPI CloseHandle(
#   __in  HANDLE hObject
# );
def CloseHandle(hHandle):
    if type(hHandle) not in (type(0), type(0L)):
        if hasattr(hHandle, 'close'):
            hHandle.close()
            return
        raise TypeError, "Invalid handle type: %s" % type(hHandle)
    success = ctypes.windll.kernel32.CloseHandle(hHandle)
    if success == FALSE:
        raise ctypes.WinError()

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
    if hSourceProcessHandle is None:
        hSourceProcessHandle = GetCurrentProcess()
    if hTargetProcessHandle is None:
        hTargetProcessHandle = hSourceProcessHandle
    if bInheritHandle:
        bInheritHandle = TRUE
    else:
        bInheritHandle = FALSE
    if type(hSourceProcessHandle) not in (type(0), type(0L)):
        if hasattr(hSourceProcessHandle, 'value'):
            hSourceProcessHandle = hSourceProcessHandle.value
        else:
            raise TypeError, "Invalid handle type: %s" % type(hSourceProcessHandle)
    if type(hTargetProcessHandle) not in (type(0), type(0L)):
        if hasattr(hTargetProcessHandle, 'value'):
            hTargetProcessHandle = hTargetProcessHandle.value
        else:
            raise TypeError, "Invalid handle type: %s" % type(hTargetProcessHandle)
    lpTargetHandle = HANDLE(-1)
    success = ctypes.windll.kernel32.DuplicateHandle(hSourceHandle, hSourceProcessHandle, hTargetProcessHandle, byref(lpTargetHandle), dwDesiredAccess, bInheritHandle, dwOptions)
    if success == FALSE:
        raise ctypes.WinError()
    return Handle(lpTargetHandle.value)

# void WINAPI OutputDebugString(
#   __in_opt  LPCTSTR lpOutputString
# );
def OutputDebugStringA(lpOutputString):
    if lpOutputString:
        lpOutputString = LPSTR(lpOutputString)
    else:
        lpOutputString = NULL
    ctypes.windll.kernel32.OutputDebugStringA(lpOutputString)
def OutputDebugStringW(lpOutputString):
    if lpOutputString:
        lpOutputString = LPWSTR(lpOutputString)
    else:
        lpOutputString = NULL
    ctypes.windll.kernel32.OutputDebugStringW(lpOutputString)
OutputDebugString = GuessStringType(OutputDebugStringA, OutputDebugStringW)

# BOOL WINAPI SetDllDirectory(
#   __in_opt  LPCTSTR lpPathName
# );
def SetDllDirectory(lpPathName):
    if lpPathName is None:
        lpPathName = NULL
    if lpPathName != NULL:
        lpPathName = ctypes.c_char_p(lpPathName)
    success = ctypes.windll.kernel32.SetDllDirectory(lpPathName)
    if success == FALSE:
        raise ctypes.WinError()

# HMODULE WINAPI LoadLibrary(
#   __in  LPCTSTR lpFileName
# );
def LoadLibrary(pszLibrary):
    return ctypes.windll.kernel32.LoadLibrary(pszLibrary)

# HMODULE WINAPI LoadLibraryEx(
#   __in        LPCTSTR lpFileName,
#   __reserved  HANDLE hFile,
#   __in        DWORD dwFlags
# );
def LoadLibraryEx(pszLibrary, dwFlags):
    return ctypes.windll.kernel32.LoadLibraryEx(pszLibrary, NULL, dwFlags)

# HMODULE WINAPI GetModuleHandle(
#   __in_opt  LPCTSTR lpModuleName
# );
def GetModuleHandleA(lpModuleName):
    lpModuleName = ctypes.c_char_p(lpModuleName)
    return ctypes.windll.kernel32.GetModuleHandleA(lpModuleName)
def GetModuleHandleW(lpModuleName):
    lpModuleName = ctypes.c_wchar_p(lpModuleName)
    return ctypes.windll.kernel32.GetModuleHandleW(lpModuleName)
GetModuleHandle = GuessStringType(GetModuleHandleA, GetModuleHandleW)

# FARPROC WINAPI GetProcAddress(
#   __in  HMODULE hModule,
#   __in  LPCSTR lpProcName
# );
def GetProcAddress(hModule, lpProcName):
    if type(lpProcName) in (type(0), type(0L)):
        if lpProcName & 0xFFFF0000:
            raise ValueError, 'Ordinal number too large: %d' % lpProcName
    else:
        if type(lpProcName) == type(u''):
            lpProcName = lpProcName.encode('ascii', 'ignore')
##        if type(lpProcName) != type(''):
##            raise ValueError, 'Expected string, got %s' % type(lpProcName)
        lpProcName = ctypes.c_char_p(lpProcName)
    return ctypes.windll.kernel32.GetProcAddress(hModule, lpProcName)

# BOOL WINAPI FreeLibrary(
#   __in  HMODULE hModule
# );
def FreeLibrary():
    return ctypes.windll.kernel32.FreeLibrary(hLibrary)

# BOOL WINAPI QueryFullProcessImageName(
#   __in     HANDLE hProcess,
#   __in     DWORD dwFlags,
#   __out    LPTSTR lpExeName,
#   __inout  PDWORD lpdwSize
# );
def QueryFullProcessImageNameA(hProcess, dwFlags = 0):
    lpdwSize = DWORD(0)
    ctypes.windll.kernel32.QueryFullProcessImageNameA(hProcess, dwFlags, NULL, ctypes.byref(lpdwSize))
    if lpdwSize.value == 0:
        raise ctypes.WinError()
    lpExeName = ctypes.create_string_buffer('', lpdwSize.value)
    retval = ctypes.windll.kernel32.QueryFullProcessImageNameA(hProcess, dwFlags, ctypes.byref(lpExeName), ctypes.byref(lpdwSize))
    if retval == 0:
        raise ctypes.WinError()
    return lpExeName.raw[:lpdwSize.value]
def QueryFullProcessImageNameW(hProcess, dwFlags = 0):
    lpdwSize = DWORD(0)
    ctypes.windll.kernel32.QueryFullProcessImageNameW(hProcess, dwFlags, NULL, ctypes.byref(lpdwSize))
    if lpdwSize.value == 0:
        raise ctypes.WinError()
    lpExeName = ctypes.create_unicode_buffer('', lpdwSize.value)
    retval = ctypes.windll.kernel32.QueryFullProcessImageNameW(hProcess, dwFlags, ctypes.byref(lpExeName), ctypes.byref(lpdwSize))
    if retval == 0:
        raise ctypes.WinError()
    return lpExeName.raw[:lpdwSize.value]
QueryFullProcessImageName = GuessStringType(QueryFullProcessImageNameA, QueryFullProcessImageNameW)

# DWORD WINAPI GetLogicalDriveStrings(
#   __in   DWORD nBufferLength,
#   __out  LPTSTR lpBuffer
# );
def GetLogicalDriveStringsA():
    nBufferLength = 0x1000
    lpBuffer = ctypes.create_string_buffer('', nBufferLength)
    size = ctypes.windll.kernel32.GetLogicalDriveStringsA(nBufferLength, ctypes.byref(lpBuffer))
    if size == 0:
        raise ctypes.WinError()
    return lpBuffer.value
def GetLogicalDriveStringsW():
    nBufferLength = 0x1000
    lpBuffer = ctypes.create_unicode_buffer('', nBufferLength)
    size = ctypes.windll.kernel32.GetLogicalDriveStringsW(nBufferLength, ctypes.byref(lpBuffer))
    if size == 0:
        raise ctypes.WinError()
    return lpBuffer.value
GetLogicalDriveStrings = GuessStringType(GetLogicalDriveStringsA, GetLogicalDriveStringsW)

# DWORD WINAPI QueryDosDevice(
#   __in_opt  LPCTSTR lpDeviceName,
#   __out     LPTSTR lpTargetPath,
#   __in      DWORD ucchMax
# );
def QueryDosDeviceA(lpDeviceName):
    lpDeviceName = ctypes.create_string_buffer(lpDeviceName)
    ucchMax = 0x1000
    lpTargetPath = ctypes.create_string_buffer('', ucchMax)
    size = ctypes.windll.kernel32.QueryDosDeviceA(ctypes.byref(lpDeviceName), ctypes.byref(lpTargetPath), ucchMax)
    if size == 0:
        raise ctypes.WinError()
    return lpTargetPath.value
def QueryDosDeviceW(lpDeviceName):
    lpDeviceName = ctypes.create_unicode_buffer(lpDeviceName)
    ucchMax = 0x1000
    lpTargetPath = ctypes.create_unicode_buffer(u'', ucchMax)
    size = ctypes.windll.kernel32.QueryDosDeviceW(ctypes.byref(lpDeviceName), ctypes.byref(lpTargetPath), ucchMax)
    if size == 0:
        raise ctypes.WinError()
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
    lpBaseAddress = ctypes.windll.kernel32.MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
    if lpBaseAddress == NULL:
        raise ctypes.WinError()
    return lpBaseAddress

# BOOL WINAPI UnmapViewOfFile(
#   __in  LPCVOID lpBaseAddress
# );
def UnmapViewOfFile(lpBaseAddress):
    success = ctypes.windll.kernel32.UnmapViewOfFile(lpBaseAddress)
    if success == 0:
        raise ctypes.WinError()

# HANDLE WINAPI OpenFileMapping(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  LPCTSTR lpName
# );
def OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName):
    hFileMappingObject = ctypes.windll.kernel32.OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)
def OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName):
    hFileMappingObject = ctypes.windll.kernel32.OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName)
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
def CreateFileMappingA(hFile, lpAttributes = NULL, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = NULL):
    hFileMappingObject = ctypes.windll.kernel32.CreateFileMappingA(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFileMappingObject)
def CreateFileMappingW(hFile, lpAttributes = NULL, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = NULL):
    hFileMappingObject = ctypes.windll.kernel32.CreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
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
def CreateFileA(lpFileName, dwDesiredAccess = GENERIC_ALL, dwShareMode = 0, lpSecurityAttributes = NULL, dwCreationDisposition = OPEN_ALWAYS, dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL, hTemplateFile = NULL):
    hFile = ctypes.windll.kernel32.CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFile)
def CreateFileW(lpFileName, dwDesiredAccess = GENERIC_ALL, dwShareMode = 0, lpSecurityAttributes = NULL, dwCreationDisposition = OPEN_ALWAYS, dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL, hTemplateFile = NULL):
    hFile = ctypes.windll.kernel32.CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hFile)
CreateFile = GuessStringType(CreateFileA, CreateFileW)

# BOOL WINAPI FlushFileBuffers(
#   __in  HANDLE hFile
# );
def FlushFileBuffers(hFile):
    success = ctypes.windll.kernel32.FlushFileBuffers(hFile)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI FlushViewOfFile(
#   __in  LPCVOID lpBaseAddress,
#   __in  SIZE_T dwNumberOfBytesToFlush
# );
def FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush = 0):
    success = ctypes.windll.kernel32.FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush)
    if success == FALSE:
        raise ctypes.WinError()

# DWORD WINAPI SearchPath(
#   __in_opt   LPCTSTR lpPath,
#   __in       LPCTSTR lpFileName,
#   __in_opt   LPCTSTR lpExtension,
#   __in       DWORD nBufferLength,
#   __out      LPTSTR lpBuffer,
#   __out_opt  LPTSTR *lpFilePart
# );
def SearchPathA(lpPath, lpFileName, lpExtension):
    if lpPath is None:
        lpPath = NULL
    if lpPath != NULL:
        lpPath = ctypes.c_char_p(lpPath)
    if lpExtension is None:
        lpExtension = NULL
    if lpExtension != NULL:
        lpExtension = ctypes.c_char_p(lpExtension)
    lpFileName = ctypes.c_char_p(lpFileName)
    nBufferLength = ctypes.windll.kernel32.SearchPathA(lpPath, lpFileName, lpExtension, 0, NULL, NULL)
    if nBufferLength == 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_string_buffer("\0", nBufferLength + 1)
    lpFilePart = ctypes.c_char_p()
    nCount = ctypes.windll.kernel32.SearchPathA(lpPath, lpFileName, lpExtension, nBufferLength, ctypes.byref(lpBuffer), ctypes.byref(lpFilePart))
    if nCount == 0:
        raise ctypes.WinError()
    lpFilePart = lpFilePart.value
    lpBuffer = lpBuffer.value
    if lpBuffer == '':
        if GetLastError() == 0:
            SetLastError(ERROR_FILE_NOT_FOUND)
        raise ctypes.WinError()
    return (lpBuffer, lpFilePart)
def SearchPathW(lpPath, lpFileName, lpExtension):
    if lpPath is None:
        lpPath = NULL
    if lpPath != NULL:
        lpPath = ctypes.c_wchar_p(lpPath)
    if lpExtension is None:
        lpExtension = NULL
    if lpExtension != NULL:
        lpExtension = ctypes.c_wchar_p(lpExtension)
    lpFileName = ctypes.c_wchar_p(lpFileName)
    nBufferLength = ctypes.windll.kernel32.SearchPathW(lpPath, lpFileName, lpExtension, 0, NULL, NULL)
    if nBufferLength == 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_unicode_buffer(u"\0", nBufferLength + 2)
    lpFilePart = ctypes.c_wchar_p()
    nCount = ctypes.windll.kernel32.SearchPathW(lpPath, lpFileName, lpExtension, nBufferLength, ctypes.byref(lpBuffer), ctypes.byref(lpFilePart))
    if nCount == 0:
        raise ctypes.WinError()
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
    success = ctypes.windll.kernel32.SetSearchPathMode(Flags)
    if success == FALSE:
        raise ctypes.WinError()

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
    if lpInBuffer != NULL:
        lpInBuffer = ctypes.byref(lpInBuffer)
    if lpOutBuffer != NULL:
        lpOutBuffer = ctypes.byref(lpOutBuffer)
    if lpOverlapped != NULL:
        lpOverlapped = ctypes.byref(lpOverlapped)
    lpBytesReturned = DWORD(0)
    success = ctypes.windll.kernel32.DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, ctypes.byref(lpBytesReturned), lpOverlapped)
    if success == FALSE:
        raise ctypes.WinError()
    return lpBytesReturned.value

# BOOL GetFileInformationByHandle(
#   HANDLE hFile,
#   LPBY_HANDLE_FILE_INFORMATION lpFileInformation
# );
def GetFileInformationByHandle(hFile):
    lpFileInformation = BY_HANDLE_FILE_INFORMATION()
    success = ctypes.windll.kernel32.GetFileInformationByHandle(hFile, ctypes.byref(lpFileInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return lpFileInformation

# BOOL WINAPI GetFileInformationByHandleEx(
#   __in   HANDLE hFile,
#   __in   FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
#   __out  LPVOID lpFileInformation,
#   __in   DWORD dwBufferSize
# );
def GetFileInformationByHandleEx(hFile, FileInformationClass, lpFileInformation, dwBufferSize):
    # TODO
    # support each FileInformationClass so the function can allocate the
    # corresponding structure for the lpFileInformation parameter
    success = ctypes.windll.kernel32.GetFileInformationByHandleEx(hFile, FileInformationClass, ctypes.byref(lpFileInformation), dwBufferSize)
    if success == 0:
        raise ctypes.WinError()
    return success

# DWORD GetFullPathName(
#   LPCTSTR lpFileName,
#   DWORD nBufferLength,
#   LPTSTR lpBuffer,
#   LPTSTR* lpFilePart
# );
def GetFullPathNameA(lpFileName, nBufferLength = MAX_PATH):
    lpFileName  = ctypes.create_string_buffer(lpFileName, nBufferLength)
    lpBuffer    = ctypes.create_string_buffer('', nBufferLength)
    lpFilePart  = ctypes.c_char_p()
    success = ctypes.windll.kernel32.GetFullPathNameA(ctypes.byref(lpFileName), nBufferLength, ctypes.byref(lpBuffer), ctypes.byref(lpFilePart))
    if success == FALSE:
        raise ctypes.WinError()
    return lpBuffer.value, lpFilePart.value
def GetFullPathNameW(lpFileName, nBufferLength = MAX_PATH):
    lpFileName  = ctypes.create_unicode_buffer(lpFileName, nBufferLength)
    lpBuffer    = ctypes.create_unicode_buffer(u'', nBufferLength)
    lpFilePart  = ctypes.c_wchar_p()
    success = ctypes.windll.kernel32.GetFullPathNameW(ctypes.byref(lpFileName), nBufferLength, ctypes.byref(lpBuffer), ctypes.byref(lpFilePart))
    if success == FALSE:
        raise ctypes.WinError()
    return lpBuffer.value, lpFilePart.value
GetFullPathName = GuessStringType(GetFullPathNameA, GetFullPathNameW)

# DWORD WINAPI GetTempPath(
#   __in   DWORD nBufferLength,
#   __out  LPTSTR lpBuffer
# );
def GetTempPathA():
    nBufferLength = ctypes.windll.kernel32.GetTempPathA(0, NULL)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_string_buffer("", nBufferLength)
    nCopied = ctypes.windll.kernel32.GetTempPathA(nBufferLength, lpBuffer)
    if nCopied > nBufferLength or nCopied == 0:
        raise ctypes.WinError()
    return lpBuffer.value
def GetTempPathW():
    nBufferLength = ctypes.windll.kernel32.GetTempPathW(0, NULL)
    if nBufferLength <= 0:
        raise ctypes.WinError()
    lpBuffer = ctypes.create_unicode_buffer(u"", nBufferLength)
    nCopied = ctypes.windll.kernel32.GetTempPathW(nBufferLength, lpBuffer)
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
    if lpPathName in (None, NULL):
        lpPathName = GetTempPathA()
    lpTempFileName = ctypes.create_string_buffer("", MAX_PATH)
    uUnique = ctypes.windll.kernel32.GetTempFileNameA(lpPathName, lpPrefixString, uUnique, ctypes.byref(lpTempFileName))
    if uUnique == 0:
        raise ctypes.WinError()
    return lpTempFileName.value, uUnique
def GetTempFileNameW(lpPathName = None, lpPrefixString = u"TMP", uUnique = 0):
    if lpPathName in (None, NULL):
        lpPathName = GetTempPathW()
    lpTempFileName = ctypes.create_unicode_buffer(u"", MAX_PATH)
    uUnique = ctypes.windll.kernel32.GetTempFileNameW(lpPathName, lpPrefixString, uUnique, ctypes.byref(lpTempFileName))
    if uUnique == 0:
        raise ctypes.WinError()
    return lpTempFileName.value, uUnique
GetTempFileName = GuessStringType(GetTempFileNameA, GetTempFileNameW)

# HLOCAL WINAPI LocalFree(
#   __in  HLOCAL hMem
# );
def LocalFree(hMem):
    result = ctypes.windll.kernel32.LocalFree(hMem)
    if result != NULL:
        ctypes.WinError()

# BOOL WINAPI HandlerRoutine(
#   __in  DWORD dwCtrlType
# );
try:
    # under Windows
    HANDLER_ROUTINE = WINFUNCTYPE(DWORD)
except Exception:
    # under Wine
    HANDLER_ROUTINE = LPVOID

# BOOL WINAPI SetConsoleCtrlHandler(
#   __in_opt  PHANDLER_ROUTINE HandlerRoutine,
#   __in      BOOL Add
# );
def SetConsoleCtrlHandler(HandlerRoutine = None, Add = True):
    if Add:
        Add = TRUE
    else:
        Add = FALSE
    if callable(HandlerRoutine):
        HandlerRoutine = HANDLER_ROUTINE(HandlerRoutine)
    elif not HandlerRoutine:
        HandlerRoutine = NULL
    else:
        raise ValueError, "Bad argument for HandlerRoutine: %r" % HandlerRoutine
    success = ctypes.windll.kernel32.SetConsoleCtrlHandler(HandlerRoutine, Add)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI GenerateConsoleCtrlEvent(
#   __in  DWORD dwCtrlEvent,
#   __in  DWORD dwProcessGroupId
# );
def GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId):
    success = ctypes.windll.kernel32.GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId)
    if success == FALSE:
        raise ctypes.WinError()

# DWORD WINAPI WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD dwMilliseconds
# );
def WaitForSingleObject(hHandle, dwMilliseconds = INFINITE):
    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    if dwMilliseconds != INFINITE:
        r = ctypes.windll.kernel32.WaitForSingleObject(hHandle, dwMilliseconds)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = ctypes.windll.kernel32.WaitForSingleObject(hHandle, 100)
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
    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    if bAlertable:
        bAlertable = TRUE
    else:
        bAlertable = FALSE
    if dwMilliseconds != INFINITE:
        r = ctypes.windll.kernel32.WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = ctypes.windll.kernel32.WaitForSingleObjectEx(hHandle, 100, bAlertable)
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
    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    nCount          = len(handles)
    lpHandlesType   = DWORD * nCount
    lpHandles       = lpHandlesType(*handles)
    if bWaitAll:
        bWaitAll    = TRUE
    else:
        bWaitAll    = FALSE
    if dwMilliseconds != INFINITE:
        r = ctypes.windll.kernel32.WaitForMultipleObjects(ctypes.byref(lpHandles), bWaitAll, dwMilliseconds)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = ctypes.windll.kernel32.WaitForMultipleObjects(ctypes.byref(lpHandles), bWaitAll, 100)
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
    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    nCount          = len(handles)
    lpHandlesType   = DWORD * nCount
    lpHandles       = lpHandlesType(*handles)
    if bWaitAll:
        bWaitAll    = TRUE
    else:
        bWaitAll    = FALSE
    if bAlertable:
        bAlertable  = TRUE
    else:
        bAlertable  = FALSE
    if dwMilliseconds != INFINITE:
        r = ctypes.windll.kernel32.WaitForMultipleObjectsEx(ctypes.byref(lpHandles), bWaitAll, dwMilliseconds, bAlertable)
        if r == WAIT_FAILED:
            raise ctypes.WinError()
    else:
        while 1:
            r = ctypes.windll.kernel32.WaitForMultipleObjectsEx(ctypes.byref(lpHandles), bWaitAll, 100, bAlertable)
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
    if not dwMilliseconds and dwMilliseconds != 0:
        dwMilliseconds = INFINITE
    lpDebugEvent                  = DEBUG_EVENT()
    lpDebugEvent.dwDebugEventCode = 0
    lpDebugEvent.dwProcessId      = 0
    lpDebugEvent.dwThreadId       = 0
    if dwMilliseconds != INFINITE:
        success = ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(lpDebugEvent), dwMilliseconds)
        if success == FALSE:
            raise ctypes.WinError()
    else:
        while 1:
            success = ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(lpDebugEvent), 100)
            if success != FALSE:
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
    success = ctypes.windll.kernel32.ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI FlushInstructionCache(
#   __in  HANDLE hProcess,
#   __in  LPCVOID lpBaseAddress,
#   __in  SIZE_T dwSize
# );
def FlushInstructionCache(hProcess, lpBaseAddress = NULL, dwSize = 0):
    # http://blogs.msdn.com/oldnewthing/archive/2003/12/08/55954.aspx#55958
    success = ctypes.windll.kernel32.FlushInstructionCache(hProcess, lpBaseAddress, dwSize)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL DebugActiveProcess(
#   DWORD dwProcessId
# );
def DebugActiveProcess(dwProcessId):
    success = ctypes.windll.kernel32.DebugActiveProcess(dwProcessId)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL DebugActiveProcessStop(
#   DWORD dwProcessId
# );
def DebugActiveProcessStop(dwProcessId):
    success = ctypes.windll.kernel32.DebugActiveProcessStop(dwProcessId)
    if success == FALSE:
        raise ctypes.WinError()

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
    if not lpApplicationName:
        lpApplicationName   = NULL
    else:
        lpApplicationName   = ctypes.c_char_p(lpApplicationName)
    if not lpCommandLine:
        lpCommandLine       = NULL
    else:
        lpCommandLine       = ctypes.create_string_buffer(lpCommandLine)
    if not lpEnvironment:
        lpEnvironment       = NULL
    else:
        lpEnvironment       = ctypes.c_char_p(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = NULL
    else:
        lpCurrentDirectory  = ctypes.c_char_p(lpCurrentDirectory)
    if isinstance(lpProcessAttributes, SECURITY_ATTRIBUTES):
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    else:
        lpProcessAttributes = NULL
    if isinstance(lpThreadAttributes, SECURITY_ATTRIBUTES):
        lpThreadAttributes  = ctypes.byref(lpThreadAttributes)
    else:
        lpThreadAttributes  = NULL
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
    success = ctypes.windll.kernel32.CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return ProcessInformation(lpProcessInformation)
def CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None):
    if not lpApplicationName:
        lpApplicationName   = NULL
    else:
        lpApplicationName   = ctypes.c_wchar_p(lpApplicationName)
    if not lpCommandLine:
        lpCommandLine       = NULL
    else:
        lpCommandLine       = ctypes.create_unicode_buffer(lpCommandLine)
    if not lpEnvironment:
        lpEnvironment       = NULL
    else:
        lpEnvironment       = ctypes.c_wchar_p(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = NULL
    else:
        lpCurrentDirectory  = ctypes.c_wchar_p(lpCurrentDirectory)
    if isinstance(lpProcessAttributes, SECURITY_ATTRIBUTES):
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    else:
        lpProcessAttributes = NULL
    if isinstance(lpThreadAttributes, SECURITY_ATTRIBUTES):
        lpThreadAttributes  = ctypes.byref(lpThreadAttributes)
    else:
        lpThreadAttributes  = NULL
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
    success = ctypes.windll.kernel32.CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
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
    if not lpApplicationName:
        lpApplicationName   = NULL
    else:
        lpApplicationName   = ctypes.c_char_p(lpApplicationName)
    if not lpCommandLine:
        lpCommandLine       = NULL
    else:
        lpCommandLine       = ctypes.create_string_buffer(lpCommandLine)
    if not lpEnvironment:
        lpEnvironment       = NULL
    else:
        lpEnvironment       = ctypes.c_char_p(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = NULL
    else:
        lpCurrentDirectory  = ctypes.c_char_p(lpCurrentDirectory)
    if isinstance(lpProcessAttributes, SECURITY_ATTRIBUTES):
        lpProcessAttributes = ctypes.byref(lpProcessAttributes)
    else:
        lpProcessAttributes = NULL
    if isinstance(lpThreadAttributes, SECURITY_ATTRIBUTES):
        lpThreadAttributes  = ctypes.byref(lpThreadAttributes)
    else:
        lpThreadAttributes  = NULL
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
    lpProcessInformation.hProcess     = -1
    lpProcessInformation.hThread      = -1
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0
    success = ctypes.windll.kernel32.CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return ProcessInformation(lpProcessInformation)

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
    hProcess = ctypes.windll.kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return ProcessHandle(hProcess)

# HANDLE WINAPI OpenThread(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwThreadId
# );
def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    hThread = ctypes.windll.kernel32.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId)
    if hThread == NULL:
        raise ctypes.WinError()
    return ThreadHandle(hThread)

# DWORD WINAPI SuspendThread(
#   __in  HANDLE hThread
# );
def SuspendThread(hThread):
    count = ctypes.windll.kernel32.SuspendThread(hThread)
    if count == -1:
        raise ctypes.WinError()
    return count

# DWORD WINAPI ResumeThread(
#   __in  HANDLE hThread
# );
def ResumeThread(hThread):
    count = ctypes.windll.kernel32.ResumeThread(hThread)
    if count == -1:
        raise ctypes.WinError()
    return count

# BOOL WINAPI TerminateThread(
#   __inout  HANDLE hThread,
#   __in     DWORD dwExitCode
# );
def TerminateThread(hThread, dwExitCode = 0):
    success = ctypes.windll.kernel32.TerminateThread(hThread, dwExitCode)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI TerminateProcess(
#   __inout  HANDLE hProcess,
#   __in     DWORD dwExitCode
# );
def TerminateProcess(hProcess, dwExitCode = 0):
    success = ctypes.windll.kernel32.TerminateProcess(hProcess, dwExitCode)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );
def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
    lpBuffer                = ctypes.create_string_buffer('', nSize)
    lpNumberOfBytesRead     = ctypes.c_uint(0)
    success = ctypes.windll.kernel32.ReadProcessMemory(hProcess, lpBaseAddress, ctypes.byref(lpBuffer), nSize, ctypes.byref(lpNumberOfBytesRead))
    if success == FALSE:
        if GetLastError() != ERROR_PARTIAL_COPY:
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
    nSize                   = len(lpBuffer)
    lpBuffer                = ctypes.create_string_buffer(lpBuffer)
    lpNumberOfBytesWritten  = ctypes.c_uint(0)
    success = ctypes.windll.kernel32.WriteProcessMemory(hProcess, lpBaseAddress, ctypes.byref(lpBuffer), nSize, ctypes.byref(lpNumberOfBytesWritten))
    if success == FALSE:
        if GetLastError() != ERROR_PARTIAL_COPY:
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
    lpAddress = ctypes.windll.kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
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
    lpBuffer = MEMORY_BASIC_INFORMATION()
    dwLength = sizeof(MEMORY_BASIC_INFORMATION)
    success  = ctypes.windll.kernel32.VirtualQueryEx(hProcess, lpAddress, ctypes.byref(lpBuffer), dwLength)
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
    flOldProtect = DWORD(0)
    success = ctypes.windll.kernel32.VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, ctypes.byref(flOldProtect))
    if success == FALSE:
        raise ctypes.WinError()
    return flOldProtect.value

# BOOL WINAPI VirtualFreeEx(
#   __in  HANDLE hProcess,
#   __in  LPVOID lpAddress,
#   __in  SIZE_T dwSize,
#   __in  DWORD dwFreeType
# );
def VirtualFreeEx(hProcess, lpAddress, dwSize = 0, dwFreeType = MEM_RELEASE):
    success = ctypes.windll.kernel32.VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI GetThreadSelectorEntry(
#   __in   HANDLE hThread,
#   __in   DWORD dwSelector,
#   __out  LPLDT_ENTRY lpSelectorEntry
# );
def GetThreadSelectorEntry(hThread, dwSelector):
    ldt = LDT_ENTRY()
    success = ctypes.windll.kernel32.GetThreadSelectorEntry(hThread, dwSelector, ctypes.byref(ldt))
    if success == FALSE:
        raise types.WinError()
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
    if isinstance(lpThreadAttributes, SECURITY_ATTRIBUTES):
        lpThreadAttributes = ctypes.byref(lpThreadAttributes)
    else:
        lpThreadAttributes = NULL
    dwThreadId = DWORD(0)
    hThread = ctypes.windll.kernel32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, ctypes.byref(dwThreadId))
    if hThread == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return ThreadHandle(hThread), dwThreadId.value

# HANDLE WINAPI GetCurrentProcess(void);
def GetCurrentProcess():
    return ctypes.windll.kernel32.GetCurrentProcess()

# HANDLE WINAPI GetCurrentThread(void);
def GetCurrentThread():
    return ctypes.windll.kernel32.GetCurrentThread()

# DWORD WINAPI GetProcessId(
#   __in  HANDLE hProcess
# );
def GetProcessId(hProcess):
    dwProcessId = ctypes.windll.kernel32.GetProcessId(hProcess)
    if dwProcessId == 0:
        raise ctypes.WinError()
    return dwProcessId

# DWORD WINAPI GetThreadId(
#   __in  HANDLE hThread
# );
def GetThreadId(hThread):
    dwThreadId = ctypes.windll.kernel32.GetThreadId(hThread)
    if dwThreadId == 0:
        raise ctypes.WinError()
    return dwThreadId

# DWORD WINAPI GetProcessIdOfThread(
#   __in  HANDLE hThread
# );
def GetProcessIdOfThread(hThread):
    dwProcessId = ctypes.windll.kernel32.GetProcessIdOfThread(hThread)
    if dwProcessId == 0:
        raise ctypes.WinError()
    return dwProcessId

# BOOL WINAPI GetExitCodeProcess(
#   __in   HANDLE hProcess,
#   __out  LPDWORD lpExitCode
# );
def GetExitCodeProcess(hProcess):
    lpExitCode = DWORD(0)
    success = ctypes.windll.kernel32.GetExitCodeProcess(hProcess, ctypes.byref(lpExitCode))
    if success == 0:
        raise ctypes.WinError()
    return lpExitCode.value

# BOOL WINAPI GetExitCodeThread(
#   __in   HANDLE hThread,
#   __out  LPDWORD lpExitCode
# );
def GetExitCodeThread(hThread):
    lpExitCode = DWORD(0)
    success = ctypes.windll.kernel32.GetExitCodeThread(hThread, ctypes.byref(lpExitCode))
    if success == 0:
        raise ctypes.WinError()
    return lpExitCode.value

# DWORD WINAPI GetProcessVersion(
#   __in  DWORD ProcessId
# );
def GetProcessVersion(ProcessId):
    retval = ctypes.windll.kernel32.GetProcessVersion(ProcessId)
    if retval == 0:
        raise ctypes.WinError()
    return retval

# DWORD WINAPI GetPriorityClass(
#   __in  HANDLE hProcess
# );
def GetPriorityClass(hProcess):
    retval = ctypes.windll.kernel32.GetPriorityClass(hProcess)
    if retval == 0:
        raise ctypes.WinError()
    return retval

# BOOL WINAPI SetPriorityClass(
#   __in  HANDLE hProcess,
#   __in  DWORD dwPriorityClass
# );
def SetPriorityClass(hProcess, dwPriorityClass):
    success = ctypes.windll.kernel32.SetPriorityClass(hProcess, dwPriorityClass)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI GetProcessPriorityBoost(
#   __in   HANDLE hProcess,
#   __out  PBOOL pDisablePriorityBoost
# );
def GetProcessPriorityBoost(hProcess):
    pDisablePriorityBoost = DWORD(0)
    success = ctypes.windll.kernel32.GetProcessPriorityBoost(hProcess, ctypes.byref(pDisablePriorityBoost))
    if success == FALSE:
        raise ctypes.WinError()
    return bool(pDisablePriorityBoost.value)

# BOOL WINAPI SetProcessPriorityBoost(
#   __in  HANDLE hProcess,
#   __in  BOOL DisablePriorityBoost
# );
def SetProcessPriorityBoost(hProcess, DisablePriorityBoost):
    if DisablePriorityBoost:
        DisablePriorityBoost = TRUE
    else:
        DisablePriorityBoost = FALSE
    success = ctypes.windll.kernel32.SetProcessPriorityBoost(hProcess, DisablePriorityBoost)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI GetProcessAffinityMask(
#   __in   HANDLE hProcess,
#   __out  PDWORD_PTR lpProcessAffinityMask,
#   __out  PDWORD_PTR lpSystemAffinityMask
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms683213(VS.85).aspx

# BOOL WINAPI SetProcessAffinityMask(
#   __in  HANDLE hProcess,
#   __in  DWORD_PTR dwProcessAffinityMask
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms686223(VS.85).aspx

# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL pbDebuggerPresent
# );
def CheckRemoteDebuggerPresent(hProcess):
    pbDebuggerPresent = DWORD(0)
    success = ctypes.windll.kernel32.CheckRemoteDebuggerPresent(hProcess, ctypes.byref(pbDebuggerPresent))
    if success == FALSE:
        raise ctypes.WinError()
    return bool(pbDebuggerPresent.value)

# BOOL DebugSetProcessKillOnExit(
#   BOOL KillOnExit
# );
def DebugSetProcessKillOnExit(KillOnExit):
    if KillOnExit:
        KillOnExit = TRUE
    else:
        KillOnExit = FALSE
    success = ctypes.windll.kernel32.DebugSetProcessKillOnExit(KillOnExit)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL DebugBreakProcess(
#   HANDLE Process
# );
def DebugBreakProcess(hProcess):
    success = ctypes.windll.kernel32.DebugBreakProcess(hProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  LPCONTEXT lpContext
# );
def GetThreadContext(hThread, ContextFlags = CONTEXT_ALL):
    lpContext = CONTEXT()
    lpContext.ContextFlags = ContextFlags
    success = ctypes.windll.kernel32.GetThreadContext(hThread, ctypes.byref(lpContext))
    if success == FALSE:
        raise ctypes.WinError()
    return lpContext.to_dict()

# BOOL WINAPI SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const CONTEXT* lpContext
# );
def SetThreadContext(hThread, lpContext):
    if isinstance(lpContext, dict):
        lpContext = CONTEXT.from_dict(lpContext)
    success = ctypes.windll.kernel32.SetThreadContext(hThread, ctypes.byref(lpContext))
    if success == FALSE:
        raise ctypes.WinError()

# HANDLE WINAPI CreateToolhelp32Snapshot(
#   __in  DWORD dwFlags,
#   __in  DWORD th32ProcessID
# );
def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    hSnapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hSnapshot)

# BOOL WINAPI Process32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPPROCESSENTRY32 lppe
# );
def Process32First(hSnapshot):
    pe        = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = ctypes.windll.kernel32.Process32First(hSnapshot, ctypes.byref(pe))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

# BOOL WINAPI Process32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPPROCESSENTRY32 lppe
# );
def Process32Next(hSnapshot, pe = None):
    if pe is None:
        pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = ctypes.windll.kernel32.Process32Next(hSnapshot, ctypes.byref(pe))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

# BOOL WINAPI Thread32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPTHREADENTRY32 lpte
# );
def Thread32First(hSnapshot):
    te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = ctypes.windll.kernel32.Thread32First(hSnapshot, ctypes.byref(te))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Thread32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPTHREADENTRY32 lpte
# );
def Thread32Next(hSnapshot, te = None):
    if te is None:
        te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = ctypes.windll.kernel32.Thread32Next(hSnapshot, ctypes.byref(te))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Module32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPMODULEENTRY32 lpme
# );
def Module32First(hSnapshot):
    me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = ctypes.windll.kernel32.Module32First(hSnapshot, ctypes.byref(me))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return me

# BOOL WINAPI Module32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPMODULEENTRY32 lpme
# );
def Module32Next(hSnapshot, me = None):
    if me is None:
        me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    success = ctypes.windll.kernel32.Module32Next(hSnapshot, ctypes.byref(me))
    if success == FALSE:
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
    he = HEAPENTRY32()
    he.dwSize = sizeof(HEAPENTRY32)
    success = ctypes.windll.kernel32.Heap32First(ctypes.byref(he), th32ProcessID, th32HeapID)
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return he

# BOOL WINAPI Heap32Next(
#   __out  LPHEAPENTRY32 lphe
# );
def Heap32Next(he):
    he.dwSize = sizeof(HEAPENTRY32)
    success = ctypes.windll.kernel32.Heap32Next(ctypes.byref(he))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return he

# BOOL WINAPI Heap32ListFirst(
#   __in     HANDLE hSnapshot,
#   __inout  LPHEAPLIST32 lphl
# );
def Heap32ListFirst(hSnapshot):
    hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = ctypes.windll.kernel32.Heap32ListFirst(hSnapshot, ctypes.byref(hl))
    if success == FALSE:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return hl

# BOOL WINAPI Heap32ListNext(
#   __in     HANDLE hSnapshot,
#   __out  LPHEAPLIST32 lphl
# );
def Heap32ListNext(hSnapshot, hl = None):
    if hl is None:
        hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = ctypes.windll.kernel32.Heap32ListNext(hSnapshot, ctypes.byref(hl))
    if success == FALSE:
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
def Toolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, nSize):
    lpBuffer                = ctypes.create_string_buffer('', nSize)
    lpNumberOfBytesRead     = ctypes.c_uint(0)
    success = ctypes.windll.kernel32.Toolhelp32ReadProcessMemory(th32ProcessID, lpBaseAddress, ctypes.byref(lpBuffer), nSize, ctypes.byref(lpNumberOfBytesRead))
    if success == FALSE:
        if GetLastError() != ERROR_PARTIAL_COPY:
            raise ctypes.WinError()
    return str(lpBuffer.raw)[:lpNumberOfBytesRead.value]

# DWORD WINAPI GetCurrentProcessorNumber(void);
def GetCurrentProcessorNumber():
    retval = ctypes.windll.kernel32.GetCurrentProcessorNumber()
    if retval == 0:
        raise ctypes.WinError()
    return retval

# VOID WINAPI FlushProcessWriteBuffers(void);
def FlushProcessWriteBuffers():
    ctypes.windll.kernel32.FlushProcessWriteBuffers()

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
def GetGuiResources(hProcess, uiFlags):
    return ctypes.windll.kernel32.GetGuiResources(hProcess, uiFlags)

# BOOL WINAPI GetProcessHandleCount(
#   __in     HANDLE hProcess,
#   __inout  PDWORD pdwHandleCount
# );
def GetProcessHandleCount(hProcess):
    pdwHandleCount = DWORD(0)
    success = ctypes.windll.kernel32.GetProcessHandleCount(hProcess, ctypes.byref(pdwHandleCount))
    if success == FALSE:
        raise ctypes.WinError()
    return pdwHandleCount.value

# BOOL WINAPI GetProcessTimes(
#   __in   HANDLE hProcess,
#   __out  LPFILETIME lpCreationTime,
#   __out  LPFILETIME lpExitTime,
#   __out  LPFILETIME lpKernelTime,
#   __out  LPFILETIME lpUserTime
# );

# TO DO http://msdn.microsoft.com/en-us/library/ms683223(VS.85).aspx

# void WINAPI GetSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetSystemInfo():
    sysinfo = SYSTEM_INFO()
    ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(sysinfo))
    return sysinfo

# void WINAPI GetNativeSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetNativeSystemInfo():
    sysinfo = SYSTEM_INFO()
    ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
    return sysinfo

#------------------------------------------------------------------------------
# Wow64

# BOOL WINAPI IsWow64Process(
#   __in   HANDLE hProcess,
#   __out  PBOOL Wow64Process
# );
def IsWow64Process(hProcess):
    Wow64Process = BOOL(FALSE)
    success = ctypes.windll.kernel32.IsWow64Process(hProcess, ctypes.byref(Wow64Process))
    if success == FALSE:
        raise ctypes.WinError()
    return Wow64Process

# BOOL Wow64GetThreadSelectorEntry(
#   __in   HANDLE hThread,
#   __in   DWORD dwSelector,
#   __out  PWOW64_LDT_ENTRY lpSelectorEntry
# );
def Wow64GetThreadSelectorEntry(hThread, dwSelector):
    lpSelectorEntry = WOW64_LDT_ENTRY()
    success = ctypes.windll.kernel32.Wow64GetThreadSelectorEntry(hThread, dwSelector, ctypes.byref(lpSelectorEntry))
    if success == FALSE:
        raise ctypes.WinError() # ERROR_NOT_SUPPORTED means we have to call GetThreadSelectorEntry
    return lpSelectorEntry

# DWORD WINAPI Wow64SuspendThread(
#   __in  HANDLE hThread
# );
def Wow64SuspendThread(hThread):
    success = ctypes.windll.kernel32.Wow64SuspendThread(hThread)
    if success == FALSE:
        raise ctypes.WinError() # ERROR_INVALID_FUNCTION means we have to call SuspendThread

# XXX TODO Use this http://www.nynaeve.net/Code/GetThreadWow64Context.cpp
# Also see http://www.woodmann.com/forum/archive/index.php/t-11162.html

# BOOL WINAPI Wow64GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  PWOW64_CONTEXT lpContext
# );
def Wow64GetThreadContext(hThread, lpContext = None):
    if lpContext is None:
        lpContext = WOW64_CONTEXT()
        lpContext.ContextFlags = WOW64_CONTEXT_ALL
    success = ctypes.windll.kernel32.Wow64GetThreadContext(hThread, ctypes.byref(lpContext))
    if success == FALSE:
        raise ctypes.WinError() # ERROR_INVALID_FUNCTION means we have to call GetThreadContext
    return lpContext.to_dict()

# BOOL WINAPI Wow64SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const WOW64_CONTEXT *lpContext
# );
def Wow64SetThreadContext(hThread, lpContext):
    if isinstance(lpContext, dict):
        lpContext = WOW64_CONTEXT.from_dict(lpContext)
    success = ctypes.windll.kernel32.Wow64SetThreadContext(hThread, ctypes.byref(lpContext))
    if success == FALSE:
        raise ctypes.WinError() # ERROR_INVALID_FUNCTION means we have to call SetThreadContext

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
