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

# $Id$

"""
Debugging API wrappers in ctypes.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/Win32APIWrappers}
"""

import struct
import ctypes

sizeof      = ctypes.sizeof
POINTER     = ctypes.POINTER
Structure   = ctypes.Structure
Union       = ctypes.Union

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
PWSTR       = LPWSTR
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
HANDLE      = DWORD
HMODULE     = DWORD
HINSTANCE   = DWORD
HLOCAL      = DWORD
HGLOBAL     = DWORD
NTSTATUS    = DWORD
KAFFINITY   = LONG
KPRIORITY   = LONG
TCHAR       = CHAR
SIZE_T      = DWORD
PVOID       = LPVOID
PPVOID      = POINTER(PVOID)

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

STILL_ACTIVE = 259

MAX_MODULE_NAME32   = 255
MAX_PATH            = 260

WAIT_TIMEOUT        = 0x102
WAIT_FAILED         = -1
WAIT_OBJECT_0       = 0

EXCEPTION_NONCONTINUABLE        = 0x1       # Noncontinuable exception
EXCEPTION_MAXIMUM_PARAMETERS    = 15        # maximum number of exception parameters
MAXIMUM_WAIT_OBJECTS            = 64        # Maximum number of wait objects
MAXIMUM_SUSPEND_COUNT           = 0x7f      # Maximum times thread can be suspended

HW_ACCESS                       = 0x00000003
HW_EXECUTE                      = 0x00000000
HW_WRITE                        = 0x00000001

FORMAT_MESSAGE_ALLOCATE_BUFFER  = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM      = 0x00001000

GR_GDIOBJECTS  = 0
GR_USEROBJECTS = 1

PROCESS_NAME_NATIVE = 1

# SetSearchPathMode flags
# TODO I couldn't find these constants :(
##BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE     = ???
##BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE    = ???
##BASE_SEARCH_PATH_PERMANENT                  = ???

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

# DuplicateHandle constants
DUPLICATE_CLOSE_SOURCE      = 0x00000001
DUPLICATE_SAME_ACCESS       = 0x00000002

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

# Status codes
STATUS_WAIT_0                    = 0x00000000L
STATUS_ABANDONED_WAIT_0          = 0x00000080L
STATUS_USER_APC                  = 0x000000C0L
STATUS_TIMEOUT                   = 0x00000102L
STATUS_PENDING                   = 0x00000103L
DBG_EXCEPTION_HANDLED            = 0x00010001L
DBG_CONTINUE                     = 0x00010002L
DBG_EXCEPTION_NOT_HANDLED        = 0x80010001L
STATUS_SEGMENT_NOTIFICATION      = 0x40000005L
##DBG_TERMINATE_THREAD             = 0x40010003L
##DBG_TERMINATE_PROCESS            = 0x40010004L
##DBG_CONTROL_C                    = 0x40010005L
##DBG_CONTROL_BREAK                = 0x40010008L
##DBG_COMMAND_EXCEPTION            = 0x40010009L
STATUS_GUARD_PAGE_VIOLATION      = 0x80000001L
STATUS_DATATYPE_MISALIGNMENT     = 0x80000002L
STATUS_BREAKPOINT                = 0x80000003L
STATUS_SINGLE_STEP               = 0x80000004L
STATUS_INVALID_INFO_CLASS        = 0xC0000003L
STATUS_ACCESS_VIOLATION          = 0xC0000005L
STATUS_IN_PAGE_ERROR             = 0xC0000006L
STATUS_INVALID_HANDLE            = 0xC0000008L
STATUS_NO_MEMORY                 = 0xC0000017L
STATUS_ILLEGAL_INSTRUCTION       = 0xC000001DL
STATUS_NONCONTINUABLE_EXCEPTION  = 0xC0000025L
STATUS_INVALID_DISPOSITION       = 0xC0000026L
STATUS_ARRAY_BOUNDS_EXCEEDED     = 0xC000008CL
STATUS_FLOAT_DENORMAL_OPERAND    = 0xC000008DL
STATUS_FLOAT_DIVIDE_BY_ZERO      = 0xC000008EL
STATUS_FLOAT_INEXACT_RESULT      = 0xC000008FL
STATUS_FLOAT_INVALID_OPERATION   = 0xC0000090L
STATUS_FLOAT_OVERFLOW            = 0xC0000091L
STATUS_FLOAT_STACK_CHECK         = 0xC0000092L
STATUS_FLOAT_UNDERFLOW           = 0xC0000093L
STATUS_INTEGER_DIVIDE_BY_ZERO    = 0xC0000094L
STATUS_INTEGER_OVERFLOW          = 0xC0000095L
STATUS_PRIVILEGED_INSTRUCTION    = 0xC0000096L
STATUS_STACK_OVERFLOW            = 0xC00000FDL
STATUS_CONTROL_C_EXIT            = 0xC000013AL
STATUS_FLOAT_MULTIPLE_FAULTS     = 0xC00002B4L
STATUS_FLOAT_MULTIPLE_TRAPS      = 0xC00002B5L
STATUS_REG_NAT_CONSUMPTION       = 0xC00002C9L
STATUS_SXS_EARLY_DEACTIVATION    = 0xC015000FL
STATUS_SXS_INVALID_DEACTIVATION  = 0xC0150010L

STATUS_POSSIBLE_DEADLOCK         = 0xC0000194L

STATUS_UNWIND_CONSOLIDATE        = 0x80000029L

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

# Privilege constants
SE_CREATE_TOKEN_NAME              = "SeCreateTokenPrivilege"
SE_ASSIGNPRIMARYTOKEN_NAME        = "SeAssignPrimaryTokenPrivilege"
SE_LOCK_MEMORY_NAME               = "SeLockMemoryPrivilege"
SE_INCREASE_QUOTA_NAME            = "SeIncreaseQuotaPrivilege"
SE_UNSOLICITED_INPUT_NAME         = "SeUnsolicitedInputPrivilege"
SE_MACHINE_ACCOUNT_NAME           = "SeMachineAccountPrivilege"
SE_TCB_NAME                       = "SeTcbPrivilege"
SE_SECURITY_NAME                  = "SeSecurityPrivilege"
SE_TAKE_OWNERSHIP_NAME            = "SeTakeOwnershipPrivilege"
SE_LOAD_DRIVER_NAME               = "SeLoadDriverPrivilege"
SE_SYSTEM_PROFILE_NAME            = "SeSystemProfilePrivilege"
SE_SYSTEMTIME_NAME                = "SeSystemtimePrivilege"
SE_PROF_SINGLE_PROCESS_NAME       = "SeProfileSingleProcessPrivilege"
SE_INC_BASE_PRIORITY_NAME         = "SeIncreaseBasePriorityPrivilege"
SE_CREATE_PAGEFILE_NAME           = "SeCreatePagefilePrivilege"
SE_CREATE_PERMANENT_NAME          = "SeCreatePermanentPrivilege"
SE_BACKUP_NAME                    = "SeBackupPrivilege"
SE_RESTORE_NAME                   = "SeRestorePrivilege"
SE_SHUTDOWN_NAME                  = "SeShutdownPrivilege"
SE_DEBUG_NAME                     = "SeDebugPrivilege"
SE_AUDIT_NAME                     = "SeAuditPrivilege"
SE_SYSTEM_ENVIRONMENT_NAME        = "SeSystemEnvironmentPrivilege"
SE_CHANGE_NOTIFY_NAME             = "SeChangeNotifyPrivilege"
SE_REMOTE_SHUTDOWN_NAME           = "SeRemoteShutdownPrivilege"
SE_UNDOCK_NAME                    = "SeUndockPrivilege"
SE_SYNC_AGENT_NAME                = "SeSyncAgentPrivilege"
SE_ENABLE_DELEGATION_NAME         = "SeEnableDelegationPrivilege"
SE_MANAGE_VOLUME_NAME             = "SeManageVolumePrivilege"
SE_IMPERSONATE_NAME               = "SeImpersonatePrivilege"
SE_CREATE_GLOBAL_NAME             = "SeCreateGlobalPrivilege"

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED            = 0x00000002
SE_PRIVILEGE_REMOVED            = 0x00000004
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

TOKEN_ADJUST_PRIVILEGES         = 0x00000020

# LoadLibraryEx constants
DONT_RESOLVE_DLL_REFERENCES         = 0x00000001
LOAD_LIBRARY_AS_DATAFILE            = 0x00000002
LOAD_WITH_ALTERED_SEARCH_PATH       = 0x00000008
LOAD_IGNORE_CODE_AUTHZ_LEVEL        = 0x00000010
LOAD_LIBRARY_AS_IMAGE_RESOURCE      = 0x00000020
LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE  = 0x00000040

# DEP flags for ProcessExecuteFlags
MEM_EXECUTE_OPTION_ENABLE               = 1
MEM_EXECUTE_OPTION_DISABLE              = 2
MEM_EXECUTE_OPTION_ATL7_THUNK_EMULATION = 4
MEM_EXECUTE_OPTION_PERMANENT            = 8

# NtQuerySystemInformation() constants from:
# http://www.informit.com/articles/article.aspx?p=22442&seqNum=4
SystemBasicInformation                  = 1     # 0x002C
SystemProcessorInformation              = 2     # 0x000C
SystemPerformanceInformation            = 3     # 0x0138
SystemTimeInformation                   = 4     # 0x0020
SystemPathInformation                   = 5     # not implemented
SystemProcessInformation                = 6     # 0x00F8 + per process
SystemCallInformation                   = 7     # 0x0018 + (n * 0x0004)
SystemConfigurationInformation          = 8     # 0x0018
SystemProcessorCounters                 = 9     # 0x0030 per cpu
SystemGlobalFlag                        = 10    # 0x0004
SystemInfo10                            = 11    # not implemented
SystemModuleInformation                 = 12    # 0x0004 + (n * 0x011C)
SystemLockInformation                   = 13    # 0x0004 + (n * 0x0024)
SystemInfo13                            = 14    # not implemented
SystemPagedPoolInformation              = 15    # checked build only
SystemNonPagedPoolInformation           = 16    # checked build only
SystemHandleInformation                 = 17    # 0x0004 + (n * 0x0010)
SystemObjectInformation                 = 18    # 0x0038+ + (n * 0x0030+)
SystemPagefileInformation               = 19    # 0x0018+ per page file
SystemInstemulInformation               = 20    # 0x0088
SystemInfo20                            = 21    # invalid info class
SystemCacheInformation                  = 22    # 0x0024
SystemPoolTagInformation                = 23    # 0x0004 + (n * 0x001C)
SystemProcessorStatistics               = 24    # 0x0000, or 0x0018 per cpu
SystemDpcInformation                    = 25    # 0x0014
SystemMemoryUsageInformation1           = 26    # checked build only
SystemLoadImage                         = 27    # 0x0018, set mode only
SystemUnloadImage                       = 28    # 0x0004, set mode only
SystemTimeAdjustmentInformation         = 29    # 0x000C, 0x0008 writeable
SystemMemoryUsageInformation2           = 30    # checked build only
SystemInfo30                            = 31    # checked build only
SystemInfo31                            = 32    # checked build only
SystemCrashDumpInformation              = 33    # 0x0004
SystemExceptionInformation              = 34    # 0x0010
SystemCrashDumpStateInformation         = 35    # 0x0008
SystemDebuggerInformation               = 36    # 0x0002
SystemThreadSwitchInformation           = 37    # 0x0030
SystemRegistryQuotaInformation          = 38    # 0x000C
SystemLoadDriver                        = 39    # 0x0008, set mode only
SystemPrioritySeparationInformation     = 40    # 0x0004, set mode only
SystemInfo40                            = 41    # not implemented
SystemInfo41                            = 42    # not implemented
SystemInfo42                            = 43    # invalid info class
SystemInfo43                            = 44    # invalid info class
SystemTimeZoneInformation               = 45    # 0x00AC
SystemLookasideInformation              = 46    # n * 0x0020
# info classes specific to Windows 2000
# WTS = Windows Terminal Server
SystemSetTimeSlipEvent                  = 47    # set mode only
SystemCreateSession                     = 48    # WTS, set mode only
SystemDeleteSession                     = 49    # WTS, set mode only
SystemInfo49                            = 50    # invalid info class
SystemRangeStartInformation             = 51    # 0x0004
SystemVerifierInformation               = 52    # 0x0068
SystemAddVerifier                       = 53    # set mode only
SystemSessionProcessesInformation       = 54    # WTS

# NtQueryInformationProcess constants (from MSDN)
##ProcessBasicInformation = 0
##ProcessDebugPort        = 7
##ProcessWow64Information = 26
##ProcessImageFileName    = 27

# NtQueryInformationProcess constants
# http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PROCESS_INFORMATION_CLASS.html
ProcessBasicInformation             = 0
ProcessQuotaLimits                  = 1
ProcessIoCounters                   = 2
ProcessVmCounters                   = 3
ProcessTimes                        = 4
ProcessBasePriority                 = 5
ProcessRaisePriority                = 6
ProcessDebugPort                    = 7
ProcessExceptionPort                = 8
ProcessAccessToken                  = 9
ProcessLdtInformation               = 10
ProcessLdtSize                      = 11
ProcessDefaultHardErrorMode         = 12
ProcessIoPortHandlers               = 13
ProcessPooledUsageAndLimits         = 14
ProcessWorkingSetWatch              = 15
ProcessUserModeIOPL                 = 16
ProcessEnableAlignmentFaultFixup    = 17
ProcessPriorityClass                = 18
ProcessWx86Information              = 19
ProcessHandleCount                  = 20
ProcessAffinityMask                 = 21
ProcessPriorityBoost                = 22

ProcessWow64Information             = 26
ProcessImageFileName                = 27

ProcessExecuteFlags                 = 34

# NtQueryInformationThread constants
#
ThreadBasicInformation          = 0
ThreadTimes                     = 1
ThreadPriority                  = 2
ThreadBasePriority              = 3
ThreadAffinityMask              = 4
ThreadImpersonationToken        = 5
ThreadDescriptorTableEntry      = 6
ThreadEnableAlignmentFaultFixup = 7
ThreadEventPair                 = 8
ThreadQuerySetWin32StartAddress = 9
ThreadZeroTlsCell               = 10
ThreadPerformanceCount          = 11
ThreadAmILastThread             = 12
ThreadIdealProcessor            = 13
ThreadPriorityBoost             = 14
ThreadSetTlsArrayAddress        = 15
ThreadIsIoPending               = 16
ThreadHideFromDebugger          = 17

# From http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_DISPOSITION.html
# typedef enum _EXCEPTION_DISPOSITION
# {
#          ExceptionContinueExecution = 0,
#          ExceptionContinueSearch = 1,
#          ExceptionNestedException = 2,
#          ExceptionCollidedUnwind = 3
# } EXCEPTION_DISPOSITION;
ExceptionContinueExecution  = 0
ExceptionContinueSearch     = 1
ExceptionNestedException    = 2
ExceptionCollidedUnwind     = 3

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

#--- UNICODE_STRING structure  ------------------------------------------------

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

#--- PEB and TEB structure, constants and data types --------------------------

# From http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
#
# typedef struct _CLIENT_ID
# {
#     PVOID UniqueProcess;
#     PVOID UniqueThread;
# } CLIENT_ID, *PCLIENT_ID;
class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess",   PVOID),
        ("UniqueThread",    PVOID),
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

# From MSDN:
#
# typedef struct _LDR_DATA_TABLE_ENTRY {
#     BYTE Reserved1[2];
#     LIST_ENTRY InMemoryOrderLinks;
#     PVOID Reserved2[2];
#     PVOID DllBase;
#     PVOID EntryPoint;
#     PVOID Reserved3;
#     UNICODE_STRING FullDllName;
#     BYTE Reserved4[8];
#     PVOID Reserved5[3];
#     union {
#         ULONG CheckSum;
#         PVOID Reserved6;
#     };
#     ULONG TimeDateStamp;
# } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
##class LDR_DATA_TABLE_ENTRY(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",           BYTE * 2),
##        ("InMemoryOrderLinks",  LIST_ENTRY),
##        ("Reserved2",           PVOID * 2),
##        ("DllBase",             PVOID),
##        ("EntryPoint",          PVOID),
##        ("Reserved3",           PVOID),
##        ("FullDllName",           UNICODE_STRING),
##        ("Reserved4",           BYTE * 8),
##        ("Reserved5",           PVOID * 3),
##        ("CheckSum",            ULONG),
##        ("TimeDateStamp",       ULONG),
##]

# From MSDN:
#
# typedef struct _PEB_LDR_DATA {
#   BYTE         Reserved1[8];
#   PVOID        Reserved2[3];
#   LIST_ENTRY   InMemoryOrderModuleList;
# } PEB_LDR_DATA,
#  *PPEB_LDR_DATA;
##class PEB_LDR_DATA(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE),
##        ("Reserved2",               PVOID),
##        ("InMemoryOrderModuleList", LIST_ENTRY),
##]

# From MSDN:
#
# typedef struct _RTL_USER_PROCESS_PARAMETERS {
#   BYTE             Reserved1[16];
#   PVOID            Reserved2[10];
#   UNICODE_STRING   ImagePathName;
#   UNICODE_STRING   CommandLine;
# } RTL_USER_PROCESS_PARAMETERS,
#  *PRTL_USER_PROCESS_PARAMETERS;
##class RTL_USER_PROCESS_PARAMETERS(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE * 16),
##        ("Reserved2",               PVOID * 10),
##        ("ImagePathName",           UNICODE_STRING),
##        ("CommandLine",             UNICODE_STRING),
##]

##PPS_POST_PROCESS_INIT_ROUTINE = PVOID

#from MSDN:
#
# typedef struct _PEB {
#     BYTE Reserved1[2];
#     BYTE BeingDebugged;
#     BYTE Reserved2[21];
#     PPEB_LDR_DATA LoaderData;
#     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
#     BYTE Reserved3[520];
#     PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
#     BYTE Reserved4[136];
#     ULONG SessionId;
# } PEB;
##class PEB(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE * 2),
##        ("BeingDebugged",           BYTE),
##        ("Reserved2",               BYTE * 21),
##        ("LoaderData",              POINTER(PEB_LDR_DATA)),
##        ("ProcessParameters",       POINTER(RTL_USER_PROCESS_PARAMETERS)),
##        ("Reserved3",               BYTE * 520),
##        ("PostProcessInitRoutine",  PPS_POST_PROCESS_INIT_ROUTINE),
##        ("Reserved4",               BYTE),
##        ("SessionId",               ULONG),
##]

# from MSDN:
#
# typedef struct _TEB {
#   BYTE    Reserved1[1952];
#   PVOID   Reserved2[412];
#   PVOID   TlsSlots[64];
#   BYTE    Reserved3[8];
#   PVOID   Reserved4[26];
#   PVOID   ReservedForOle;
#   PVOID   Reserved5[4];
#   PVOID   TlsExpansionSlots;
# } TEB,
#  *PTEB;
##class TEB(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",           PVOID * 1952),
##        ("Reserved2",           PVOID * 412),
##        ("TlsSlots",            PVOID * 64),
##        ("Reserved3",           BYTE  * 8),
##        ("Reserved4",           PVOID * 26),
##        ("ReservedForOle",      PVOID),
##        ("Reserved5",           PVOID * 4),
##        ("TlsExpansionSlots",   PVOID),
##]

# from http://undocumented.ntinternals.net/UserMode/Structures/LDR_MODULE.html
#
# typedef struct _LDR_MODULE {
#   LIST_ENTRY InLoadOrderModuleList;
#   LIST_ENTRY InMemoryOrderModuleList;
#   LIST_ENTRY InInitializationOrderModuleList;
#   PVOID BaseAddress;
#   PVOID EntryPoint;
#   ULONG SizeOfImage;
#   UNICODE_STRING FullDllName;
#   UNICODE_STRING BaseDllName;
#   ULONG Flags;
#   SHORT LoadCount;
#   SHORT TlsIndex;
#   LIST_ENTRY HashTableEntry;
#   ULONG TimeDateStamp;
# } LDR_MODULE, *PLDR_MODULE;
class LDR_MODULE(Structure):
    _pack_ = 1
    _fields_ = [
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("BaseAddress",                     PVOID),
        ("EntryPoint",                      PVOID),
        ("SizeOfImage",                     ULONG),
        ("FullDllName",                     UNICODE_STRING),
        ("BaseDllName",                     UNICODE_STRING),
        ("Flags",                           ULONG),
        ("LoadCount",                       SHORT),
        ("TlsIndex",                        SHORT),
        ("HashTableEntry",                  LIST_ENTRY),
        ("TimeDateStamp",                   ULONG),
]

# from http://undocumented.ntinternals.net/UserMode/Structures/PEB_LDR_DATA.html
#
# typedef struct _PEB_LDR_DATA {
#   ULONG Length;
#   BOOLEAN Initialized;
#   PVOID SsHandle;
#   LIST_ENTRY InLoadOrderModuleList;
#   LIST_ENTRY InMemoryOrderModuleList;
#   LIST_ENTRY InInitializationOrderModuleList;
# } PEB_LDR_DATA, *PPEB_LDR_DATA;
class PEB_LDR_DATA(Structure):
    _pack_ = 1
    _fields_ = [
        ("Length",                          ULONG),
        ("Initialized",                     BOOLEAN),
        ("SsHandle",                        PVOID),
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
]

# From http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB_FREE_BLOCK.html
#
# typedef struct _PEB_FREE_BLOCK {
#   PEB_FREE_BLOCK *Next;
#   ULONG Size;
# } PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;
class PEB_FREE_BLOCK(Structure):
    pass

##PPEB_FREE_BLOCK = POINTER(PEB_FREE_BLOCK)
PPEB_FREE_BLOCK = PVOID

PEB_FREE_BLOCK._fields_ = [
        ("Next", PPEB_FREE_BLOCK),
        ("Size", ULONG),
]

# From http://undocumented.ntinternals.net/UserMode/Structures/RTL_DRIVE_LETTER_CURDIR.html
#
# typedef struct _RTL_DRIVE_LETTER_CURDIR {
#   USHORT Flags;
#   USHORT Length;
#   ULONG TimeStamp;
#   UNICODE_STRING DosPath;
# } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
class RTL_DRIVE_LETTER_CURDIR(Structure):
    _fields_ = [
        ("Flags",       USHORT),
        ("Length",      USHORT),
        ("TimeStamp",   ULONG),
        ("DosPath",     UNICODE_STRING),
]

# From http://www.nirsoft.net/kernel_struct/vista/CURDIR.html
#
# typedef struct _CURDIR
# {
#      UNICODE_STRING DosPath;
#      PVOID Handle;
# } CURDIR, *PCURDIR;
class CURDIR(Structure):
    _fields_ = [
        ("DosPath", UNICODE_STRING),
        ("Handle",  PVOID),
]

# From MSDN:
#
# typedef struct _RTL_USER_PROCESS_PARAMETERS {
#   BYTE           Reserved1[16];
#   PVOID          Reserved2[10];
#   UNICODE_STRING ImagePathName;
#   UNICODE_STRING CommandLine;
# } RTL_USER_PROCESS_PARAMETERS,
# *PRTL_USER_PROCESS_PARAMETERS;
class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved1",       BYTE * 16),
        ("Reserved2",       PVOID * 10),
        ("ImagePathName",   UNICODE_STRING),
        ("CommandLine",     UNICODE_STRING),
]

# kd> dt _RTL_USER_PROCESS_PARAMETERS
# ntdll!_RTL_USER_PROCESS_PARAMETERS
#    +0x000 MaximumLength    : Uint4B
#    +0x004 Length           : Uint4B
#    +0x008 Flags            : Uint4B
#    +0x00c DebugFlags       : Uint4B
#    +0x010 ConsoleHandle    : Ptr32 Void
#    +0x014 ConsoleFlags     : Uint4B
#    +0x018 StandardInput    : Ptr32 Void
#    +0x01c StandardOutput   : Ptr32 Void
#    +0x020 StandardError    : Ptr32 Void
#    +0x024 CurrentDirectory : _CURDIR
#    +0x030 DllPath          : _UNICODE_STRING
#    +0x038 ImagePathName    : _UNICODE_STRING
#    +0x040 CommandLine      : _UNICODE_STRING
#    +0x048 Environment      : Ptr32 Void
#    +0x04c StartingX        : Uint4B
#    +0x050 StartingY        : Uint4B
#    +0x054 CountX           : Uint4B
#    +0x058 CountY           : Uint4B
#    +0x05c CountCharsX      : Uint4B
#    +0x060 CountCharsY      : Uint4B
#    +0x064 FillAttribute    : Uint4B
#    +0x068 WindowFlags      : Uint4B
#    +0x06c ShowWindowFlags  : Uint4B
#    +0x070 WindowTitle      : _UNICODE_STRING
#    +0x078 DesktopInfo      : _UNICODE_STRING
#    +0x080 ShellInfo        : _UNICODE_STRING
#    +0x088 RuntimeData      : _UNICODE_STRING
#    +0x090 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
#    +0x290 EnvironmentSize  : Uint4B
##class RTL_USER_PROCESS_PARAMETERS(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("MaximumLength",           ULONG),
##        ("Length",                  ULONG),
##        ("Flags",                   ULONG),
##        ("DebugFlags",              ULONG),
##        ("ConsoleHandle",           PVOID),
##        ("ConsoleFlags",            ULONG),
##        ("StandardInput",           HANDLE),
##        ("StandardOutput",          HANDLE),
##        ("StandardError",           HANDLE),
##        ("CurrentDirectory",        CURDIR),
##        ("DllPath",                 UNICODE_STRING),
##        ("ImagePathName",           UNICODE_STRING),
##        ("CommandLine",             UNICODE_STRING),
##        ("Environment",             PVOID),
##        ("StartingX",               ULONG),
##        ("StartingY",               ULONG),
##        ("CountX",                  ULONG),
##        ("CountY",                  ULONG),
##        ("CountCharsX",             ULONG),
##        ("CountCharsY",             ULONG),
##        ("FillAttribute",           ULONG),
##        ("WindowFlags",             ULONG),
##        ("ShowWindowFlags",         ULONG),
##        ("WindowTitle",             UNICODE_STRING),
##        ("DesktopInfo",             UNICODE_STRING),
##        ("ShellInfo",               UNICODE_STRING),
##        ("RuntimeData",             UNICODE_STRING),
##        ("CurrentDirectores",       RTL_DRIVE_LETTER_CURDIR * 32), # typo here?
##
##        # Windows 2008 and Vista
##        ("EnvironmentSize",         ULONG),
##]
##    @property
##    def CurrentDirectories(self):
##        return self.CurrentDirectores

# From http://www.nirsoft.net/kernel_struct/vista/RTL_CRITICAL_SECTION_DEBUG.html
#
# typedef struct _RTL_CRITICAL_SECTION_DEBUG
# {
#      WORD Type;
#      WORD CreatorBackTraceIndex;
#      PRTL_CRITICAL_SECTION CriticalSection;
#      LIST_ENTRY ProcessLocksList;
#      ULONG EntryCount;
#      ULONG ContentionCount;
#      ULONG Flags;
#      WORD CreatorBackTraceIndexHigh;
#      WORD SpareUSHORT;
# } RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;
#
# From http://www.nirsoft.net/kernel_struct/vista/RTL_CRITICAL_SECTION.html
#
# typedef struct _RTL_CRITICAL_SECTION
# {
#      PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
#      LONG LockCount;
#      LONG RecursionCount;
#      PVOID OwningThread;
#      PVOID LockSemaphore;
#      ULONG SpinCount;
# } RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#
class RTL_CRITICAL_SECTION(Structure):
    _pack_ = 1
class RTL_CRITICAL_SECTION_DEBUG(Structure):
    _pack_ = 1
##PRTL_CRITICAL_SECTION       = POINTER(RTL_CRITICAL_SECTION)
##PRTL_CRITICAL_SECTION_DEBUG = POINTER(RTL_CRITICAL_SECTION_DEBUG)
PRTL_CRITICAL_SECTION       = PVOID
PRTL_CRITICAL_SECTION_DEBUG = PVOID
RTL_CRITICAL_SECTION._fields_ = [
        ("DebugInfo",       PRTL_CRITICAL_SECTION_DEBUG),
        ("LockCount",       LONG),
        ("RecursionCount",  LONG),
        ("OwningThread",    PVOID),
        ("LockSemaphore",   PVOID),
        ("SpinCount",       ULONG),
]
RTL_CRITICAL_SECTION_DEBUG._fields_ = [
        ("Type",                        WORD),
        ("CreatorBackTraceIndex",       WORD),
        ("CriticalSection",             PRTL_CRITICAL_SECTION),
        ("ProcessLocksList",            LIST_ENTRY),
        ("EntryCount",                  ULONG),
        ("ContentionCount",             ULONG),
        ("Flags",                       ULONG),
        ("CreatorBackTraceIndexHigh",   WORD),
        ("SpareUSHORT",                 WORD),
]

# kd> dt nt!_PEB
#    +0x000 InheritedAddressSpace : UChar
#    +0x001 ReadImageFileExecOptions : UChar
#    +0x002 BeingDebugged    : UChar
#    +0x003 BitField         : UChar
#    +0x003 ImageUsesLargePages : Pos 0, 1 Bit
#    +0x003 IsProtectedProcess : Pos 1, 1 Bit
#    +0x003 IsLegacyProcess  : Pos 2, 1 Bit
#    +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
#    +0x003 SpareBits        : Pos 4, 4 Bits
#    +0x004 Mutant           : Ptr32 Void
#    +0x008 ImageBaseAddress : Ptr32 Void
#    +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
#    +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
#    +0x014 SubSystemData    : Ptr32 Void
#    +0x018 ProcessHeap      : Ptr32 Void
#    +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
#    +0x020 AtlThunkSListPtr : Ptr32 Void
#    +0x024 IFEOKey          : Ptr32 Void
#    +0x028 CrossProcessFlags : Uint4B
#    +0x028 ProcessInJob     : Pos 0, 1 Bit
#    +0x028 ProcessInitializing : Pos 1, 1 Bit
#    +0x028 ReservedBits0    : Pos 2, 30 Bits
#    +0x02c KernelCallbackTable : Ptr32 Void
#    +0x02c UserSharedInfoPtr : Ptr32 Void
#    +0x030 SystemReserved   : [1] Uint4B
#    +0x034 SpareUlong       : Uint4B
#    +0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
#    +0x03c TlsExpansionCounter : Uint4B
#    +0x040 TlsBitmap        : Ptr32 Void
#    +0x044 TlsBitmapBits    : [2] Uint4B
#    +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
#    +0x050 HotpatchInformation : Ptr32 Void
#    +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
#    +0x058 AnsiCodePageData : Ptr32 Void
#    +0x05c OemCodePageData  : Ptr32 Void
#    +0x060 UnicodeCaseTableData : Ptr32 Void
#    +0x064 NumberOfProcessors : Uint4B
#    +0x068 NtGlobalFlag     : Uint4B
#    +0x070 CriticalSectionTimeout : _LARGE_INTEGER
#    +0x078 HeapSegmentReserve : Uint4B
#    +0x07c HeapSegmentCommit : Uint4B
#    +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
#    +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
#    +0x088 NumberOfHeaps    : Uint4B
#    +0x08c MaximumNumberOfHeaps : Uint4B
#    +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
#    +0x094 GdiSharedHandleTable : Ptr32 Void
#    +0x098 ProcessStarterHelper : Ptr32 Void
#    +0x09c GdiDCAttributeList : Uint4B
#    +0x0a0 LoaderLock       : Ptr32 _RTL_CRITICAL_SECTION
#    +0x0a4 OSMajorVersion   : Uint4B
#    +0x0a8 OSMinorVersion   : Uint4B
#    +0x0ac OSBuildNumber    : Uint2B
#    +0x0ae OSCSDVersion     : Uint2B
#    +0x0b0 OSPlatformId     : Uint4B
#    +0x0b4 ImageSubsystem   : Uint4B
#    +0x0b8 ImageSubsystemMajorVersion : Uint4B
#    +0x0bc ImageSubsystemMinorVersion : Uint4B
#    +0x0c0 ImageProcessAffinityMask : Uint4B
#    +0x0c4 GdiHandleBuffer  : [34] Uint4B
#    +0x14c PostProcessInitRoutine : Ptr32     void
#    +0x150 TlsExpansionBitmap : Ptr32 Void
#    +0x154 TlsExpansionBitmapBits : [32] Uint4B
#    +0x1d4 SessionId        : Uint4B
#    +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
#    +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
#    +0x1e8 pShimData        : Ptr32 Void
#    +0x1ec AppCompatInfo    : Ptr32 Void
#    +0x1f0 CSDVersion       : _UNICODE_STRING
#    +0x1f8 ActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
#    +0x1fc ProcessAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
#    +0x200 SystemDefaultActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
#    +0x204 SystemAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
#    +0x208 MinimumStackCommit : Uint4B
#    +0x20c FlsCallback      : Ptr32 _FLS_CALLBACK_INFO
#    +0x210 FlsListHead      : _LIST_ENTRY
#    +0x218 FlsBitmap        : Ptr32 Void
#    +0x21c FlsBitmapBits    : [4] Uint4B
#    +0x22c FlsHighIndex     : Uint4B
#    +0x230 WerRegistrationData : Ptr32 Void
#    +0x234 WerShipAssertPtr : Ptr32 Void

##PPEB_LDR_DATA                   = POINTER(PEB_LDR_DATA)
##PRTL_USER_PROCESS_PARAMETERS    = POINTER(RTL_USER_PROCESS_PARAMETERS)
PPEB_LDR_DATA                   = PVOID
PRTL_USER_PROCESS_PARAMETERS    = PVOID

PPEBLOCKROUTINE                 = PVOID

# BitField
ImageUsesLargePages         = 1 << 0
IsProtectedProcess          = 1 << 1
IsLegacyProcess             = 1 << 2
IsImageDynamicallyRelocated = 1 << 3

# TODO
# Break down the PEB into multiple structures, once for each Windows version.
# Then autodetect the current Windows version and set the PEB symbol to the
# correct structure (while keeping the others for reference).
class PEB(Structure):
    _pack_ = 1
    _fields_ = [

        # Windows NT

        ("InheritedAddressSpace",               UCHAR),
        ("ReadImageFileExecOptions",            UCHAR),
        ("BeingDebugged",                       UCHAR),
        ("BitField",                            UCHAR),
        ("Mutant",                              HANDLE),
        ("ImageBaseAddress",                    PVOID),
        ("Ldr",                                 PPEB_LDR_DATA),
        ("ProcessParameters",                   PRTL_USER_PROCESS_PARAMETERS),
        ("SubSystemData",                       PVOID),
        ("ProcessHeap",                         PVOID),
        ("FastPebLock",                         PVOID),
        ("FastPebLockRoutine",                  PPEBLOCKROUTINE),
        ("FastPebUnlockRoutine",                PPEBLOCKROUTINE),
        ("EnvironmentUpdateCount",              ULONG),
        ("KernelCallbackTable",                 PPVOID),
        ("EventLogSection",                     PVOID),
        ("EventLog",                            PVOID),
        ("FreeList",                            PPEB_FREE_BLOCK),
        ("TlsExpansionCounter",                 ULONG),
        ("TlsBitmap",                           PVOID),
        ("TlsBitmapBits",                       ULONG * 2),
        ("ReadOnlySharedMemoryBase",            PVOID),
        ("ReadOnlySharedMemoryHeap",            PVOID),
        ("ReadOnlyStaticServerData",            PPVOID),
        ("AnsiCodePageData",                    PVOID),
        ("OemCodePageData",                     PVOID),
        ("UnicodeCaseTableData",                PVOID),
        ("NumberOfProcessors",                  ULONG),
        ("NtGlobalFlag",                        ULONG),
        ("Spare2",                              BYTE * 4),
        ("CriticalSectionTimeout",              LONGLONG),  # LARGE_INTEGER
        ("HeapSegmentReserve",                  ULONG),
        ("HeapSegmentCommit",                   ULONG),
        ("HeapDeCommitTotalFreeThreshold",      ULONG),
        ("HeapDeCommitFreeBlockThreshold",      ULONG),
        ("NumberOfHeaps",                       ULONG),
        ("MaximumNumberOfHeaps",                ULONG),
        ("ProcessHeaps",                        PPVOID),
        ("GdiSharedHandleTable",                PVOID),
        ("ProcessStarterHelper",                PVOID),
        ("GdiDCAttributeList",                  PVOID),
        ("LoaderLock",                          PRTL_CRITICAL_SECTION),
        ("OSMajorVersion",                      ULONG),
        ("OSMinorVersion",                      ULONG),
        ("OSBuildNumber",                       ULONG),
        ("OSPlatformId",                        ULONG),
        ("ImageSubSystem",                      ULONG),
        ("ImageSubSystemMajorVersion",          ULONG),
        ("ImageSubSystemMinorVersion",          ULONG),
        ("ImageProcessAffinityMask",            ULONG),
        ("GdiHandleBuffer",                     ULONG * 34),
        ("PostProcessInitRoutine",              ULONG),
        ("TlsExpansionBitmap",                  ULONG),
        ("TlsExpansionBitmapBits",              BYTE * 128),
        ("SessionId",                           ULONG),

        # Windows XP

        ("AppCompatFlags",                      ULONGLONG), # ULARGE_INTEGER
        ("AppCompatFlagsUser",                  ULONGLONG), # ULARGE_INTEGER
        ("pShimData",                           PVOID),
        ("AppCompatInfo",                       PVOID),
        ("CSDVersion",                          UNICODE_STRING),
        ("ActivationContextData",               PVOID), # PACTIVATION_CONTEXT_DATA
        ("ProcessAssemblyStorageMap",           PVOID), # PASSEMBLY_STORAGE_MAP
        ("SystemDefaultActivationContextData",  PVOID), # PACTIVATION_CONTEXT_DATA
        ("SystemAssemblyStorageMap",            PVOID), # PASSEMBLY_STORAGE_MAP
        ("MinimumStackCommit",                  ULONG),

        # Windows 2003

        ("FlsCallback",                         PVOID), # PFLS_CALLBACK_INFO
        ("FlsListHead",                         LIST_ENTRY),
        ("FlsBitmap",                           PVOID),
        ("FlsBitmapBits",                       ULONG * 4),
        ("FlsHighIndex",                        ULONG),

        # Windows 2008 and Vista

        ("WerRegistrationData",                 PVOID),
        ("WerShipAssertPtr",                    PVOID),
]

# from http://www.nirsoft.net/kernel_struct/vista/NT_TIB.html
#
# typedef struct _NT_TIB
# {
#      PEXCEPTION_REGISTRATION_RECORD ExceptionList;
#      PVOID StackBase;
#      PVOID StackLimit;
#      PVOID SubSystemTib;
#      union
#      {
#           PVOID FiberData;
#           ULONG Version;
#      };
#      PVOID ArbitraryUserPointer;
#      PNT_TIB Self;
# } NT_TIB, *PNT_TIB;
class _NT_TIB_UNION(Union):
    _fields_ = [
        ("FiberData",   PVOID),
        ("Version",     ULONG),
]
class NT_TIB(Structure):
    _fields_ = [
        ("StackBase",               PVOID),
        ("StackLimit",              PVOID),
        ("SubSystemTib",            PVOID),
        ("u",                       _NT_TIB_UNION),
        ("ArbitraryUserPointer",    PVOID),
        ("Self",                    PVOID),     # PNTTIB
]
PNTTIB = POINTER(NT_TIB)

# From http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_REGISTRATION_RECORD.html
#
# typedef struct _EXCEPTION_REGISTRATION_RECORD
# {
#      PEXCEPTION_REGISTRATION_RECORD Next;
#      PEXCEPTION_DISPOSITION Handler;
# } EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
class EXCEPTION_REGISTRATION_RECORD(Structure):
    pass

EXCEPTION_DISPOSITION           = DWORD
##PEXCEPTION_DISPOSITION          = POINTER(EXCEPTION_DISPOSITION)
##PEXCEPTION_REGISTRATION_RECORD  = POINTER(EXCEPTION_REGISTRATION_RECORD)
PEXCEPTION_DISPOSITION          = PVOID
PEXCEPTION_REGISTRATION_RECORD  = PVOID

EXCEPTION_REGISTRATION_RECORD._fields_ = [
        ("Next",    PEXCEPTION_REGISTRATION_RECORD),
        ("Handler", PEXCEPTION_DISPOSITION),
]

##PPEB = POINTER(PEB)
PPEB = PVOID

# From http://www.nirsoft.net/kernel_struct/vista/GDI_TEB_BATCH.html
#
# typedef struct _GDI_TEB_BATCH
# {
#      ULONG Offset;
#      ULONG HDC;
#      ULONG Buffer[310];
# } GDI_TEB_BATCH, *PGDI_TEB_BATCH;
class GDI_TEB_BATCH(Structure):
    _fields_ = [
        ("Offset",  ULONG),
        ("HDC",     ULONG),
        ("Buffer",  ULONG * 310),
]

# kd> dt _TEB
#    +0x000 NtTib            : _NT_TIB
#    +0x01c EnvironmentPointer : Ptr32 Void
#    +0x020 ClientId         : _CLIENT_ID
#    +0x028 ActiveRpcHandle  : Ptr32 Void
#    +0x02c ThreadLocalStoragePointer : Ptr32 Void
#    +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
#    +0x034 LastErrorValue   : Uint4B
#    +0x038 CountOfOwnedCriticalSections : Uint4B
#    +0x03c CsrClientThread  : Ptr32 Void
#    +0x040 Win32ThreadInfo  : Ptr32 Void
#    +0x044 User32Reserved   : [26] Uint4B
#    +0x0ac UserReserved     : [5] Uint4B
#    +0x0c0 WOW32Reserved    : Ptr32 Void
#    +0x0c4 CurrentLocale    : Uint4B
#    +0x0c8 FpSoftwareStatusRegister : Uint4B
#    +0x0cc SystemReserved1  : [54] Ptr32 Void
#    +0x1a4 ExceptionCode    : Int4B
#    +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
#    +0x1ac SpareBytes1      : [36] UChar
#    +0x1d0 TxFsContext      : Uint4B
#    +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
#    +0x6b4 RealClientId     : _CLIENT_ID
#    +0x6bc GdiCachedProcessHandle : Ptr32 Void
#    +0x6c0 GdiClientPID     : Uint4B
#    +0x6c4 GdiClientTID     : Uint4B
#    +0x6c8 GdiThreadLocalInfo : Ptr32 Void
#    +0x6cc Win32ClientInfo  : [62] Uint4B
#    +0x7c4 glDispatchTable  : [233] Ptr32 Void
#    +0xb68 glReserved1      : [29] Uint4B
#    +0xbdc glReserved2      : Ptr32 Void
#    +0xbe0 glSectionInfo    : Ptr32 Void
#    +0xbe4 glSection        : Ptr32 Void
#    +0xbe8 glTable          : Ptr32 Void
#    +0xbec glCurrentRC      : Ptr32 Void
#    +0xbf0 glContext        : Ptr32 Void
#    +0xbf4 LastStatusValue  : Uint4B
#    +0xbf8 StaticUnicodeString : _UNICODE_STRING
#    +0xc00 StaticUnicodeBuffer : [261] Wchar
#    +0xe0c DeallocationStack : Ptr32 Void
#    +0xe10 TlsSlots         : [64] Ptr32 Void
#    +0xf10 TlsLinks         : _LIST_ENTRY
#    +0xf18 Vdm              : Ptr32 Void
#    +0xf1c ReservedForNtRpc : Ptr32 Void
#    +0xf20 DbgSsReserved    : [2] Ptr32 Void
#    +0xf28 HardErrorMode    : Uint4B
#    +0xf2c Instrumentation  : [9] Ptr32 Void
#    +0xf50 ActivityId       : _GUID
#    +0xf60 SubProcessTag    : Ptr32 Void
#    +0xf64 EtwLocalData     : Ptr32 Void
#    +0xf68 EtwTraceData     : Ptr32 Void
#    +0xf6c WinSockData      : Ptr32 Void
#    +0xf70 GdiBatchCount    : Uint4B
#    +0xf74 SpareBool0       : UChar
#    +0xf75 SpareBool1       : UChar
#    +0xf76 SpareBool2       : UChar
#    +0xf77 IdealProcessor   : UChar
#    +0xf78 GuaranteedStackBytes : Uint4B
#    +0xf7c ReservedForPerf  : Ptr32 Void
#    +0xf80 ReservedForOle   : Ptr32 Void
#    +0xf84 WaitingOnLoaderLock : Uint4B
#    +0xf88 SavedPriorityState : Ptr32 Void
#    +0xf8c SoftPatchPtr1    : Uint4B
#    +0xf90 ThreadPoolData   : Ptr32 Void
#    +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
#    +0xf98 ImpersonationLocale : Uint4B
#    +0xf9c IsImpersonating  : Uint4B
#    +0xfa0 NlsCache         : Ptr32 Void
#    +0xfa4 pShimData        : Ptr32 Void
#    +0xfa8 HeapVirtualAffinity : Uint4B
#    +0xfac CurrentTransactionHandle : Ptr32 Void
#    +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
#    +0xfb4 FlsData          : Ptr32 Void
#    +0xfb8 PreferredLanguages : Ptr32 Void
#    +0xfbc UserPrefLanguages : Ptr32 Void
#    +0xfc0 MergedPrefLanguages : Ptr32 Void
#    +0xfc4 MuiImpersonation : Uint4B
#    +0xfc8 CrossTebFlags    : Uint2B
#    +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
#    +0xfca SameTebFlags     : Uint2B
#    +0xfca DbgSafeThunkCall : Pos 0, 1 Bit
#    +0xfca DbgInDebugPrint  : Pos 1, 1 Bit
#    +0xfca DbgHasFiberData  : Pos 2, 1 Bit
#    +0xfca DbgSkipThreadAttach : Pos 3, 1 Bit
#    +0xfca DbgWerInShipAssertCode : Pos 4, 1 Bit
#    +0xfca DbgRanProcessInit : Pos 5, 1 Bit
#    +0xfca DbgClonedThread  : Pos 6, 1 Bit
#    +0xfca DbgSuppressDebugMsg : Pos 7, 1 Bit
#    +0xfca RtlDisableUserStackWalk : Pos 8, 1 Bit
#    +0xfca RtlExceptionAttached : Pos 9, 1 Bit
#    +0xfca SpareSameTebBits : Pos 10, 6 Bits
#    +0xfcc TxnScopeEnterCallback : Ptr32 Void
#    +0xfd0 TxnScopeExitCallback : Ptr32 Void
#    +0xfd4 TxnScopeContext  : Ptr32 Void
#    +0xfd8 LockCount        : Uint4B
#    +0xfdc ProcessRundown   : Uint4B
#    +0xfe0 LastSwitchTime   : Uint8B
#    +0xfe8 TotalSwitchOutTime : Uint8B
#    +0xff0 WaitReasonBitMap : _LARGE_INTEGER

# TODO
# Break down the TEB into multiple structures, once for each Windows version.
# Then autodetect the current Windows version and set the TEB symbol to the
# correct structure (while keeping the others for reference).
class TEB(Structure):
    _pack_ = 1
    _fields_ = [

        # Windows NT (maybe 2000)

        ("NtTib",                           NT_TIB),
        ("EnvironmentPointer",              PVOID),
        ("ClientId",                        CLIENT_ID),
        ("ActiveRpcHandle",                 PVOID),
        ("ThreadLocalStoragePointer",       PVOID),
        ("ProcessEnvironmentBlock",         PPEB),
        ("LastErrorValue",                  ULONG),
        ("CountOfOwnedCriticalSections",    ULONG),
        ("CsrClientThread",                 PVOID),
        ("Win32ThreadInfo",                 PVOID),
        ("User32Reserved",                  ULONG * 26),
        ("UserReserved",                    ULONG * 5),
        ("WOW32Reserved",                   PVOID),
        ("CurrentLocale",                   ULONG),
        ("FpSoftwareStatusRegister",        ULONG),
        ("SystemReserved1",                 PVOID * 54),
        ("Spare1",                          PVOID),
        ("ExceptionCode",                   ULONG),
        ("ActivationContextStackPointer",   PVOID), # PACTIVATION_CONTEXT_STACK
        ("SpareBytes1",                     ULONG * 36),
        ("TxFsContext",                     ULONG),
        ("GdiTebBatch",                     GDI_TEB_BATCH),
        ("RealClientId",                    CLIENT_ID),
        ("GdiCachedProcessHandle",          PVOID),
        ("GdiClientPID",                    ULONG),
        ("GdiClientTID",                    ULONG),
        ("GdiThreadLocalInfo",              PVOID),
        ("Win32ClientInfo",                 PVOID * 62),
        ("glDispatchTable",                 PVOID * 233),
        ("glReserved1",                     ULONG * 29),
        ("glReserved2",                     PVOID),
        ("glSectionInfo",                   PVOID),
        ("glSection",                       PVOID),
        ("glTable",                         PVOID),
        ("glCurrentRC",                     PVOID),
        ("glContext",                       PVOID),
        ("LastStatusValue",                 NTSTATUS),
        ("StaticUnicodeString",             UNICODE_STRING),
        ("StaticUnicodeBuffer",             WCHAR * 261),
        ("DeallocationStack",               PVOID),
        ("TlsSlots",                        PVOID * 64),
        ("TlsLinks",                        LIST_ENTRY),
        ("Vdm",                             PVOID),
        ("ReservedForNtRpc",                PVOID),
        ("DbgSsReserved",                   PVOID * 2),
        ("HardErrorDisabled",               ULONG),
        ("Instrumentation",                 PVOID * 9),
        ("ActivityId",                      GUID),
        ("SubProcessTag",                   PVOID),
        ("EtwLocalData",                    PVOID),
        ("EtwTraceData",                    PVOID),
        ("WinSockData",                     PVOID),
        ("GdiBatchCount",                   ULONG),
        ("SpareBool0",                      UCHAR),
        ("SpareBool1",                      UCHAR),
        ("SpareBool2",                      UCHAR),
        ("IdealProcessor",                  UCHAR),
        ("GuaranteedStackBytes",            ULONG),
        ("ReservedForPerf",                 PVOID),
        ("ReservedForOle",                  PVOID),
        ("WaitingOnLoaderLock",             ULONG),

        # Windows NT only I believe???
##        ("StackCommit",                     PVOID),
##        ("StackCommitMax",                  PVOID),
##        ("StackReserved",                   PVOID),

        # TODO
        # Add more fields here

##        +0xf88 SavedPriorityState : Ptr32 Void
##        +0xf8c SoftPatchPtr1    : Uint4B
##        +0xf90 ThreadPoolData   : Ptr32 Void
##        +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
##        +0xf98 ImpersonationLocale : Uint4B
##        +0xf9c IsImpersonating  : Uint4B
##        +0xfa0 NlsCache         : Ptr32 Void
##        +0xfa4 pShimData        : Ptr32 Void
##        +0xfa8 HeapVirtualAffinity : Uint4B
##        +0xfac CurrentTransactionHandle : Ptr32 Void
##        +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
##        +0xfb4 FlsData          : Ptr32 Void
##        +0xfb8 PreferredLanguages : Ptr32 Void
##        +0xfbc UserPrefLanguages : Ptr32 Void
##        +0xfc0 MergedPrefLanguages : Ptr32 Void
##        +0xfc4 MuiImpersonation : Uint4B
##        +0xfc8 CrossTebFlags    : Uint2B
##        +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
##        +0xfca SameTebFlags     : Uint2B
##        +0xfca DbgSafeThunkCall : Pos 0, 1 Bit
##        +0xfca DbgInDebugPrint  : Pos 1, 1 Bit
##        +0xfca DbgHasFiberData  : Pos 2, 1 Bit
##        +0xfca DbgSkipThreadAttach : Pos 3, 1 Bit
##        +0xfca DbgWerInShipAssertCode : Pos 4, 1 Bit
##        +0xfca DbgRanProcessInit : Pos 5, 1 Bit
##        +0xfca DbgClonedThread  : Pos 6, 1 Bit
##        +0xfca DbgSuppressDebugMsg : Pos 7, 1 Bit
##        +0xfca RtlDisableUserStackWalk : Pos 8, 1 Bit
##        +0xfca RtlExceptionAttached : Pos 9, 1 Bit
##        +0xfca SpareSameTebBits : Pos 10, 6 Bits
##        +0xfcc TxnScopeEnterCallback : Ptr32 Void
##        +0xfd0 TxnScopeExitCallback : Ptr32 Void
##        +0xfd4 TxnScopeContext  : Ptr32 Void
##        +0xfd8 LockCount        : Uint4B
##        +0xfdc ProcessRundown   : Uint4B
##        +0xfe0 LastSwitchTime   : Uint8B
##        +0xfe8 TotalSwitchOutTime : Uint8B
##        +0xff0 WaitReasonBitMap : _LARGE_INTEGER
]

# From MSDN:
#
# typedef struct _PROCESS_BASIC_INFORMATION {
#     PVOID Reserved1;
#     PPEB PebBaseAddress;
#     PVOID Reserved2[2];
#     ULONG_PTR UniqueProcessId;
#     PVOID Reserved3;
# } PROCESS_BASIC_INFORMATION;
##class PROCESS_BASIC_INFORMATION(Structure):
##    _fields_ = [
##        ("Reserved1",       PVOID),
##        ("PebBaseAddress",  PPEB),
##        ("Reserved2",       PVOID * 2),
##        ("UniqueProcessId", ULONG_PTR),
##        ("Reserved3",       PVOID),
##]

# From http://catch22.net/tuts/tips2
#
# typedef struct
# {
#     ULONG      ExitStatus;
#     PVOID      PebBaseAddress;
#     ULONG      AffinityMask;
#     ULONG      BasePriority;
#     ULONG_PTR  UniqueProcessId;
#     ULONG_PTR  InheritedFromUniqueProcessId;
# } PROCESS_BASIC_INFORMATION;
class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",                      ULONG),
        ("PebBaseAddress",                  PVOID),
        ("AffinityMask",                    ULONG),
        ("BasePriority",                    ULONG),
        ("UniqueProcessId",                 ULONG_PTR),
        ("InheritedFromUniqueProcessId",    ULONG_PTR),
]

# From http://undocumented.ntinternals.net/UserMode/Structures/THREAD_BASIC_INFORMATION.html
#
# typedef struct _THREAD_BASIC_INFORMATION {
#   NTSTATUS ExitStatus;
#   PVOID TebBaseAddress;
#   CLIENT_ID ClientId;
#   KAFFINITY AffinityMask;
#   KPRIORITY Priority;
#   KPRIORITY BasePriority;
# } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

##PTEB = POINTER(TEB)
PTEB = PVOID

class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",      NTSTATUS),
        ("TebBaseAddress",  PTEB),
        ("ClientId",        CLIENT_ID),
        ("AffinityMask",    KAFFINITY),
        ("Priority",        KPRIORITY),
        ("BasePriority",    KPRIORITY),
]

#--- SYSDBG_MSR structure and constants ---------------------------------------

SysDbgReadMsr  = 16
SysDbgWriteMsr = 17

class SYSDBG_MSR(Structure):
    _fields_ = [
        ("Address", ULONG),
        ("Data",    ULONGLONG),
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
        ('BaseAddress',         DWORD),     # remote pointer
        ('AllocationBase',      DWORD),     # remote pointer
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

#--- CONTEXT structure and constants (for x86 only) ---------------------------

# The following values specify the type of access in the first parameter
# of the exception record whan the exception code specifies an access
# violation.
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch

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
        # The format and contexts are processor specific

        ('ExtendedRegisters',   BYTE * MAXIMUM_SUPPORTED_EXTENSION),
    ]

    def __iter__(self):
        return self.__ContextIterator(self)

    class __ContextIterator:
        'Iterator of CONTEXT structures.'

        ctx_debug   = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')
        ctx_segs    = ('SegGs', 'SegFs', 'SegEs', 'SegDs', )
        ctx_int     = ('Edi', 'Esi', 'Ebx', 'Edx', 'Ecx', 'Eax')
        ctx_ctrl    = ('Ebp', 'Eip', 'SegCs', 'EFlags', 'Esp', 'SegSs')
        ctx_float_1 = (
            'ControlWord',
            'StatusWord',
            'TagWord',
            'ErrorOffset',
            'ErrorSelector',
            'DataOffset',
            'DataSelector',
        )
        ctx_float_2 = (
            'Cr0NpxState',
        )

        def extract(self, ctx, names):
            for n in names:
                self.iter.append( (n, getattr(ctx, n)) )

        def extract_array(self, ctx, n):
            ctx = getattr(ctx, n)
            self.iter.append( (n, [ctx[i] for i in xrange(len(ctx))] ) )

        def check_flag(self, f, mask):
            return (f & mask) != CONTEXT_i386

        def __init__(self, ctx):
            f = ctx.ContextFlags
            self.iter = list()
            self.iter.append( ('ContextFlags', f) )
            if self.check_flag(f, CONTEXT_DEBUG_REGISTERS):
                self.extract(ctx, self.ctx_debug)
            if self.check_flag(f, CONTEXT_FLOATING_POINT):
                self.extract(ctx.FloatSave, self.ctx_float_1)
                self.extract_array(ctx.FloatSave, 'RegisterArea')
                self.extract(ctx.FloatSave, self.ctx_float_2)
            if self.check_flag(f, CONTEXT_SEGMENTS):
                self.extract(ctx, self.ctx_segs)
            if self.check_flag(f, CONTEXT_INTEGER):
                self.extract(ctx, self.ctx_int)
            if self.check_flag(f, CONTEXT_CONTROL):
                self.extract(ctx, self.ctx_ctrl)
            if self.check_flag(f, CONTEXT_EXTENDED_REGISTERS):
                self.extract_array(ctx, 'ExtendedRegisters')

        def next(self):
            if len(self.iter):
                return self.iter.pop(0)
            raise StopIteration

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

#--- PSAPI structures and constants -------------------------------------------

LIST_MODULES_DEFAULT    = 0x00
LIST_MODULES_32BIT      = 0x01
LIST_MODULES_64BIT      = 0x02
LIST_MODULES_ALL        = 0x03

# typedef struct _MODULEINFO {
#   LPVOID lpBaseOfDll;
#   DWORD  SizeOfImage;
#   LPVOID EntryPoint;
# } MODULEINFO, *LPMODULEINFO;
class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll",     LPVOID),    # remote pointer
        ("SizeOfImage",     DWORD),
        ("EntryPoint",      LPVOID),    # remote pointer
]

#--- TOKEN_PRIVILEGE structure ------------------------------------------------

# typedef struct _LUID {
#   DWORD LowPart;
#   LONG HighPart;
# } LUID,
#  *PLUID;
class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

# typedef struct _LUID_AND_ATTRIBUTES {
#   LUID Luid;
#   DWORD Attributes;
# } LUID_AND_ATTRIBUTES,
#  *PLUID_AND_ATTRIBUTES;
class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

# typedef struct _TOKEN_PRIVILEGES {
#   DWORD PrivilegeCount;
#   LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
# } TOKEN_PRIVILEGES,
#  *PTOKEN_PRIVILEGES;
class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
##        ("Privileges",      LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]
    # See comments on AdjustTokenPrivileges about this structure

#--- IO_STATUS_BLOCK structure ------------------------------------------------

# typedef struct _IO_STATUS_BLOCK {
#     union {
#         NTSTATUS Status;
#         PVOID Pointer;
#     };
#     ULONG_PTR Information;
# } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
class IO_STATUS_BLOCK(Structure):
    _fields_ = [
        ("Status",      NTSTATUS),
        ("Information", ULONG_PTR),
    ]
    @property
    def Pointer(self):
        return PVOID(self.Status)

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
    ctypes.windll.kernel32.SetLastError(dwErrCode, dwType)

# BOOL WINAPI CloseHandle(
#   __in  HANDLE hObject
# );
def CloseHandle(hHandle):
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
def DuplicateHandle(hSourceHandle, hSourceProcessHandle = None, hTargetProcessHandle = None, dwDesiredAccess = STANDARD_RIGHTS_ALL, bInheritHandle = FALSE, dwOptions = DUPLICATE_SAME_ACCESS):
    if hSourceProcessHandle is None:
        hSourceProcessHandle = GetCurrentProcess()
    if hTargetProcessHandle is None:
        hTargetProcessHandle = hSourceProcessHandle
    if bInheritHandle:
        bInheritHandle = TRUE
    else:
        bInheritHandle = FALSE
    lpTargetHandle = HANDLE(-1)
    success = ctypes.windll.kernel32.DuplicateHandle(hSourceHandle, hSourceProcessHandle, hTargetProcessHandle, byref(lpTargetHandle), dwDesiredAccess, bInheritHandle, dwOptions)
    if success == FALSE:
        raise ctypes.WinError()
    return lpTargetHandle.value

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

def GetModuleHandleA(lpModuleName):
    lpModuleName = ctypes.c_char_p(lpModuleName)
    return ctypes.windll.kernel32.GetModuleHandleA(lpModuleName)

def GetModuleHandleW(lpModuleName):
    lpModuleName = ctypes.c_wchar_p(lpModuleName)
    return ctypes.windll.kernel32.GetModuleHandleW(lpModuleName)

# HMODULE WINAPI GetModuleHandle(
#   __in_opt  LPCTSTR lpModuleName
# );
def GetModuleHandle(lpModuleName):
    if type(lpModuleName) == type(u''):
        return GetModuleHandleW(lpModuleName)
    return GetModuleHandleA(lpModuleName)

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
def QueryFullProcessImageNameW(hProcess, dwFlags):
    lpdwSize = DWORD(0)
    ctypes.windll.kernel32.QueryFullProcessImageNameW(hProcess, dwFlags, NULL, ctypes.byref(lpdwSize))
    if lpdwSize.value == 0:
        raise ctypes.WinError()
    lpExeName = ctypes.create_unicode_buffer('', lpdwSize.value)
    retval = ctypes.windll.kernel32.QueryFullProcessImageNameW(hProcess, dwFlags, ctypes.byref(lpExeName), ctypes.byref(lpdwSize))
    if retval == 0:
        raise ctypes.WinError()
    return lpExeName.raw[:lpdwSize.value]
QueryFullProcessImageName = QueryFullProcessImageNameA

# DWORD WINAPI GetLogicalDriveStrings(
#   __in   DWORD nBufferLength,
#   __out  LPTSTR lpBuffer
# );
def GetLogicalDriveStrings():
    nBufferLength = 0x1000
    lpBuffer = ctypes.create_unicode_buffer('', nBufferLength)
    size = ctypes.windll.kernel32.GetLogicalDriveStringsA(nBufferLength, ctypes.byref(lpBuffer))
    if size == 0:
        raise ctypes.WinError()
    return lpBuffer.value

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
QueryDosDevice = QueryDosDeviceA

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
def OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName):
    hFileMappingObject = ctypes.windll.kernel32.OpenFileMappingA(dwDesiredAccess, bInheritHandle, ctypes.byref(lpName))
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hFileMappingObject

# HANDLE WINAPI CreateFileMapping(
#   __in      HANDLE hFile,
#   __in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
#   __in      DWORD flProtect,
#   __in      DWORD dwMaximumSizeHigh,
#   __in      DWORD dwMaximumSizeLow,
#   __in_opt  LPCTSTR lpName
# );
def CreateFileMappingA(hFile, lpAttributes = NULL, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = NULL):
    if lpName != NULL:
        lpName = ctypes.byref(lpName)
    hFileMappingObject = ctypes.windll.kernel32.CreateFileMappingA(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hFileMappingObject
def CreateFileMappingW(hFile, lpAttributes = NULL, flProtect = PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh = 0, dwMaximumSizeLow = 0, lpName = NULL):
    if lpName != NULL:
        lpName = ctypes.byref(lpName)
    hFileMappingObject = ctypes.windll.kernel32.CreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    if hFileMappingObject == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hFileMappingObject
CreateFileMapping = CreateFileMappingA

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
    lpFileName = ctypes.byref(lpFileName)
    hFile = ctypes.windll.kernel32.CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hFile
def CreateFileW(lpFileName, dwDesiredAccess = GENERIC_ALL, dwShareMode = 0, lpSecurityAttributes = NULL, dwCreationDisposition = OPEN_ALWAYS, dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL, hTemplateFile = NULL):
    lpFileName = ctypes.byref(lpFileName)
    hFile = ctypes.windll.kernel32.CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    if hFile == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hFile
CreateFile = CreateFileA

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
SearchPath = SearchPathA

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
GetFullPathName = GetFullPathNameA

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
GetTempPath = GetTempPathA

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
GetTempFileName = GetTempFileNameA

# LPWSTR *CommandLineToArgvW(
#     LPCWSTR lpCmdLine,
#     int *pNumArgs
# );
def CommandLineToArgvW(lpCmdLine):
    if lpCmdLine is None:
        lpCmdLine = NULL
    if lpCmdLine != NULL:
        lpCmdLine = ctypes.byref(lpCmdLine)
    argc = ctypes.c_int(0)
    argv = ctypes.windll.shell32.CommandLineToArgvW(lpCmdLine, ctypes.byref(argc))
    if argv == NULL or argc <= 0:
        ctypes.WinError()
    try:
        vptr = ctypes.c_void_p(argv)
        aptr = ctypes.cast(vptr, LPWSTR * argc)
        argv = [ str( aptr[i].contents ) for i in xrange(0, argc + 1) ]
    finally:
        LocalFree(argv)
    return argv
def CommandLineToArgvA(lpCmdLine):
    if lpCmdLine not in (None, NULL):
        lpCmdLine = unicode(lpCmdLine)
    argv = CommandLineToArgvW(lpCmdLine)
    argv = [ str(x) for x in argv ]
    return argv
CommandLineToArgv = CommandLineToArgvA

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
    HANDLER_ROUTINE = ctypes.WINFUNCTYPE(DWORD)
except Exception:
    # under Wine
    HANDLER_ROUTINE = LPVOID

# BOOL WINAPI SetConsoleCtrlHandler(
#   __in_opt  PHANDLER_ROUTINE HandlerRoutine,
#   __in      BOOL Add
# );
def SetConsoleCtrlHandler(HandlerRoutine, Add = True):
    if Add:
        Add = TRUE
    else:
        Add = FALSE
    success = ctypes.windll.kernel32.SetConsoleCtrlHandler(HANDLER_ROUTINE(HandlerRoutine), Add)
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
    r = ctypes.windll.kernel32.WaitForSingleObject(hHandle, dwMilliseconds)
    if r == WAIT_FAILED:
        raise ctypes.WinError()
    return r

# DWORD WINAPI WaitForSingleObjectEx(
#   HANDLE hHandle,
#   DWORD dwMilliseconds,
#   BOOL bAlertable
# );
def WaitForSingleObjectEx(hHandle, dwMilliseconds = INFINITE, bAlertable = True):
    if bAlertable:
        bAlertable = TRUE
    else:
        bAlertable = FALSE
    r = ctypes.windll.kernel32.WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable)
    if r == WAIT_FAILED:
        raise ctypes.WinError()
    return r

# DWORD WINAPI WaitForMultipleObjects(
#   DWORD nCount,
#   const HANDLE *lpHandles,
#   BOOL bWaitAll,
#   DWORD dwMilliseconds
# );
def WaitForMultipleObjects(handles, bWaitAll = False, dwMilliseconds = INFINITE):
    nCount          = len(handles)
    lpHandlesType   = DWORD * nCount
    lpHandles       = lpHandlesType(*handles)
    if bWaitAll:
        bWaitAll    = TRUE
    else:
        bWaitAll    = FALSE
    r = ctypes.windll.kernel32.WaitForMultipleObjects(ctypes.byref(lpHandles), bWaitAll, dwMilliseconds)
    if r == WAIT_FAILED:
        raise ctypes.WinError()
    return r

# DWORD WINAPI WaitForMultipleObjectsEx(
#   DWORD nCount,
#   const HANDLE *lpHandles,
#   BOOL bWaitAll,
#   DWORD dwMilliseconds,
#   BOOL bAlertable
# );
def WaitForMultipleObjectsEx(handles, bWaitAll = False, dwMilliseconds = INFINITE):
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
    r = ctypes.windll.kernel32.WaitForMultipleObjectsEx(ctypes.byref(lpHandles), bWaitAll, dwMilliseconds, bAlertable)
    if r == WAIT_FAILED:
        raise ctypes.WinError()
    return r

# BOOL WaitForDebugEvent(
#   LPDEBUG_EVENT lpDebugEvent,
#   DWORD dwMilliseconds
# );
def WaitForDebugEvent(lpDebugEvent, dwMilliseconds = INFINITE):
    success = ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(lpDebugEvent), dwMilliseconds)
    if success == FALSE:
        raise ctypes.WinError()

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
def CreateProcessA(lpApplicationName, lpCommandLine=NULL, lpProcessAttributes=NULL, lpThreadAttributes=NULL, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=NULL, lpCurrentDirectory=NULL, lpStartupInfo=NULL, lpProcessInformation=NULL):
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
    if not isinstance(lpStartupInfo, STARTUPINFO) and not isinstance(lpStartupInfo, STARTUPINFOEX):
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    if not isinstance(lpProcessInformation, PROCESS_INFORMATION):
        lpProcessInformation              = PROCESS_INFORMATION()
        lpProcessInformation.hProcess     = -1
        lpProcessInformation.hThread      = -1
        lpProcessInformation.dwProcessId  = 0
        lpProcessInformation.dwThreadId   = 0
    success = ctypes.windll.kernel32.CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return lpProcessInformation
def CreateProcessW(lpApplicationName, lpCommandLine=NULL, lpProcessAttributes=NULL, lpThreadAttributes=NULL, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=NULL, lpCurrentDirectory=NULL, lpStartupInfo=NULL, lpProcessInformation=NULL):
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
    if not isinstance(lpStartupInfo, STARTUPINFO) and not isinstance(lpStartupInfo, STARTUPINFOEX):
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    if not isinstance(lpProcessInformation, PROCESS_INFORMATION):
        lpProcessInformation              = PROCESS_INFORMATION()
        lpProcessInformation.hProcess     = -1
        lpProcessInformation.hThread      = -1
        lpProcessInformation.dwProcessId  = 0
        lpProcessInformation.dwThreadId   = 0
    success = ctypes.windll.kernel32.CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return lpProcessInformation
CreateProcess = CreateProcessA

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
def CreateProcessAsUser(hToken, lpApplicationName, lpCommandLine=NULL, lpProcessAttributes=NULL, lpThreadAttributes=NULL, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=NULL, lpCurrentDirectory=NULL, lpStartupInfo=NULL, lpProcessInformation=NULL):
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
    if not isinstance(lpStartupInfo, STARTUPINFO) and not isinstance(lpStartupInfo, STARTUPINFOEX):
        lpStartupInfo              = STARTUPINFO()
        lpStartupInfo.cb           = sizeof(STARTUPINFO)
        lpStartupInfo.lpReserved   = 0
        lpStartupInfo.lpDesktop    = 0
        lpStartupInfo.lpTitle      = 0
        lpStartupInfo.dwFlags      = 0
        lpStartupInfo.cbReserved2  = 0
        lpStartupInfo.lpReserved2  = 0
    if not isinstance(lpProcessInformation, PROCESS_INFORMATION):
        lpProcessInformation              = PROCESS_INFORMATION()
        lpProcessInformation.hProcess     = -1
        lpProcessInformation.hThread      = -1
        lpProcessInformation.dwProcessId  = 0
        lpProcessInformation.dwThreadId   = 0
    success = ctypes.windll.kernel32.CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return lpProcessInformation

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
    hProcess = ctypes.windll.kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return hProcess

# HANDLE WINAPI OpenThread(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwThreadId
# );
def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    hThread = ctypes.windll.kernel32.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId)
    if hThread == NULL:
        raise ctypes.WinError()
    return hThread

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
    return lpBuffer

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
    return hThread, dwThreadId.value

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
def CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent):
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
    return dict(lpContext)
##    return lpContext

# BOOL WINAPI SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const CONTEXT* lpContext
# );
def SetThreadContext(hThread, lpContext):
    if not isinstance(lpContext, CONTEXT):
        lpContext = CONTEXT(**lpContext)
    success = ctypes.windll.kernel32.SetThreadContext(hThread, ctypes.byref(lpContext))
    if success == FALSE:
        raise ctypes.WinError()

# HANDLE WINAPI CreateToolhelp32Snapshot(
#   __in  DWORD dwFlags,
#   __in  DWORD th32ProcessID
# );
def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    retval = ctypes.windll.kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if retval == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return retval

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

#--- ntdll.dll ----------------------------------------------------------------

# NTSYSAPI NTSTATUS NTAPI NtSystemDebugControl(
#   IN SYSDBG_COMMAND Command,
#   IN PVOID InputBuffer OPTIONAL,
#   IN ULONG InputBufferLength,
#   OUT PVOID OutputBuffer OPTIONAL,
#   IN ULONG OutputBufferLength,
#   OUT PULONG ReturnLength OPTIONAL
# );
def NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength):
    if InputBufferLength is None:
        if InputBuffer == NULL:
            InputBufferLength = 0
        else:
            InputBufferLength = sizeof(InputBuffer)
    if OutputBufferLength is None:
        if OutputBuffer == NULL:
            OutputBufferLength = 0
        else:
            OutputBufferLength = sizeof(OutputBuffer)
    if InputBuffer != NULL:
        InputBuffer = ctypes.byref(InputBuffer)
    if OutputBuffer != NULL:
        OutputBuffer = ctypes.byref(OutputBuffer)
    if ReturnLength != NULL:
        ReturnLength = ctypes.byref(ULONG(ReturnLength))
    ntstatus = ctypes.windll.ntdll.NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength)
    # TODO this function should not return the ntstatus
    # instead it should allocate it's own memory when possible
    # and return the data as a python object
#    if ntstatus != 0:
#        raise ctypes.WinError(ntstatus ^ 0xFFFFFFFF)
    return ntstatus
ZwSystemDebugControl = NtSystemDebugControl

# NTSTATUS WINAPI NtQueryInformationProcess(
#   __in       HANDLE ProcessHandle,
#   __in       PROCESSINFOCLASS ProcessInformationClass,
#   __out      PVOID ProcessInformation,
#   __in       ULONG ProcessInformationLength,
#   __out_opt  PULONG ReturnLength
# );
def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformationLength = None):
    if ProcessInformationLength is not None:
        ProcessInformation = ctypes.create_string_buffer("", ProcessInformationLength)
    else:
        if   ProcessInformationClass == ProcessBasicInformation:
            ProcessInformation = PROCESS_BASIC_INFORMATION()
            ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION)
        elif ProcessInformationClass == ProcessImageFileName:
            unicode_buffer = ctypes.create_unicode_buffer(u"", 0x1000)
            ProcessInformation = UNICODE_STRING(0, 0x1000, ctypes.addressof(unicode_buffer))
            ProcessInformationLength = sizeof(UNICODE_STRING)
        elif ProcessInformationClass in (ProcessDebugPort, ProcessWow64Information, ProcessWx86Information, ProcessHandleCount, ProcessPriorityBoost):
            ProcessInformation = DWORD()
            ProcessInformationLength = sizeof(DWORD)
        else:
            raise Exception, "Unknown ProcessInformationClass, use an explicit ProcessInformationLength value instead"
    ReturnLength = ULONG(0)
    ntstatus = ctypes.windll.ntdll.NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ctypes.byref(ProcessInformation), ProcessInformationLength, ctypes.byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    if   ProcessInformationClass == ProcessBasicInformation:
        retval = ProcessInformation
    elif ProcessInformationClass in (ProcessDebugPort, ProcessWow64Information, ProcessWx86Information, ProcessHandleCount, ProcessPriorityBoost):
        retval = ProcessInformation.value
    elif ProcessInformationClass == ProcessImageFileName:
        vptr = ctypes.c_void_p(ProcessInformation.Buffer)
        cptr = ctypes.cast( vptr, ctypes.c_wchar * ProcessInformation.Length )
        retval = cptr.contents.raw
    else:
        retval = ProcessInformation.raw[:ReturnLength.value]
    return retval
ZwQueryInformationProcess = NtQueryInformationProcess

# NTSTATUS WINAPI NtQueryInformationThread(
#   __in       HANDLE ThreadHandle,
#   __in       THREADINFOCLASS ThreadInformationClass,
#   __out      PVOID ThreadInformation,
#   __in       ULONG ThreadInformationLength,
#   __out_opt  PULONG ReturnLength
# );
def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformationLength = None):
    if ThreadInformationLength is not None:
        ThreadInformation = ctypes.create_string_buffer("", ThreadInformationLength)
    else:
        if   ThreadInformationClass == ThreadBasicInformation:
            ThreadInformation = THREAD_BASIC_INFORMATION()
            ThreadInformationLength = sizeof(THREAD_BASIC_INFORMATION)
        elif ThreadInformationClass in (ThreadQuerySetWin32StartAddress, ThreadAmILastThread, ThreadPriorityBoost, ThreadHideFromDebugger):
            ThreadInformation = DWORD()
            ThreadInformationLength = sizeof(DWORD)
        elif ThreadInformationClass == ThreadPerformanceCount:
            ThreadInformation = LONGLONG()  # LARGE_INTEGER
            ThreadInformationLength = sizeof(LONGLONG)
        else:
            raise Exception, "Unknown ThreadInformationClass, use an explicit ThreadInformationLength value instead"
    ReturnLength = ULONG(0)
    ntstatus = ctypes.windll.ntdll.NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ctypes.byref(ThreadInformation), ThreadInformationLength, ctypes.byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    if   ThreadInformationClass == ThreadBasicInformation:
        retval = ThreadInformation
    elif ThreadInformationClass in (ThreadQuerySetWin32StartAddress, ThreadAmILastThread, ThreadPriorityBoost, ThreadHideFromDebugger):
        retval = ThreadInformation.value
    elif ThreadInformationClass == ThreadPerformanceCount:
        retval = ThreadInformation.value
    else:
        retval = ThreadInformation.raw[:ReturnLength.value]
    return retval
ZwQueryInformationThread = NtQueryInformationThread

# NTSTATUS
#   NtQueryInformationFile(
#     IN HANDLE  FileHandle,
#     OUT PIO_STATUS_BLOCK  IoStatusBlock,
#     OUT PVOID  FileInformation,
#     IN ULONG  Length,
#     IN FILE_INFORMATION_CLASS  FileInformationClass
#     );
def NtQueryInformationFile(FileHandle, FileInformationClass, FileInformation, Length):
    IoStatusBlock = IO_STATUS_BLOCK()
    status = NtQueryInformationFile(FileHandle, ctypes.byref(IoStatusBlock), ctypes.byref(FileInformation), Length, FileInformationClass)
    if status != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    return IoStatusBlock.Information
ZwQueryInformationFile = NtQueryInformationFile

#--- advapi32.dll -------------------------------------------------------------

# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess):
    TokenHandle = DWORD(0)
    success = ctypes.windll.advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))
    if success == FALSE:
        raise ctypes.WinError()
    return TokenHandle.value

# BOOL WINAPI OpenThreadToken(
#   __in   HANDLE ThreadHandle,
#   __in   DWORD DesiredAccess,
#   __in   BOOL OpenAsSelf,
#   __out  PHANDLE TokenHandle
# );
def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf = True):
    if OpenAsSelf:
        OpenAsSelf = TRUE
    else:
        OpenAsSelf = FALSE
    TokenHandle = DWORD(0)
    success = ctypes.windll.advapi32.OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, ctypes.byref(TokenHandle))
    if success == FALSE:
        raise ctypes.WinError()
    return TokenHandle.value

# BOOL WINAPI LookupPrivilegeValue(
#   __in_opt  LPCTSTR lpSystemName,
#   __in      LPCTSTR lpName,
#   __out     PLUID lpLuid
# );
def LookupPrivilegeValue(lpSystemName, lpName):
    if lpSystemName != NULL:
        lpSystemName = ctypes.c_char_p(lpSystemName)
    lpName       = ctypes.create_string_buffer(lpName)
    lpLuid       = LUID()
    success = ctypes.windll.advapi32.LookupPrivilegeValueA(lpSystemName, ctypes.byref(lpName), ctypes.byref(lpLuid))
    if success == FALSE:
        raise ctypes.WinError()
    return lpLuid

# BOOL WINAPI LookupPrivilegeName(
#   __in_opt   LPCTSTR lpSystemName,
#   __in       PLUID lpLuid,
#   __out_opt  LPTSTR lpName,
#   __inout    LPDWORD cchName
# );
def LookupPrivilegeName(lpSystemName, lpLuid):
    if lpSystemName != NULL:
        lpSystemName = ctypes.c_char_p(lpSystemName)
    cchName = DWORD(0)
    success = ctypes.windll.advapi32.LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), NULL, ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
    lpName = ctypes.create_string_buffer("", cchName.value)
    success = ctypes.windll.advapi32.LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), ctypes.byref(lpName), ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
    return str(lpName)#[:cchName.value]

# BOOL WINAPI AdjustTokenPrivileges(
#   __in       HANDLE TokenHandle,
#   __in       BOOL DisableAllPrivileges,
#   __in_opt   PTOKEN_PRIVILEGES NewState,
#   __in       DWORD BufferLength,
#   __out_opt  PTOKEN_PRIVILEGES PreviousState,
#   __out_opt  PDWORD ReturnLength
# );
def AdjustTokenPrivileges(TokenHandle, NewState = ()):
    #
    # I don't know how to allocate variable sized structures in ctypes :(
    # so this hack will work by using always TOKEN_PRIVILEGES of one element
    # and calling the API many times. This also means the PreviousState
    # parameter won't be supported yet as it's too much hassle. In a future
    # version I look forward to implementing this function correctly.
    #
    if not NewState:
        success = ctypes.windll.advapi32.AdjustTokenPrivileges(TokenHandle, TRUE, NULL, 0, NULL, 0)
        if success == FALSE:
            raise ctypes.WinError()
    else:
        success = True
        for (privilege, enabled) in NewState:
            if not isinstance(privilege, LUID):
                privilege = LookupPrivilegeValue(NULL, privilege)
            if enabled == True:
                flags = SE_PRIVILEGE_ENABLED
            elif enabled == False:
                flags = SE_PRIVILEGE_REMOVED
            elif enabled == None:
                flags = 0
            else:
                flags = enabled
            laa = LUID_AND_ATTRIBUTES(privilege, flags)
            tp  = TOKEN_PRIVILEGES(1, laa)
            success = ctypes.windll.advapi32.AdjustTokenPrivileges(TokenHandle, FALSE, ctypes.byref(tp), sizeof(tp), NULL, 0)
            if success == FALSE:
                raise ctypes.WinError()

#--- psapi.dll ----------------------------------------------------------------

# BOOL WINAPI EnumDeviceDrivers(
#   __out  LPVOID *lpImageBase,
#   __in   DWORD cb,
#   __out  LPDWORD lpcbNeeded
# );
def EnumDeviceDrivers():
    size       = 0x1000
    lpcbNeeded = DWORD(size)
    unit       = ctypes.sizeof(LPVOID)
    while 1:
        lpImageBase = (LPVOID * int(size / unit))()
        success = ctypes.windll.psapi.EnumDeviceDrivers(ctypes.byref(lpImageBase), lpcbNeeded, ctypes.byref(lpcbNeeded))
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lpImageBase[index] for index in xrange(0, int(needed / unit)) ]

# BOOL WINAPI EnumProcesses(
#   __out  DWORD *pProcessIds,
#   __in   DWORD cb,
#   __out  DWORD *pBytesReturned
# );
def EnumProcesses():
    size            = 0x1000
    cbBytesReturned = DWORD()
    unit            = ctypes.sizeof(DWORD)
    while 1:
        ProcessIds = (DWORD * int(size / unit))()
        cbBytesReturned.value = size
        success = ctypes.windll.psapi.EnumProcesses(ctypes.byref(ProcessIds), cbBytesReturned, ctypes.byref(cbBytesReturned))
        if success == FALSE:
            raise ctypes.WinError()
        returned = cbBytesReturned.value
        if returned < size:
            break
        size = size + 0x1000
    ProcessIdList = list()
    for ProcessId in ProcessIds:
        if ProcessId is None:
            break
        ProcessIdList.append(ProcessId)
    return ProcessIdList

# BOOL WINAPI EnumProcessModules(
#   __in   HANDLE hProcess,
#   __out  HMODULE *lphModule,
#   __in   DWORD cb,
#   __out  LPDWORD lpcbNeeded
# );
def EnumProcessModules(hProcess):
    size = 0x1000
    lpcbNeeded = DWORD(size)
    unit = ctypes.sizeof(HMODULE)
    while 1:
        lphModule = (HMODULE * int(size / unit))()
        success = ctypes.windll.psapi.EnumProcessModules(hProcess, ctypes.byref(lphModule), lpcbNeeded, ctypes.byref(lpcbNeeded))
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in xrange(0, int(needed / unit)) ]

# BOOL WINAPI EnumProcessModulesEx(
#   __in   HANDLE hProcess,
#   __out  HMODULE *lphModule,
#   __in   DWORD cb,
#   __out  LPDWORD lpcbNeeded,
#   __in   DWORD dwFilterFlag
# );
def EnumProcessModulesEx(hProcess, dwFilterFlag = LIST_MODULES_DEFAULT):
    size = 0x1000
    lpcbNeeded = DWORD(size)
    unit = ctypes.sizeof(HMODULE)
    while 1:
        lphModule = (HMODULE * int(size / unit))()
        success = ctypes.windll.psapi.EnumProcessModulesEx(hProcess, ctypes.byref(lphModule), lpcbNeeded, ctypes.byref(lpcbNeeded), dwFilterFlag)
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in xrange(0, int(needed / unit)) ]

# DWORD WINAPI GetDeviceDriverBaseName(
#   __in   LPVOID ImageBase,
#   __out  LPTSTR lpBaseName,
#   __in   DWORD nSize
# );
def GetDeviceDriverBaseNameA(ImageBase):
    nSize = MAX_PATH
    while 1:
        lpBaseName = ctypes.create_string_buffer("", nSize)
        nCopied = ctypes.windll.psapi.GetDeviceDriverBaseNameA(ImageBase, ctypes.byref(lpBaseName), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpBaseName.value
def GetDeviceDriverBaseNameW(ImageBase):
    nSize = MAX_PATH
    while 1:
        lpBaseName = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = ctypes.windll.psapi.GetDeviceDriverBaseNameW(ImageBase, ctypes.byref(lpBaseName), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpBaseName.value
GetDeviceDriverBaseName = GetDeviceDriverBaseNameA

# DWORD WINAPI GetDeviceDriverFileName(
#   __in   LPVOID ImageBase,
#   __out  LPTSTR lpFilename,
#   __in   DWORD nSize
# );
def GetDeviceDriverFileNameA(ImageBase):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_string_buffer("", nSize)
        nCopied = ctypes.windll.psapi.GetDeviceDriverFileNameA(ImageBase, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
def GetDeviceDriverFileNameW(ImageBase):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = ctypes.windll.psapi.GetDeviceDriverFileNameW(ImageBase, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetDeviceDriverFileName = GetDeviceDriverFileNameA

# DWORD WINAPI GetMappedFileName(
#   __in   HANDLE hProcess,
#   __in   LPVOID lpv,
#   __out  LPTSTR lpFilename,
#   __in   DWORD nSize
# );
def GetMappedFileNameA(hProcess, lpv):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_string_buffer("", nSize)
        nCopied = ctypes.windll.psapi.GetMappedFileNameA(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
def GetMappedFileNameW(hProcess, lpv):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = ctypes.windll.psapi.GetMappedFileNameW(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetMappedFileName = GetMappedFileNameA

# DWORD WINAPI GetModuleFileNameEx(
#   __in      HANDLE hProcess,
#   __in_opt  HMODULE hModule,
#   __out     LPTSTR lpFilename,
#   __in      DWORD nSize
# );
def GetModuleFileNameExA(hProcess, hModule):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_string_buffer("", nSize)
        nCopied = ctypes.windll.psapi.GetModuleFileNameExA(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
def GetModuleFileNameExW(hProcess, hModule):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = ctypes.windll.psapi.GetModuleFileNameExW(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetModuleFileNameEx = GetModuleFileNameExA

#BOOL WINAPI GetModuleInformation(
#   __in   HANDLE hProcess,
#   __in   HMODULE hModule,
#   __out  LPMODULEINFO lpmodinfo,
#   __in   DWORD cb
# );
def GetModuleInformation(hProcess, hModule, lpmodinfo = None):
    if lpmodinfo is None:
        lpmodinfo = MODULEINFO()
    success = ctypes.windll.psapi.GetModuleInformation(hProcess, hModule, ctypes.byref(lpmodinfo), ctypes.sizeof(lpmodinfo))
    if success == FALSE:
        raise ctypes.WinError()
    return lpmodinfo

# DWORD WINAPI GetProcessImageFileName(
#   __in   HANDLE hProcess,
#   __out  LPTSTR lpImageFileName,
#   __in   DWORD nSize
# );
def GetProcessImageFileNameA(hProcess):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_string_buffer("", nSize)
        nCopied = ctypes.windll.psapi.GetProcessImageFileNameA(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
def GetProcessImageFileNameW(hProcess):
    nSize = MAX_PATH
    while 1:
        lpFilename = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = ctypes.windll.psapi.GetProcessImageFileNameW(hProcess, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetProcessImageFileName = GetProcessImageFileNameA

#--- shlwapi.dll --------------------------------------------------------------

# LPTSTR PathAddBackslash(
#     LPTSTR lpszPath
# );
def PathAddBackslashA(lpszPath):
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathAddBackslashA(lpszPath)
    return lpszPath.value
def PathAddBackslashW(lpszPath):
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathAddBackslashW(lpszPath)
    return lpszPath.value
PathAddBackslash = PathAddBackslashA

# BOOL PathAddExtension(
#     LPTSTR pszPath,
#     LPCTSTR pszExtension
# );
def PathAddExtensionA(lpszPath, pszExtension = None):
    if pszExtension is None:
        pszExtension = NULL
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAddExtensionA(lpszPath, pszExtension)
    if success == FALSE:
        return None
    return lpszPath.value
def PathAddExtensionW(lpszPath, pszExtension = None):
    if pszExtension is None:
        pszExtension = NULL
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAddExtensionW(lpszPath, pszExtension)
    if success == FALSE:
        return None
    return lpszPath.value
PathAddExtension = PathAddExtensionA

# BOOL PathAppend(
#     LPTSTR pszPath,
#     LPCTSTR pszMore
# );
def PathAppendA(lpszPath, pszMore = None):
    if pszMore is None:
        pszMore = NULL
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAppendA(lpszPath, pszMore)
    if success == FALSE:
        return None
    return lpszPath.value
def PathAppendW(lpszPath, pszMore = None):
    if pszMore is None:
        pszMore = NULL
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAppendW(lpszPath, pszMore)
    if success == FALSE:
        return None
    return lpszPath.value
PathAppend = PathAppendA

# LPTSTR PathCombine(
#     LPTSTR lpszDest,
#     LPCTSTR lpszDir,
#     LPCTSTR lpszFile
# );
def PathCombineA(lpszDir, lpszFile):
    lpszDest = ctypes.create_string_buffer("", max(MAX_PATH, len(lpszDir) + len(lpszFile) + 1))
    retval = ctypes.windll.shlwapi.PathCombineA(lpszDest, lpszDir, lpszFile)
    if retval == NULL:
        return None
    return lpszDest.value
def PathCombineW(lpszDir, lpszFile):
    lpszDest = ctypes.create_unicode_buffer(u"", max(MAX_PATH, len(lpszDir) + len(lpszFile) + 1))
    retval = ctypes.windll.shlwapi.PathCombineW(lpszDest, lpszDir, lpszFile)
    if retval == NULL:
        return None
    return lpszDest.value
PathCombine = PathCombineA

# BOOL PathCanonicalize(
#     LPTSTR lpszDst,
#     LPCTSTR lpszSrc
# );
def PathCanonicalizeA(lpszSrc):
    lpszDst = ctypes.create_string_buffer("", MAX_PATH)
    success = ctypes.windll.shlwapi.PathCanonicalizeA(ctypes.byref(lpszDst), lpszSrc)
    if success == FALSE:
        raise ctypes.WinError()
    return lpszDst.value
def PathCanonicalizeW(lpszSrc):
    lpszDst = ctypes.create_unicode_buffer(u"", MAX_PATH)
    success = ctypes.windll.shlwapi.PathCanonicalizeW(ctypes.byref(lpszDst), lpszSrc)
    if success == FALSE:
        raise ctypes.WinError()
    return lpszDst.value
PathCanonicalize = PathCanonicalizeA

# BOOL PathFileExists(
#     LPCTSTR pszPath
# );
def PathFileExistsA(pszPath):
    return bool( ctypes.windll.shlwapi.PathFileExistsA(pszPath) )
def PathFileExistsW(pszPath):
    return bool( ctypes.windll.shlwapi.PathFileExistsW(pszPath) )
PathFileExists = PathFileExistsA

# LPTSTR PathFindExtension(
#     LPCTSTR pszPath
# );
def PathFindExtensionA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathExtension = ctypes.windll.shlwapi.PathFindExtensionA(pszPath)
    pszPathExtension = ctypes.c_void_p(pszPathExtension)
    pszPathExtension = ctypes.cast(pszPathExtension, ctypes.c_char_p)
    return pszPathExtension.value
def PathFindExtensionW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathExtension = ctypes.windll.shlwapi.PathFindExtensionW(pszPath)
    pszPathExtension = ctypes.c_void_p(pszPathExtension)
    pszPathExtension = ctypes.cast(pszPathExtension, ctypes.c_wchar_p)
    return pszPathExtension.value
PathFindExtension = PathFindExtensionA

# LPTSTR PathFindFileName(
#     LPCTSTR pszPath
# );
def PathFindFileNameA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathFilename = ctypes.windll.shlwapi.PathFindFileNameA(pszPath)
    pszPathFilename = ctypes.c_void_p(pszPathFilename)
    pszPathFilename = ctypes.cast(pszPathFilename, ctypes.c_char_p)
    return pszPathFilename.value
def PathFindFileNameW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathFilename = ctypes.windll.shlwapi.PathFindFileNameW(pszPath)
    pszPathFilename = ctypes.c_void_p(pszPathFilename)
    pszPathFilename = ctypes.cast(pszPathFilename, ctypes.c_wchar_p)
    return pszPathFilename.value
PathFindFileName = PathFindFileNameA

# LPTSTR PathFindNextComponent(
#     LPCTSTR pszPath
# );
def PathFindNextComponentA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathNext = ctypes.windll.shlwapi.PathFindNextComponentA(pszPath)
    pszPathNext = ctypes.c_void_p(pszPathNext)
    pszPathNext = ctypes.cast(pszPathNext, ctypes.c_char_p)
    return pszPathNext.value    # may return None
def PathFindNextComponentW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathNext = ctypes.windll.shlwapi.PathFindNextComponentW(pszPath)
    pszPathNext = ctypes.c_void_p(pszPathNext)
    pszPathNext = ctypes.cast(pszPathNext, ctypes.c_wchar_p)
    return pszPathNext.value    # may return None
PathFindNextComponent = PathFindNextComponentA

# BOOL PathFindOnPath(
#     LPTSTR pszFile,
#     LPCTSTR *ppszOtherDirs
# );
def PathFindOnPathA(pszFile, ppszOtherDirs = None):
    pszFile = ctypes.create_string_buffer(pszFile, MAX_PATH)
    if not ppszOtherDirs:
        ppszOtherDirs = NULL
    else:
        ppszArray = ""
        for pszOtherDirs in ppszOtherDirs:
            if pszOtherDirs:
                ppszArray = "%s%s\0" % (ppszArray, pszOtherDirs)
        ppszArray = ppszArray + "\0"
        ppszOtherDirs = ctypes.byref( ctypes.create_string_buffer(ppszArray) )
    success = ctypes.windll.shlwapi.PathFindOnPathA(pszFile, ppszOtherDirs)
    if success == FALSE:
        return None
    return pszFile.value
def PathFindOnPathW(pszFile, ppszOtherDirs = None):
    pszFile = ctypes.create_unicode_buffer(pszFile, MAX_PATH)
    if not ppszOtherDirs:
        ppszOtherDirs = NULL
    else:
        ppszArray = u""
        for pszOtherDirs in ppszOtherDirs:
            if pszOtherDirs:
                ppszArray = u"%s%s\0" % (ppszArray, pszOtherDirs)
        ppszArray = ppszArray + u"\0"
        ppszOtherDirs = ctypes.byref( ctypes.create_unicode_buffer(ppszArray) )
    success = ctypes.windll.shlwapi.PathFindOnPathW(pszFile, ppszOtherDirs)
    if success == FALSE:
        return None
    return pszFile.value
PathFindOnPath = PathFindOnPathA

# LPTSTR PathGetArgs(
#     LPCTSTR pszPath
# );
def PathGetArgsA(pszPath):
    pszPath = ctypes.windll.shlwapi.PathGetArgsA(pszPath)
    pszPath = ctypes.c_void_p(pszPath)
    pszPath = ctypes.cast(pszPath, ctypes.c_char_p)
    return pszPath.value
def PathGetArgsW(pszPath):
    pszPath = ctypes.windll.shlwapi.PathGetArgsW(pszPath)
    pszPath = ctypes.c_void_p(pszPath)
    pszPath = ctypes.cast(pszPath, ctypes.c_wchar_p)
    return pszPath.value
PathGetArgs = PathGetArgsA

# BOOL PathIsContentType(
#     LPCTSTR pszPath,
#     LPCTSTR pszContentType
# );
def PathIsContentTypeA(pszPath, pszContentType):
    return bool( ctypes.windll.shlwapi.PathIsContentTypeA(pszPath, pszContentType) )
def PathIsContentTypeW(pszPath, pszContentType):
    return bool( ctypes.windll.shlwapi.PathIsContentTypeW(pszPath, pszContentType) )
PathIsContentType = PathIsContentTypeA

# BOOL PathIsDirectory(
#     LPCTSTR pszPath
# );
def PathIsDirectoryA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryA(pszPath) )
def PathIsDirectoryW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryW(pszPath) )
PathIsDirectory = PathIsDirectoryA

# BOOL PathIsDirectoryEmpty(
#     LPCTSTR pszPath
# );
def PathIsDirectoryEmptyA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryEmptyA(pszPath) )
def PathIsDirectoryEmptyW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryEmptyW(pszPath) )
PathIsDirectoryEmpty = PathIsDirectoryEmptyA

# BOOL PathIsNetworkPath(
#     LPCTSTR pszPath
# );
def PathIsNetworkPathA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsNetworkPathA(pszPath) )
def PathIsNetworkPathW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsNetworkPathW(pszPath) )
PathIsNetworkPath = PathIsNetworkPathA

# BOOL PathIsRelative(
#     LPCTSTR lpszPath
# );
def PathIsRelativeA(lpszPath):
    return bool( ctypes.windll.shlwapi.PathIsRelativeA(lpszPath) )
def PathIsRelativeW(lpszPath):
    return bool( ctypes.windll.shlwapi.PathIsRelativeW(lpszPath) )
PathIsRelative = PathIsRelativeA

# BOOL PathIsRoot(
#     LPCTSTR pPath
# );
def PathIsRootA(pPath):
    return bool( ctypes.windll.shlwapi.PathIsRootA(pPath) )
def PathIsRootW(pPath):
    return bool( ctypes.windll.shlwapi.PathIsRootW(pPath) )
PathIsRoot = PathIsRootA

# BOOL PathIsSameRoot(
#     LPCTSTR pszPath1,
#     LPCTSTR pszPath2
# );
def PathIsSameRootA(pszPath1, pszPath2):
    return bool( ctypes.windll.shlwapi.PathIsSameRootA(pszPath1, pszPath2) )
def PathIsSameRootW(pszPath1, pszPath2):
    return bool( ctypes.windll.shlwapi.PathIsSameRootW(pszPath1, pszPath2) )
PathIsSameRoot = PathIsSameRootA

# BOOL PathIsUNC(
#     LPCTSTR pszPath
# );
def PathIsUNCA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsUNCA(pszPath) )
def PathIsUNCW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsUNCW(pszPath) )
PathIsUNC = PathIsUNCA

# XXX PathMakePretty turns filenames into all lowercase.
# I'm not sure how well that might work on Wine.

# BOOL PathMakePretty(
#     LPCTSTR pszPath
# );
def PathMakePrettyA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath)
    ctypes.windll.shlwapi.PathMakePrettyA(ctypes.byref(pszPath))
    return pszPath.value
def PathMakePrettyW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath)
    ctypes.windll.shlwapi.PathMakePrettyW(ctypes.byref(pszPath))
    return pszPath.value
PathMakePretty = PathMakePrettyA

# void PathRemoveArgs(
#     LPTSTR pszPath
# );
def PathRemoveArgsA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveArgsA(pszPath)
    return pszPath.value
def PathRemoveArgsW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveArgsW(pszPath)
    return pszPath.value
PathRemoveArgs = PathRemoveArgsA

# void PathRemoveBackslash(
#     LPTSTR pszPath
# );
def PathRemoveBackslashA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveBackslashA(pszPath)
    return pszPath.value
def PathRemoveBackslashW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveBackslashW(pszPath)
    return pszPath.value
PathRemoveBackslash = PathRemoveBackslashA

# void PathRemoveExtension(
#     LPTSTR pszPath
# );
def PathRemoveExtensionA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveExtensionA(pszPath)
    return pszPath.value
def PathRemoveExtensionW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveExtensionW(pszPath)
    return pszPath.value
PathRemoveExtension = PathRemoveExtensionA

# void PathRemoveFileSpec(
#     LPTSTR pszPath
# );
def PathRemoveFileSpecA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveFileSpecA(pszPath)
    return pszPath.value
def PathRemoveFileSpecW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveFileSpecW(pszPath)
    return pszPath.value
PathRemoveFileSpec = PathRemoveFileSpecA

# BOOL PathRenameExtension(
#     LPTSTR pszPath,
#     LPCTSTR pszExt
# );
def PathRenameExtensionA(pszPath, pszExt):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathRenameExtensionA(pszPath, pszExt)
    if success == FALSE:
        return None
    return pszPath.value
def PathRenameExtensionW(pszPath, pszExt):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathRenameExtensionW(pszPath, pszExt)
    if success == FALSE:
        return None
    return pszPath.value
PathRenameExtension = PathRenameExtensionA

# BOOL PathUnExpandEnvStrings(
#     LPCTSTR pszPath,
#     LPTSTR pszBuf,
#     UINT cchBuf
# );
def PathUnExpandEnvStringsA(pszPath):
    pszBuf = ctypes.create_string_buffer("", MAX_PATH)
    cchBuf = MAX_PATH
    ctypes.windll.shlwapi.PathUnExpandEnvStringsA(ctypes.byref(pszPath), ctypes.byref(pszBuf), cchBuf)
    return pszBuf.value
def PathUnExpandEnvStringsW(pszPath):
    pszBuf = ctypes.create_unicode_buffer(u"", MAX_PATH)
    cchBuf = MAX_PATH
    ctypes.windll.shlwapi.PathUnExpandEnvStringsW(ctypes.byref(pszPath), ctypes.byref(pszBuf), cchBuf)
    return pszBuf.value
