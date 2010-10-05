# Copyright (c) 2009-2010, Mario Vilas
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
Wrapper for advapi32.dll in ctypes.
"""

__revision__ = "$Id$"

from defines import *
from kernel32 import *

# XXX TODO
# + add registry APIs
# + add service control manager APIs

#--- Constants ----------------------------------------------------------------

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

LOGON_WITH_PROFILE              = 0x00000001
LOGON_NETCREDENTIALS_ONLY       = 0x00000002

HKEY_CLASSES_ROOT       = 0x80000000
HKEY_CURRENT_USER       = 0x80000001
HKEY_LOCAL_MACHINE      = 0x80000002
HKEY_USERS              = 0x80000003
HKEY_PERFORMANCE_DATA   = 0x80000004
HKEY_CURRENT_CONFIG     = 0x80000005

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

PLUID = POINTER(LUID)

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

PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

#--- WAITCHAIN_NODE_INFO structure and types ----------------------------------

WCT_MAX_NODE_COUNT       = 16
WCT_OBJNAME_LENGTH       = 128
WCT_ASYNC_OPEN_FLAG      = 0x1
WCTP_OPEN_ALL_FLAGS      = WCT_ASYNC_OPEN_FLAG
WCT_OUT_OF_PROC_FLAG     = 0x1
WCT_OUT_OF_PROC_COM_FLAG = 0x2
WCT_OUT_OF_PROC_CS_FLAG  = 0x4
WCTP_GETINFO_ALL_FLAGS   = WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG | WCT_OUT_OF_PROC_CS_FLAG

HWCT = LPVOID

# typedef enum _WCT_OBJECT_TYPE
# {
#     WctCriticalSectionType = 1,
#     WctSendMessageType,
#     WctMutexType,
#     WctAlpcType,
#     WctComType,
#     WctThreadWaitType,
#     WctProcessWaitType,
#     WctThreadType,
#     WctComActivationType,
#     WctUnknownType,
#     WctMaxType
# } WCT_OBJECT_TYPE;

WCT_OBJECT_TYPE         = DWORD

WctCriticalSectionType  = 1
WctSendMessageType      = 2
WctMutexType            = 3
WctAlpcType             = 4
WctComType              = 5
WctThreadWaitType       = 6
WctProcessWaitType      = 7
WctThreadType           = 8
WctComActivationType    = 9
WctUnknownType          = 10
WctMaxType              = 11

# typedef enum _WCT_OBJECT_STATUS
# {
#     WctStatusNoAccess = 1,            // ACCESS_DENIED for this object
#     WctStatusRunning,                 // Thread status
#     WctStatusBlocked,                 // Thread status
#     WctStatusPidOnly,                 // Thread status
#     WctStatusPidOnlyRpcss,            // Thread status
#     WctStatusOwned,                   // Dispatcher object status
#     WctStatusNotOwned,                // Dispatcher object status
#     WctStatusAbandoned,               // Dispatcher object status
#     WctStatusUnknown,                 // All objects
#     WctStatusError,                   // All objects
#     WctStatusMax
# } WCT_OBJECT_STATUS;

WCT_OBJECT_STATUS       = DWORD

WctStatusNoAccess       = 1             # ACCESS_DENIED for this object
WctStatusRunning        = 2             # Thread status
WctStatusBlocked        = 3             # Thread status
WctStatusPidOnly        = 4             # Thread status
WctStatusPidOnlyRpcss   = 5             # Thread status
WctStatusOwned          = 6             # Dispatcher object status
WctStatusNotOwned       = 7             # Dispatcher object status
WctStatusAbandoned      = 8             # Dispatcher object status
WctStatusUnknown        = 9             # All objects
WctStatusError          = 10            # All objects
WctStatusMax            = 11

# typedef struct _WAITCHAIN_NODE_INFO {
#   WCT_OBJECT_TYPE   ObjectType;
#   WCT_OBJECT_STATUS ObjectStatus;
#   union {
#     struct {
#       WCHAR ObjectName[WCT_OBJNAME_LENGTH];
#       LARGE_INTEGER Timeout;
#       BOOL Alertable;
#     } LockObject;
#     struct {
#       DWORD ProcessId;
#       DWORD ThreadId;
#       DWORD WaitTime;
#       DWORD ContextSwitches;
#     } ThreadObject;
#   } ;
# }WAITCHAIN_NODE_INFO, *PWAITCHAIN_NODE_INFO;

class _WAITCHAIN_NODE_INFO_STRUCT_1(Structure):
    _fields_ = [
        ("ObjectName",      WCHAR * WCT_OBJNAME_LENGTH),
        ("Timeout",         LONGLONG), # LARGE_INTEGER
        ("Alertable",       BOOL),
    ]

class _WAITCHAIN_NODE_INFO_STRUCT_2(Structure):
    _fields_ = [
        ("ProcessId",       DWORD),
        ("ThreadId",        DWORD),
        ("WaitTime",        DWORD),
        ("ContextSwitches", DWORD),
    ]

class _WAITCHAIN_NODE_INFO_UNION(Union):
    _fields_ = [
        ("LockObject",      _WAITCHAIN_NODE_INFO_STRUCT_1),
        ("ThreadObject",    _WAITCHAIN_NODE_INFO_STRUCT_2),
    ]

class WAITCHAIN_NODE_INFO(Structure):
    _fields_ = [
        ("ObjectType",      WCT_OBJECT_TYPE),
        ("ObjectStatus",    WCT_OBJECT_STATUS),
        ("u",               _WAITCHAIN_NODE_INFO_UNION),
    ]

PWAITCHAIN_NODE_INFO = POINTER(WAITCHAIN_NODE_INFO)

#--- Privilege dropping -------------------------------------------------------

SAFER_LEVEL_HANDLE = HANDLE

SAFER_SCOPEID_MACHINE = 1
SAFER_SCOPEID_USER    = 2

SAFER_LEVEL_OPEN = 1

SAFER_LEVELID_DISALLOWED   = 0x00000
SAFER_LEVELID_UNTRUSTED    = 0x01000
SAFER_LEVELID_CONSTRAINED  = 0x10000
SAFER_LEVELID_NORMALUSER   = 0x20000
SAFER_LEVELID_FULLYTRUSTED = 0x40000

SAFER_POLICY_INFO_CLASS = DWORD
SaferPolicyLevelList = 1
SaferPolicyEnableTransparentEnforcement = 2
SaferPolicyDefaultLevel = 3
SaferPolicyEvaluateUserScope = 4
SaferPolicyScopeFlags = 5

SAFER_TOKEN_NULL_IF_EQUAL = 1
SAFER_TOKEN_COMPARE_ONLY  = 2
SAFER_TOKEN_MAKE_INERT    = 4
SAFER_TOKEN_WANT_FLAGS    = 8
SAFER_TOKEN_MASK          = 15

#--- Handle wrappers ----------------------------------------------------------

# XXX maybe add functions related to the tokens here?
class TokenHandle (Handle):
    """
    Access token handle.

    @see: L{Handle}
    """
    pass

class SaferLevelHandle (Handle):
    """
    Safer level handle.
    
    @see: U{http://msdn.microsoft.com/en-us/library/ms722425(VS.85).aspx}
    """

    @property
    def _as_parameter_(self):
        return SAFER_LEVEL_HANDLE(self.value)

    @staticmethod
    def from_param(value):
        return SAFER_LEVEL_HANDLE(self.value)

    def close(self):
        if self.bOwnership and self.value not in (None, INVALID_HANDLE_VALUE):
            if Handle.__bLeakDetection:     # XXX DEBUG
                print "CLOSE HANDLE (%d) %r" % (self.value, self)
            try:
                SaferCloseLevel(self.value)
            finally:
                self.value = None

    def dup(self):
        raise NotImplementedError

    def wait(self, dwMilliseconds = None):
        raise NotImplementedError

#--- advapi32.dll -------------------------------------------------------------

# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess):
    _OpenProcessToken = windll.advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
    _OpenProcessToken.restype = bool
    _OpenProcessToken.errcheck = RaiseIfZero

    tokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(tokenHandle))
    return TokenHandle(tokenHandle.value)

# BOOL WINAPI OpenThreadToken(
#   __in   HANDLE ThreadHandle,
#   __in   DWORD DesiredAccess,
#   __in   BOOL OpenAsSelf,
#   __out  PHANDLE TokenHandle
# );
def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf = True):
    _OpenThreadToken = windll.advapi32.OpenThreadToken
    _OpenThreadToken.argtypes = [HANDLE, DWORD, BOOL, PHANDLE]
    _OpenThreadToken.restype = bool
    _OpenThreadToken.errcheck = RaiseIfZero

    tokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, ctypes.byref(tokenHandle))
    return TokenHandle(tokenHandle.value)

# BOOL WINAPI LookupPrivilegeValue(
#   __in_opt  LPCTSTR lpSystemName,
#   __in      LPCTSTR lpName,
#   __out     PLUID lpLuid
# );
def LookupPrivilegeValueA(lpSystemName, lpName):
    _LookupPrivilegeValueA = windll.advapi32.LookupPrivilegeValueA
    _LookupPrivilegeValueA.argtypes = [LPSTR, LPSTR, PLUID]
    _LookupPrivilegeValueA.restype = bool
    _LookupPrivilegeValueA.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueA(lpSystemName, lpName, ctypes.byref(lpLuid))
    return lpLuid

def LookupPrivilegeValueW(lpSystemName, lpName):
    _LookupPrivilegeValueW = windll.advapi32.LookupPrivilegeValueW
    _LookupPrivilegeValueW.argtypes = [LPWSTR, LPWSTR, PLUID]
    _LookupPrivilegeValueW.restype = bool
    _LookupPrivilegeValueW.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))
    return lpLuid

LookupPrivilegeValue = GuessStringType(LookupPrivilegeValueA, LookupPrivilegeValueW)

# BOOL WINAPI LookupPrivilegeName(
#   __in_opt   LPCTSTR lpSystemName,
#   __in       PLUID lpLuid,
#   __out_opt  LPTSTR lpName,
#   __inout    LPDWORD cchName
# );

def LookupPrivilegeNameA(lpSystemName, lpLuid):
    _LookupPrivilegeNameA = windll.advapi32.LookupPrivilegeNameA
    _LookupPrivilegeNameA.argtypes = [LPSTR, PLUID, LPSTR, LPDWORD]
    _LookupPrivilegeNameA.restype = bool
    _LookupPrivilegeNameA.errcheck = RaiseIfZero

    cchName = DWORD(0)
    _LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), NULL, ctypes.byref(cchName))
    lpName = ctypes.create_string_buffer("", cchName.value)
    _LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), ctypes.byref(lpName), ctypes.byref(cchName))
    return lpName.value

def LookupPrivilegeNameW(lpSystemName, lpLuid):
    _LookupPrivilegeNameW = windll.advapi32.LookupPrivilegeNameW
    _LookupPrivilegeNameW.argtypes = [LPWSTR, PLUID, LPWSTR, LPDWORD]
    _LookupPrivilegeNameW.restype = bool
    _LookupPrivilegeNameW.errcheck = RaiseIfZero

    cchName = DWORD(0)
    _LookupPrivilegeNameW(lpSystemName, ctypes.byref(lpLuid), NULL, ctypes.byref(cchName))
    lpName = ctypes.create_unicode_buffer(u"", cchName.value)
    _LookupPrivilegeNameW(lpSystemName, ctypes.byref(lpLuid), ctypes.byref(lpName), ctypes.byref(cchName))
    return lpName.value

LookupPrivilegeName = GuessStringType(LookupPrivilegeNameA, LookupPrivilegeNameW)

# BOOL WINAPI AdjustTokenPrivileges(
#   __in       HANDLE TokenHandle,
#   __in       BOOL DisableAllPrivileges,
#   __in_opt   PTOKEN_PRIVILEGES NewState,
#   __in       DWORD BufferLength,
#   __out_opt  PTOKEN_PRIVILEGES PreviousState,
#   __out_opt  PDWORD ReturnLength
# );
def AdjustTokenPrivileges(TokenHandle, NewState = ()):
    _AdjustTokenPrivileges = windll.advapi32.AdjustTokenPrivileges
    _AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, LPVOID, DWORD, LPVOID, LPVOID]
    _AdjustTokenPrivileges.restype = bool
    _AdjustTokenPrivileges.errcheck = RaiseIfZero
    #
    # I don't know how to allocate variable sized structures in ctypes :(
    # so this hack will work by using always TOKEN_PRIVILEGES of one element
    # and calling the API many times. This also means the PreviousState
    # parameter won't be supported yet as it's too much hassle. In a future
    # version I look forward to implementing this function correctly.
    #
    if not NewState:
        _AdjustTokenPrivileges(TokenHandle, TRUE, NULL, 0, NULL, NULL)
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
            _AdjustTokenPrivileges(TokenHandle, FALSE, ctypes.byref(tp), sizeof(tp), NULL, NULL)

# BOOL WINAPI CreateProcessWithLogonW(
#   __in         LPCWSTR lpUsername,
#   __in_opt     LPCWSTR lpDomain,
#   __in         LPCWSTR lpPassword,
#   __in         DWORD dwLogonFlags,
#   __in_opt     LPCWSTR lpApplicationName,
#   __inout_opt  LPWSTR lpCommandLine,
#   __in         DWORD dwCreationFlags,
#   __in_opt     LPVOID lpEnvironment,
#   __in_opt     LPCWSTR lpCurrentDirectory,
#   __in         LPSTARTUPINFOW lpStartupInfo,
#   __out        LPPROCESS_INFORMATION lpProcessInfo
# );
def CreateProcessWithLogonW(lpUsername = None, lpDomain = None, lpPassword = None, dwLogonFlags = 0, lpApplicationName = None, lpCommandLine = None, dwCreationFlags = 0, lpEnvironment = None, lpCurrentDirectory = None, lpStartupInfo = None):
    _CreateProcessWithLogonW = windll.advapi32.CreateProcessWithLogonW
    _CreateProcessWithLogonW.argtypes = [LPWSTR, LPWSTR, LPWSTR, DWORD, LPWSTR, LPWSTR, DWORD, LPVOID, LPWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION]
    _CreateProcessWithLogonW.restype = bool
    _CreateProcessWithLogonW.errcheck = RaiseIfZero

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
    _CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

CreateProcessWithLogonA = MakeANSIVersion(CreateProcessWithLogonW)
CreateProcessWithLogon = CreateProcessWithLogonA

# BOOL WINAPI CreateProcessWithTokenW(
#   __in         HANDLE hToken,
#   __in         DWORD dwLogonFlags,
#   __in_opt     LPCWSTR lpApplicationName,
#   __inout_opt  LPWSTR lpCommandLine,
#   __in         DWORD dwCreationFlags,
#   __in_opt     LPVOID lpEnvironment,
#   __in_opt     LPCWSTR lpCurrentDirectory,
#   __in         LPSTARTUPINFOW lpStartupInfo,
#   __out        LPPROCESS_INFORMATION lpProcessInfo
# );
def CreateProcessWithTokenW(hToken = None, dwLogonFlags = 0, lpApplicationName = None, lpCommandLine = None, dwCreationFlags = 0, lpEnvironment = None, lpCurrentDirectory = None, lpStartupInfo = None):
    _CreateProcessWithTokenW = windll.advapi32.CreateProcessWithTokenW
    _CreateProcessWithTokenW.argtypes = [HANDLE, DWORD, LPWSTR, LPWSTR, DWORD, LPVOID, LPWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION]
    _CreateProcessWithTokenW.restype = bool
    _CreateProcessWithTokenW.errcheck = RaiseIfZero

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
    _CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    return ProcessInformation(lpProcessInformation)

CreateProcessWithTokenA = MakeANSIVersion(CreateProcessWithTokenW)
CreateProcessWithToken = CreateProcessWithTokenA

# VOID CALLBACK WaitChainCallback(
#     HWCT WctHandle,
#     DWORD_PTR Context,
#     DWORD CallbackStatus,
#     LPDWORD NodeCount,
#     PWAITCHAIN_NODE_INFO NodeInfoArray,
#     LPBOOL IsCycle
# );
PWAITCHAINCALLBACK = WINFUNCTYPE(HWCT, DWORD_PTR, DWORD, LPDWORD, PWAITCHAIN_NODE_INFO, LPBOOL)

# HWCT WINAPI OpenThreadWaitChainSession(
#   __in      DWORD Flags,
#   __in_opt  PWAITCHAINCALLBACK callback
# );
def OpenThreadWaitChainSession(Flags = 0, callback = None):
    _OpenThreadWaitChainSession = windll.advapi32.OpenThreadWaitChainSession
    _OpenThreadWaitChainSession.argtypes = [DWORD, PVOID]
    _OpenThreadWaitChainSession.restype  = HWCT
    _OpenThreadWaitChainSession.errcheck = RaiseIfZero
    if callback is not None:
        callback = PWAITCHAINCALLBACK(callback)
    return _OpenThreadWaitChainSession(Flags, callback)

# BOOL WINAPI GetThreadWaitChain(
#   __in      HWCT WctHandle,
#   __in_opt  DWORD_PTR Context,
#   __in      DWORD Flags,
#   __in      DWORD ThreadId,
#   __inout   LPDWORD NodeCount,
#   __out     PWAITCHAIN_NODE_INFO NodeInfoArray,
#   __out     LPBOOL IsCycle
# );
def GetThreadWaitChain(WctHandle, Context, Flags, ThreadId):
    _GetThreadWaitChain = windll.advapi32.GetThreadWaitChain
    _GetThreadWaitChain.argtypes = [HWCT, DWORD_PTR, DWORD, DWORD, LPDWORD, PWAITCHAIN_NODE_INFO, LPBOOL]
    _GetThreadWaitChain.restype  = BOOL

    NodeCount     = DWORD(WCT_MAX_NODE_COUNT)
    NodeInfoArray = (WAITCHAIN_NODE_INFO * WCT_MAX_NODE_COUNT)()
    IsCycle       = BOOL(FALSE)
    _GetThreadWaitChain(WctHandle, Context, Flags, ThreadId, ctypes.byref(NodeCount), ctypes.cast(ctypes.pointer(NodeInfoArray), PWAITCHAIN_NODE_INFO), ctypes.byref(IsCycle))
    NodeInfoArray = [ NodeInfoArray[index] for index in xrange(0, NodeCount.value) ]
    IsCycle       = bool(IsCycle)
    return NodeInfoArray, IsCycle

# VOID WINAPI CloseThreadWaitChainSession(
#   __in  HWCT WctHandle
# );
def CloseThreadWaitChainSession(WctHandle):
    _CloseThreadWaitChainSession = windll.advapi32.CloseThreadWaitChainSession
    _CloseThreadWaitChainSession.argtypes = [HWCT]
    _CloseThreadWaitChainSession(WctHandle)

# BOOL WINAPI SaferCreateLevel(
#   __in        DWORD dwScopeId,
#   __in        DWORD dwLevelId,
#   __in        DWORD OpenFlags,
#   __out       SAFER_LEVEL_HANDLE *pLevelHandle,
#   __reserved  LPVOID lpReserved
# );
def SaferCreateLevel(dwScopeId=SAFER_SCOPEID_USER, dwLevelId=SAFER_LEVELID_NORMALUSER, OpenFlags=SAFER_LEVEL_OPEN):
    _SaferCreateLevel = windll.advapi32.SaferCreateLevel
    _SaferCreateLevel.argtypes = [DWORD, DWORD, DWORD, POINTER(SAFER_LEVEL_HANDLE), LPVOID]
    _SaferCreateLevel.restype  = BOOL
    _SaferCreateLevel.errcheck = RaiseIfZero

    hLevelHandle = SAFER_LEVEL_HANDLE(INVALID_HANDLE_VALUE)
    _SaferCreateLevel(dwScopeId, dwLevelId, OpenFlags, ctypes.byref(hLevelHandle), None)
    return SaferLevelHandle(hLevelHandle.value)

# BOOL WINAPI SaferIdentifyLevel(
#   __in        DWORD dwNumProperties,
#   __in_opt    PSAFER_CODE_PROPERTIES pCodeProperties,
#   __out       SAFER_LEVEL_HANDLE *pLevelHandle,
#   __reserved  LPVOID lpReserved
# );

# XXX TODO

# BOOL WINAPI SaferComputeTokenFromLevel(
#   __in         SAFER_LEVEL_HANDLE LevelHandle,
#   __in_opt     HANDLE InAccessToken,
#   __out        PHANDLE OutAccessToken,
#   __in         DWORD dwFlags,
#   __inout_opt  LPVOID lpReserved
# );
def SaferComputeTokenFromLevel(LevelHandle, InAccessToken=None, dwFlags=0, lpReserved=None):
    _SaferComputeTokenFromLevel = windll.advapi32.SaferCreateLevel
    _SaferComputeTokenFromLevel.argtypes = [SAFER_LEVEL_HANDLE, HANDLE, PHANDLE, DWORD, LPVOID]
    _SaferComputeTokenFromLevel.restype  = BOOL
    _SaferComputeTokenFromLevel.errcheck = RaiseIfZero

    # This is probably one of the ugliest Win32 API interfaces ever! :(
    # That's why, depending on the dwFlags argument, we may have to use a
    # pointer for the lpReserved argument.
    #
    # The most usual case, however, is to pass only the LevelHandle and the
    # InAccessToken parameters, leaving all the rest with default values.
    # Then the return value is the new token (a TokenHandle instance).
    #
    # For example, if hToken is a token to be restricted...
    #
    #   with SaferCreateLevel( dwLevelId = SAFER_LEVELID_UNTRUSTED ) as LevelHandle:
    #       hRestrictedToken = SaferComputeTokenFromLevel(LevelHandle, hToken)
    #
    # would produce the restricted token as hRestrictedToken.

    OutAccessToken = HANDLE(INVALID_HANDLE_VALUE)

    # Low-level access, for unknown flags.
    # Returns a ctypes object. No handle wrapping is done.
    # The lpReserved argument should be a ctypes object too, or None.
    if (dwFlags & SAFER_TOKEN_MASK) != dwFlags:
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, ctypes.byref(OutAccessToken), dwFlags, lpReserved)
        return TokenHandle(OutAccessToken.value)

    # Extra flags.
    if dwFlags | SAFER_TOKEN_WANT_FLAGS:
        if lpReserved is not None:
            raise ValueError, "SaferComputeTokenFromLevel: lpReserved shouldn't be NULL for SAFER_TOKEN_WANT_FLAGS"
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, ctypes.byref(OutAccessToken), dwFlags, lpReserved)
        return TokenHandle(OutAccessToken.value)

    # Only compare the token.
    if dwFlags | SAFER_TOKEN_COMPARE_ONLY:
        if lpReserved is None:
            lpReserved = LPVOID(None)
            _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, None, dwFlags, ctypes.byref(lpReserved))
            return lpReserved.value
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, None, dwFlags, lpReserved)
        return None

    # Every other known flag.
    if lpReserved is not None:
        raise ValueError, "SaferComputeTokenFromLevel: lpReserved must be NULL for these flags"
    _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, ctypes.byref(OutAccessToken), dwFlags, None)
    return TokenHandle(OutAccessToken.value)

# BOOL WINAPI SaferCloseLevel(
#   __in  SAFER_LEVEL_HANDLE hLevelHandle
# );
def SaferCloseLevel(hLevelHandle):
    _SaferCloseLevel = windll.advapi32.SaferCloseLevel
    _SaferCloseLevel.argtypes = [SAFER_LEVEL_HANDLE]
    _SaferCloseLevel.restype  = BOOL
    _SaferCloseLevel.errcheck = RaiseIfZero

    if hasattr(hLevelHandle, 'close'):
        hLevelHandle.close()
    elif hasattr(hLevelHandle, 'value'):
        _SaferCloseLevel(hLevelHandle.value)
    else:
        _SaferCloseLevel(hLevelHandle)

