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
from kernel32 import *

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

#--- advapi32.dll -------------------------------------------------------------

# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess):
    TokenHandle = DWORD(0)
    ProcessHandle = HANDLE(ProcessHandle)
    success = ctypes.windll.advapi32.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))
    if success == FALSE:
        raise ctypes.WinError()
    return Handle(TokenHandle.value)

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
    ThreadHandle = HANDLE(ThreadHandle)
    success = ctypes.windll.advapi32.OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, ctypes.byref(TokenHandle))
    if success == FALSE:
        raise ctypes.WinError()
    return Handle(TokenHandle.value)

# BOOL WINAPI LookupPrivilegeValue(
#   __in_opt  LPCTSTR lpSystemName,
#   __in      LPCTSTR lpName,
#   __out     PLUID lpLuid
# );
def LookupPrivilegeValueA(lpSystemName, lpName):
    if lpSystemName:
        lpSystemName = ctypes.c_char_p(lpSystemName)
    else:
        lpSystemName = LPVOID(NULL)
    lpName       = ctypes.create_string_buffer(lpName)
    lpLuid       = LUID()
    success = ctypes.windll.advapi32.LookupPrivilegeValueA(lpSystemName, ctypes.byref(lpName), ctypes.byref(lpLuid))
    if success == FALSE:
        raise ctypes.WinError()
    return lpLuid
def LookupPrivilegeValueW(lpSystemName, lpName):
    if lpSystemName:
        lpSystemName = ctypes.c_wchar_p(lpSystemName)
    else:
        lpSystemName = LPVOID(NULL)
    lpName       = ctypes.create_unicode_buffer(lpName)
    lpLuid       = LUID()
    success = ctypes.windll.advapi32.LookupPrivilegeValueW(lpSystemName, ctypes.byref(lpName), ctypes.byref(lpLuid))
    if success == FALSE:
        raise ctypes.WinError()
    return lpLuid
LookupPrivilegeValue = GuessStringType(LookupPrivilegeValueA, LookupPrivilegeValueW)

# BOOL WINAPI LookupPrivilegeName(
#   __in_opt   LPCTSTR lpSystemName,
#   __in       PLUID lpLuid,
#   __out_opt  LPTSTR lpName,
#   __inout    LPDWORD cchName
# );
def LookupPrivilegeNameA(lpSystemName, lpLuid):
    if lpSystemName:
        lpSystemName = ctypes.c_char_p(lpSystemName)
    else:
        lpSystemName = LPVOID(NULL)
    cchName = DWORD(0)
    success = ctypes.windll.advapi32.LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), NULL, ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
    lpName = ctypes.create_string_buffer("", cchName.value)
    success = ctypes.windll.advapi32.LookupPrivilegeNameA(lpSystemName, ctypes.byref(lpLuid), ctypes.byref(lpName), ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
    return lpName.value
def LookupPrivilegeNameW(lpSystemName, lpLuid):
    if lpSystemName:
        lpSystemName = ctypes.c_wchar_p(lpSystemName)
    else:
        lpSystemName = LPVOID(NULL)
    cchName = DWORD(0)
    success = ctypes.windll.advapi32.LookupPrivilegeNameW(lpSystemName, ctypes.byref(lpLuid), NULL, ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
    lpName = ctypes.create_unicode_buffer(u"", cchName.value)
    success = ctypes.windll.advapi32.LookupPrivilegeNameW(lpSystemName, ctypes.byref(lpLuid), ctypes.byref(lpName), ctypes.byref(cchName))
    if success == FALSE:
        raise ctypes.WinError()
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
    #
    # I don't know how to allocate variable sized structures in ctypes :(
    # so this hack will work by using always TOKEN_PRIVILEGES of one element
    # and calling the API many times. This also means the PreviousState
    # parameter won't be supported yet as it's too much hassle. In a future
    # version I look forward to implementing this function correctly.
    #
    TokenHandle = HANDLE(TokenHandle)
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
    if not lpUsername:
        lpUsername          = LPVOID(NULL)
    else:
        lpUsername          = ctypes.c_wchar_p(lpUsername)
    if not lpDomain:
        lpDomain            = LPVOID(NULL)
    else:
        lpDomain            = ctypes.c_wchar_p(lpDomain)
    if not lpPassword:
        lpPassword          = LPVOID(NULL)
    else:
        lpPassword          = ctypes.c_wchar_p(lpPassword)
    if not lpApplicationName:
        lpApplicationName   = LPVOID(NULL)
    else:
        lpApplicationName   = ctypes.c_wchar_p(lpApplicationName)
    if not lpCommandLine:
        lpCommandLine       = LPVOID(NULL)
    else:
        lpCommandLine       = ctypes.create_unicode_buffer(lpCommandLine)
    if not lpEnvironment:
        lpEnvironment       = LPVOID(NULL)
    else:
        lpEnvironment       = ctypes.c_wchar_p(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = LPVOID(NULL)
    else:
        lpCurrentDirectory  = ctypes.c_wchar_p(lpCurrentDirectory)
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
    success = ctypes.windll.advapi32.CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, ctypes.byref(lpCommandLine), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
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
    if not hToken:
        hToken              = LPVOID(NULL)
    if not lpApplicationName:
        lpApplicationName   = LPVOID(NULL)
    else:
        lpApplicationName   = ctypes.c_wchar_p(lpApplicationName)
    if not lpCommandLine:
        lpCommandLine       = LPVOID(NULL)
    else:
        lpCommandLine       = ctypes.create_unicode_buffer(lpCommandLine)
    if not lpEnvironment:
        lpEnvironment       = LPVOID(NULL)
    else:
        lpEnvironment       = ctypes.c_wchar_p(lpEnvironment)
    if not lpCurrentDirectory:
        lpCurrentDirectory  = LPVOID(NULL)
    else:
        lpCurrentDirectory  = ctypes.c_wchar_p(lpCurrentDirectory)
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
    success = ctypes.windll.advapi32.CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, ctypes.byref(lpCommandLine), dwCreationFlags, lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
    if success == FALSE:
        raise ctypes.WinError()
    return ProcessInformation(lpProcessInformation)
CreateProcessWithTokenA = MakeANSIVersion(CreateProcessWithTokenW)
CreateProcessWithToken = CreateProcessWithTokenA
