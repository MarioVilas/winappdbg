#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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
# + add service control manager APIs
# + add transacted registry operations

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

# Predefined HKEY values
HKEY_CLASSES_ROOT       = 0x80000000
HKEY_CURRENT_USER       = 0x80000001
HKEY_LOCAL_MACHINE      = 0x80000002
HKEY_USERS              = 0x80000003
HKEY_PERFORMANCE_DATA   = 0x80000004
HKEY_CURRENT_CONFIG     = 0x80000005

# Registry access rights
KEY_ALL_ACCESS          = 0xF003F
KEY_CREATE_LINK         = 0x0020
KEY_CREATE_SUB_KEY      = 0x0004
KEY_ENUMERATE_SUB_KEYS  = 0x0008
KEY_EXECUTE             = 0x20019
KEY_NOTIFY              = 0x0010
KEY_QUERY_VALUE         = 0x0001
KEY_READ                = 0x20019
KEY_SET_VALUE           = 0x0002
KEY_WOW64_32KEY         = 0x0200
KEY_WOW64_64KEY         = 0x0100
KEY_WRITE               = 0x20006

# Registry value types
REG_NONE                        = 0
REG_SZ                          = 1
REG_EXPAND_SZ                   = 2
REG_BINARY                      = 3
REG_DWORD                       = 4
REG_DWORD_LITTLE_ENDIAN         = REG_DWORD
REG_DWORD_BIG_ENDIAN            = 5
REG_LINK                        = 6
REG_MULTI_SZ                    = 7
REG_RESOURCE_LIST               = 8
REG_FULL_RESOURCE_DESCRIPTOR    = 9
REG_RESOURCE_REQUIREMENTS_LIST  = 10
REG_QWORD                       = 11
REG_QWORD_LITTLE_ENDIAN         = REG_QWORD

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

#--- GetTokenInformation enums and structures ---------------------------------

# typedef enum _TOKEN_INFORMATION_CLASS {
#   TokenUser                              = 1,
#   TokenGroups,
#   TokenPrivileges,
#   TokenOwner,
#   TokenPrimaryGroup,
#   TokenDefaultDacl,
#   TokenSource,
#   TokenType,
#   TokenImpersonationLevel,
#   TokenStatistics,
#   TokenRestrictedSids,
#   TokenSessionId,
#   TokenGroupsAndPrivileges,
#   TokenSessionReference,
#   TokenSandBoxInert,
#   TokenAuditPolicy,
#   TokenOrigin,
#   TokenElevationType,
#   TokenLinkedToken,
#   TokenElevation,
#   TokenHasRestrictions,
#   TokenAccessInformation,
#   TokenVirtualizationAllowed,
#   TokenVirtualizationEnabled,
#   TokenIntegrityLevel,
#   TokenUIAccess,
#   TokenMandatoryPolicy,
#   TokenLogonSid,
#   TokenIsAppContainer,
#   TokenCapabilities,
#   TokenAppContainerSid,
#   TokenAppContainerNumber,
#   TokenUserClaimAttributes,
#   TokenDeviceClaimAttributes,
#   TokenRestrictedUserClaimAttributes,
#   TokenRestrictedDeviceClaimAttributes,
#   TokenDeviceGroups,
#   TokenRestrictedDeviceGroups,
#   TokenSecurityAttributes,
#   TokenIsRestricted,
#   MaxTokenInfoClass
# } TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

TOKEN_INFORMATION_CLASS = ctypes.c_int

TokenUser                               = 1
TokenGroups                             = 2
TokenPrivileges                         = 3
TokenOwner                              = 4
TokenPrimaryGroup                       = 5
TokenDefaultDacl                        = 6
TokenSource                             = 7
TokenType                               = 8
TokenImpersonationLevel                 = 9
TokenStatistics                         = 10
TokenRestrictedSids                     = 11
TokenSessionId                          = 12
TokenGroupsAndPrivileges                = 13
TokenSessionReference                   = 14
TokenSandBoxInert                       = 15
TokenAuditPolicy                        = 16
TokenOrigin                             = 17
TokenElevationType                      = 18
TokenLinkedToken                        = 19
TokenElevation                          = 20
TokenHasRestrictions                    = 21
TokenAccessInformation                  = 22
TokenVirtualizationAllowed              = 23
TokenVirtualizationEnabled              = 24
TokenIntegrityLevel                     = 25
TokenUIAccess                           = 26
TokenMandatoryPolicy                    = 27
TokenLogonSid                           = 28
TokenIsAppContainer                     = 29
TokenCapabilities                       = 30
TokenAppContainerSid                    = 31
TokenAppContainerNumber                 = 32
TokenUserClaimAttributes                = 33
TokenDeviceClaimAttributes              = 34
TokenRestrictedUserClaimAttributes      = 35
TokenRestrictedDeviceClaimAttributes    = 36
TokenDeviceGroups                       = 37
TokenRestrictedDeviceGroups             = 38
TokenSecurityAttributes                 = 39
TokenIsRestricted                       = 40
MaxTokenInfoClass                       = 41

# typedef enum tagTOKEN_TYPE {
#   TokenPrimary         = 1,
#   TokenImpersonation
# } TOKEN_TYPE, *PTOKEN_TYPE;

TOKEN_TYPE = ctypes.c_int
PTOKEN_TYPE = POINTER(TOKEN_TYPE)

TokenPrimary        = 1
TokenImpersonation  = 2

# typedef enum  {
#   TokenElevationTypeDefault   = 1,
#   TokenElevationTypeFull,
#   TokenElevationTypeLimited
# } TOKEN_ELEVATION_TYPE , *PTOKEN_ELEVATION_TYPE;

TokenElevationTypeDefault   = 1
TokenElevationTypeFull      = 2
TokenElevationTypeLimited   = 3

TOKEN_ELEVATION_TYPE = ctypes.c_int
PTOKEN_ELEVATION_TYPE = POINTER(TOKEN_ELEVATION_TYPE)

# typedef enum _SECURITY_IMPERSONATION_LEVEL {
#   SecurityAnonymous,
#   SecurityIdentification,
#   SecurityImpersonation,
#   SecurityDelegation
# } SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

SecurityAnonymous       = 0
SecurityIdentification  = 1
SecurityImpersonation   = 2
SecurityDelegation      = 3

SECURITY_IMPERSONATION_LEVEL = ctypes.c_int
PSECURITY_IMPERSONATION_LEVEL = POINTER(SECURITY_IMPERSONATION_LEVEL)

# typedef struct _SID_AND_ATTRIBUTES {
#   PSID  Sid;
#   DWORD Attributes;
# } SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;
class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid",         PSID),
        ("Attributes",  DWORD),
    ]
PSID_AND_ATTRIBUTES = POINTER(SID_AND_ATTRIBUTES)

# typedef struct _TOKEN_USER {
#   SID_AND_ATTRIBUTES User;
# } TOKEN_USER, *PTOKEN_USER;
class TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]
PTOKEN_USER = POINTER(TOKEN_USER)

# typedef struct _TOKEN_MANDATORY_LABEL {
#   SID_AND_ATTRIBUTES Label;
# } TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;
class TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]
PTOKEN_MANDATORY_LABEL = POINTER(TOKEN_MANDATORY_LABEL)

# typedef struct _TOKEN_OWNER {
#   PSID Owner;
# } TOKEN_OWNER, *PTOKEN_OWNER;
class TOKEN_OWNER(Structure):
    _fields_ = [
        ("Owner", PSID),
    ]
PTOKEN_OWNER = POINTER(TOKEN_OWNER)

# typedef struct _TOKEN_PRIMARY_GROUP {
#   PSID PrimaryGroup;
# } TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;
class TOKEN_PRIMARY_GROUP(Structure):
    _fields_ = [
        ("PrimaryGroup", PSID),
    ]
PTOKEN_PRIMARY_GROUP = POINTER(TOKEN_PRIMARY_GROUP)

# typedef struct _TOKEN_APPCONTAINER_INFORMATION {
#   	PSID TokenAppContainer;
# } TOKEN_APPCONTAINER_INFORMATION, *PTOKEN_APPCONTAINER_INFORMATION;
class TOKEN_APPCONTAINER_INFORMATION(Structure):
    _fields_ = [
        ("TokenAppContainer", PSID),
    ]
PTOKEN_APPCONTAINER_INFORMATION = POINTER(TOKEN_APPCONTAINER_INFORMATION)

# typedef struct _TOKEN_ORIGIN {
#   LUID OriginatingLogonSession;
# } TOKEN_ORIGIN, *PTOKEN_ORIGIN;
class TOKEN_ORIGIN(Structure):
    _fields_ = [
        ("OriginatingLogonSession", LUID),
    ]
PTOKEN_ORIGIN = POINTER(TOKEN_ORIGIN)

# typedef struct _TOKEN_LINKED_TOKEN {
#   HANDLE LinkedToken;
# } TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;
class TOKEN_LINKED_TOKEN(Structure):
    _fields_ = [
        ("LinkedToken", HANDLE),
    ]
PTOKEN_LINKED_TOKEN = POINTER(TOKEN_LINKED_TOKEN)

# typedef struct _TOKEN_STATISTICS {
#   LUID                         TokenId;
#   LUID                         AuthenticationId;
#   LARGE_INTEGER                ExpirationTime;
#   TOKEN_TYPE                   TokenType;
#   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
#   DWORD                        DynamicCharged;
#   DWORD                        DynamicAvailable;
#   DWORD                        GroupCount;
#   DWORD                        PrivilegeCount;
#   LUID                         ModifiedId;
# } TOKEN_STATISTICS, *PTOKEN_STATISTICS;
class TOKEN_STATISTICS(Structure):
    _fields_ = [
        ("TokenId",             LUID),
        ("AuthenticationId",    LUID),
        ("ExpirationTime",      LONGLONG),  # LARGE_INTEGER
        ("TokenType",           TOKEN_TYPE),
        ("ImpersonationLevel",  SECURITY_IMPERSONATION_LEVEL),
        ("DynamicCharged",      DWORD),
        ("DynamicAvailable",    DWORD),
        ("GroupCount",          DWORD),
        ("PrivilegeCount",      DWORD),
        ("ModifiedId",          LUID),
    ]
PTOKEN_STATISTICS = POINTER(TOKEN_STATISTICS)

#--- SID_NAME_USE enum --------------------------------------------------------

# typedef enum _SID_NAME_USE {
#   SidTypeUser             = 1,
#   SidTypeGroup,
#   SidTypeDomain,
#   SidTypeAlias,
#   SidTypeWellKnownGroup,
#   SidTypeDeletedAccount,
#   SidTypeInvalid,
#   SidTypeUnknown,
#   SidTypeComputer,
#   SidTypeLabel
# } SID_NAME_USE, *PSID_NAME_USE;

SidTypeUser             = 1
SidTypeGroup            = 2
SidTypeDomain           = 3
SidTypeAlias            = 4
SidTypeWellKnownGroup   = 5
SidTypeDeletedAccount   = 6
SidTypeInvalid          = 7
SidTypeUnknown          = 8
SidTypeComputer         = 9
SidTypeLabel            = 10

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

class RegistryKeyHandle (Handle):
    """
    Registry key handle.

    @see: L{Handle}
    """

    @property
    def _as_parameter_(self):
        return HKEY(self.value)

    @staticmethod
    def from_param(value):
        return HKEY(self.value)

    def _close(self):
        RegCloseKey(self.value)

    def dup(self):
        raise NotImplementedError()

    def wait(self, dwMilliseconds = None):
        raise NotImplementedError()

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

    def _close(self):
        SaferCloseLevel(self.value)

    def dup(self):
        raise NotImplementedError()

    def wait(self, dwMilliseconds = None):
        raise NotImplementedError()

#--- advapi32.dll -------------------------------------------------------------

# BOOL WINAPI GetUserName(
#   __out    LPTSTR lpBuffer,
#   __inout  LPDWORD lpnSize
# );
def GetUserNameA():
    _GetUserNameA = windll.advapi32.GetUserNameA
    _GetUserNameA.argtypes = [LPSTR, LPDWORD]
    _GetUserNameA.restype  = bool

    nSize = DWORD(0)
    _GetUserNameA(None, byref(nSize))
    error = GetLastError()
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(error)
    lpBuffer = ctypes.create_string_buffer('', nSize.value + 1)
    success = _GetUserNameA(lpBuffer, byref(nSize))
    if not success:
        raise ctypes.WinError()
    return lpBuffer.value

def GetUserNameW():
    _GetUserNameW = windll.advapi32.GetUserNameW
    _GetUserNameW.argtypes = [LPWSTR, LPDWORD]
    _GetUserNameW.restype  = bool

    nSize = DWORD(0)
    _GetUserNameW(None, byref(nSize))
    error = GetLastError()
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(error)
    lpBuffer = ctypes.create_unicode_buffer(u'', nSize.value + 1)
    success = _GetUserNameW(lpBuffer, byref(nSize))
    if not success:
        raise ctypes.WinError()
    return lpBuffer.value

GetUserName = DefaultStringType(GetUserNameA, GetUserNameW)

# BOOL WINAPI LookupAccountName(
#   __in_opt   LPCTSTR lpSystemName,
#   __in       LPCTSTR lpAccountName,
#   __out_opt  PSID Sid,
#   __inout    LPDWORD cbSid,
#   __out_opt  LPTSTR ReferencedDomainName,
#   __inout    LPDWORD cchReferencedDomainName,
#   __out      PSID_NAME_USE peUse
# );

# XXX TO DO

# BOOL WINAPI LookupAccountSid(
#   __in_opt   LPCTSTR lpSystemName,
#   __in       PSID lpSid,
#   __out_opt  LPTSTR lpName,
#   __inout    LPDWORD cchName,
#   __out_opt  LPTSTR lpReferencedDomainName,
#   __inout    LPDWORD cchReferencedDomainName,
#   __out      PSID_NAME_USE peUse
# );
def LookupAccountSidA(lpSystemName, lpSid):
    _LookupAccountSidA = windll.advapi32.LookupAccountSidA
    _LookupAccountSidA.argtypes = [LPSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, LPDWORD]
    _LookupAccountSidA.restype  = bool

    cchName = DWORD(0)
    cchReferencedDomainName = DWORD(0)
    peUse = DWORD(0)
    _LookupAccountSidA(lpSystemName, lpSid, None, byref(cchName), None, byref(cchReferencedDomainName), byref(peUse))
    error = GetLastError()
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(error)
    lpName = ctypes.create_string_buffer('', cchName + 1)
    lpReferencedDomainName = ctypes.create_string_buffer('', cchReferencedDomainName + 1)
    success = _LookupAccountSidA(lpSystemName, lpSid, lpName, byref(cchName), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
    if not success:
        raise ctypes.WinError()
    return lpName.value, lpReferencedDomainName.value, peUse.value

def LookupAccountSidW(lpSystemName, lpSid):
    _LookupAccountSidW = windll.advapi32.LookupAccountSidA
    _LookupAccountSidW.argtypes = [LPSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
    _LookupAccountSidW.restype  = bool

    cchName = DWORD(0)
    cchReferencedDomainName = DWORD(0)
    peUse = DWORD(0)
    _LookupAccountSidW(lpSystemName, lpSid, None, byref(cchName), None, byref(cchReferencedDomainName), byref(peUse))
    error = GetLastError()
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(error)
    lpName = ctypes.create_unicode_buffer(u'', cchName + 1)
    lpReferencedDomainName = ctypes.create_unicode_buffer(u'', cchReferencedDomainName + 1)
    success = _LookupAccountSidW(lpSystemName, lpSid, lpName, byref(cchName), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
    if not success:
        raise ctypes.WinError()
    return lpName.value, lpReferencedDomainName.value, peUse.value

LookupAccountSid = GuessStringType(LookupAccountSidA, LookupAccountSidW)

# BOOL ConvertSidToStringSid(
#   __in   PSID Sid,
#   __out  LPTSTR *StringSid
# );
def ConvertSidToStringSidA(Sid):
    _ConvertSidToStringSidA = windll.advapi32.ConvertSidToStringSidA
    _ConvertSidToStringSidA.argtypes = [PSID, LPSTR]
    _ConvertSidToStringSidA.restype  = bool
    _ConvertSidToStringSidA.errcheck = RaiseIfZero

    pStringSid = LPSTR()
    _ConvertSidToStringSidA(Sid, byref(pStringSid))
    try:
        StringSid = pStringSid.value
    finally:
        LocalFree(pStringSid)
    return StringSid

def ConvertSidToStringSidW(Sid):
    _ConvertSidToStringSidW = windll.advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = [PSID, LPWSTR]
    _ConvertSidToStringSidW.restype  = bool
    _ConvertSidToStringSidW.errcheck = RaiseIfZero

    pStringSid = LPWSTR()
    _ConvertSidToStringSidW(Sid, byref(pStringSid))
    try:
        StringSid = pStringSid.value
    finally:
        LocalFree(pStringSid)
    return StringSid

ConvertSidToStringSid = DefaultStringType(ConvertSidToStringSidA, ConvertSidToStringSidW)

# BOOL WINAPI ConvertStringSidToSid(
#   __in   LPCTSTR StringSid,
#   __out  PSID *Sid
# );
def ConvertStringSidToSidA(StringSid):
    _ConvertStringSidToSidA = windll.advapi32.ConvertStringSidToSidA
    _ConvertStringSidToSidA.argtypes = [LPSTR, PVOID]
    _ConvertStringSidToSidA.restype  = bool
    _ConvertStringSidToSidA.errcheck = RaiseIfZero

    Sid = PVOID()
    _ConvertStringSidToSidA(StringSid, ctypes.pointer(Sid))
    return Sid.value

def ConvertStringSidToSidW(StringSid):
    _ConvertStringSidToSidW = windll.advapi32.ConvertStringSidToSidW
    _ConvertStringSidToSidW.argtypes = [LPWSTR, PVOID]
    _ConvertStringSidToSidW.restype  = bool
    _ConvertStringSidToSidW.errcheck = RaiseIfZero

    Sid = PVOID()
    _ConvertStringSidToSidW(StringSid, ctypes.pointer(Sid))
    return Sid.value

ConvertStringSidToSid = GuessStringType(ConvertStringSidToSidA, ConvertStringSidToSidW)

# BOOL WINAPI IsValidSid(
#   __in  PSID pSid
# );
def IsValidSid(pSid):
    _IsValidSid = windll.advapi32.IsValidSid
    _IsValidSid.argtypes = [PSID]
    _IsValidSid.restype  = bool
    return _IsValidSid(pSid)

# BOOL WINAPI EqualSid(
#   __in  PSID pSid1,
#   __in  PSID pSid2
# );
def EqualSid(pSid1, pSid2):
    _EqualSid = windll.advapi32.EqualSid
    _EqualSid.argtypes = [PSID, PSID]
    _EqualSid.restype  = bool
    return _EqualSid(pSid1, pSid2)

# DWORD WINAPI GetLengthSid(
#   __in  PSID pSid
# );
def GetLengthSid(pSid):
    _GetLengthSid = windll.advapi32.GetLengthSid
    _GetLengthSid.argtypes = [PSID]
    _GetLengthSid.restype  = DWORD
    return _GetLengthSid(pSid)

# BOOL WINAPI CopySid(
#   __in   DWORD nDestinationSidLength,
#   __out  PSID pDestinationSid,
#   __in   PSID pSourceSid
# );
def CopySid(pSourceSid):
    _CopySid = windll.advapi32.CopySid
    _CopySid.argtypes = [DWORD, PVOID, PSID]
    _CopySid.restype  = bool
    _CopySid.errcheck = RaiseIfZero

    nDestinationSidLength = GetLengthSid(pSourceSid)
    DestinationSid = ctypes.create_string_buffer('', nDestinationSidLength)
    pDestinationSid = ctypes.cast(ctypes.pointer(DestinationSid), PVOID)
    _CopySid(nDestinationSidLength, pDestinationSid, pSourceSid)
    return ctypes.cast(pDestinationSid, PSID)

# PVOID WINAPI FreeSid(
#   __in  PSID pSid
# );
def FreeSid(pSid):
    _FreeSid = windll.advapi32.FreeSid
    _FreeSid.argtypes = [PSID]
    _FreeSid.restype  = PSID
    _FreeSid.errcheck = RaiseIfNotZero
    _FreeSid(pSid)

# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess):
    _OpenProcessToken = windll.advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
    _OpenProcessToken.restype  = bool
    _OpenProcessToken.errcheck = RaiseIfZero

    tokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenProcessToken(ProcessHandle, DesiredAccess, byref(tokenHandle))
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
    _OpenThreadToken.restype  = bool
    _OpenThreadToken.errcheck = RaiseIfZero

    tokenHandle = HANDLE(INVALID_HANDLE_VALUE)
    _OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, byref(tokenHandle))
    return TokenHandle(tokenHandle.value)

# BOOL WINAPI IsTokenRestricted(
#   __in  HANDLE TokenHandle
# );
def IsTokenRestricted(hTokenHandle):
    _IsTokenRestricted = windll.advapi32.IsTokenRestricted
    _IsTokenRestricted.argtypes = [HANDLE]
    _IsTokenRestricted.restype  = bool
    _IsTokenRestricted.errcheck = RaiseIfNotErrorSuccess

    SetLastError(ERROR_SUCCESS)
    return _IsTokenRestricted(hTokenHandle)

# BOOL WINAPI LookupPrivilegeValue(
#   __in_opt  LPCTSTR lpSystemName,
#   __in      LPCTSTR lpName,
#   __out     PLUID lpLuid
# );
def LookupPrivilegeValueA(lpSystemName, lpName):
    _LookupPrivilegeValueA = windll.advapi32.LookupPrivilegeValueA
    _LookupPrivilegeValueA.argtypes = [LPSTR, LPSTR, PLUID]
    _LookupPrivilegeValueA.restype  = bool
    _LookupPrivilegeValueA.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueA(lpSystemName, lpName, byref(lpLuid))
    return lpLuid

def LookupPrivilegeValueW(lpSystemName, lpName):
    _LookupPrivilegeValueW = windll.advapi32.LookupPrivilegeValueW
    _LookupPrivilegeValueW.argtypes = [LPWSTR, LPWSTR, PLUID]
    _LookupPrivilegeValueW.restype  = bool
    _LookupPrivilegeValueW.errcheck = RaiseIfZero

    lpLuid = LUID()
    if not lpSystemName:
        lpSystemName = None
    _LookupPrivilegeValueW(lpSystemName, lpName, byref(lpLuid))
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
    _LookupPrivilegeNameA.restype  = bool
    _LookupPrivilegeNameA.errcheck = RaiseIfZero

    cchName = DWORD(0)
    _LookupPrivilegeNameA(lpSystemName, byref(lpLuid), NULL, byref(cchName))
    lpName = ctypes.create_string_buffer("", cchName.value)
    _LookupPrivilegeNameA(lpSystemName, byref(lpLuid), byref(lpName), byref(cchName))
    return lpName.value

def LookupPrivilegeNameW(lpSystemName, lpLuid):
    _LookupPrivilegeNameW = windll.advapi32.LookupPrivilegeNameW
    _LookupPrivilegeNameW.argtypes = [LPWSTR, PLUID, LPWSTR, LPDWORD]
    _LookupPrivilegeNameW.restype  = bool
    _LookupPrivilegeNameW.errcheck = RaiseIfZero

    cchName = DWORD(0)
    _LookupPrivilegeNameW(lpSystemName, byref(lpLuid), NULL, byref(cchName))
    lpName = ctypes.create_unicode_buffer(u"", cchName.value)
    _LookupPrivilegeNameW(lpSystemName, byref(lpLuid), byref(lpName), byref(cchName))
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
    _AdjustTokenPrivileges.restype  = bool
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
            _AdjustTokenPrivileges(TokenHandle, FALSE, byref(tp), sizeof(tp), NULL, NULL)

# BOOL WINAPI GetTokenInformation(
#   __in       HANDLE TokenHandle,
#   __in       TOKEN_INFORMATION_CLASS TokenInformationClass,
#   __out_opt  LPVOID TokenInformation,
#   __in       DWORD TokenInformationLength,
#   __out      PDWORD ReturnLength
# );
def GetTokenInformation(hTokenHandle, TokenInformationClass):
    if TokenInformationClass <= 0 or TokenInformationClass > MaxTokenInfoClass:
        raise ValueError("Invalid value for TokenInformationClass (%i)" % TokenInformationClass)

    # User SID.
    if TokenInformationClass == TokenUser:
        TokenInformation = TOKEN_USER()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.User.Sid.value

    # Owner SID.
    if TokenInformationClass == TokenOwner:
        TokenInformation = TOKEN_OWNER()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.Owner.value

    # Primary group SID.
    if TokenInformationClass == TokenOwner:
        TokenInformation = TOKEN_PRIMARY_GROUP()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.PrimaryGroup.value

    # App container SID.
    if TokenInformationClass == TokenAppContainerSid:
        TokenInformation = TOKEN_APPCONTAINER_INFORMATION()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.TokenAppContainer.value

    # Integrity level SID.
    if TokenInformationClass == TokenIntegrityLevel:
        TokenInformation = TOKEN_MANDATORY_LABEL()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.Label.Sid.value, TokenInformation.Label.Attributes

    # Logon session LUID.
    if TokenInformationClass == TokenOrigin:
        TokenInformation = TOKEN_ORIGIN()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.OriginatingLogonSession

    # Primary or impersonation token.
    if TokenInformationClass == TokenType:
        TokenInformation = TOKEN_TYPE(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.value

    # Elevated token.
    if TokenInformationClass == TokenElevation:
        TokenInformation = TOKEN_ELEVATION(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.value

    # Security impersonation level.
    if TokenInformationClass == TokenElevation:
        TokenInformation = SECURITY_IMPERSONATION_LEVEL(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.value

    # Session ID and other DWORD values.
    if TokenInformationClass in (TokenSessionId, TokenAppContainerNumber):
        TokenInformation = DWORD(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation.value

    # Various boolean flags.
    if TokenInformationClass in (TokenSandBoxInert, TokenHasRestrictions, TokenUIAccess,
                                 TokenVirtualizationAllowed, TokenVirtualizationEnabled):
        TokenInformation = DWORD(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return bool(TokenInformation.value)

    # Linked token.
    if TokenInformationClass == TokenLinkedToken:
        TokenInformation = TOKEN_LINKED_TOKEN(0)
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenHandle(TokenInformation.LinkedToken.value, bOwnership = True)

    # Token statistics.
    if TokenInformationClass == TokenStatistics:
        TokenInformation = TOKEN_STATISTICS()
        _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
        return TokenInformation # TODO add a class wrapper?

    # Currently unsupported flags.
    raise NotImplementedError("TokenInformationClass(%i) not yet supported!" % TokenInformationClass)

def _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation):
    _GetTokenInformation = windll.advapi32.GetTokenInformation
    _GetTokenInformation.argtypes = [HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD]
    _GetTokenInformation.restype  = bool
    _GetTokenInformation.errcheck = RaiseIfZero

    ReturnLength = DWORD(0)
    TokenInformationLength = SIZEOF(TokenInformation)
    _GetTokenInformation(hTokenHandle, TokenInformationClass, byref(TokenInformation), TokenInformationLength, byref(ReturnLength))
    if ReturnLength.value != TokenInformationLength:
        raise ctypes.WinError(ERROR_INSUFFICIENT_BUFFER)
    return TokenInformation

# BOOL WINAPI SetTokenInformation(
#   __in  HANDLE TokenHandle,
#   __in  TOKEN_INFORMATION_CLASS TokenInformationClass,
#   __in  LPVOID TokenInformation,
#   __in  DWORD TokenInformationLength
# );

# XXX TODO

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
    _CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, byref(lpStartupInfo), byref(lpProcessInformation))
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
    _CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, byref(lpStartupInfo), byref(lpProcessInformation))
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
    _GetThreadWaitChain(WctHandle, Context, Flags, ThreadId, byref(NodeCount), ctypes.cast(ctypes.pointer(NodeInfoArray), PWAITCHAIN_NODE_INFO), byref(IsCycle))
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
    _SaferCreateLevel(dwScopeId, dwLevelId, OpenFlags, byref(hLevelHandle), None)
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
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, byref(OutAccessToken), dwFlags, lpReserved)
        return TokenHandle(OutAccessToken.value)

    # Extra flags.
    if dwFlags | SAFER_TOKEN_WANT_FLAGS:
        if lpReserved is not None:
            raise ValueError("SaferComputeTokenFromLevel: lpReserved shouldn't be NULL for SAFER_TOKEN_WANT_FLAGS")
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, byref(OutAccessToken), dwFlags, lpReserved)
        return TokenHandle(OutAccessToken.value)

    # Only compare the token.
    if dwFlags | SAFER_TOKEN_COMPARE_ONLY:
        if lpReserved is None:
            lpReserved = LPVOID(None)
            _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, None, dwFlags, byref(lpReserved))
            return lpReserved.value
        _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, None, dwFlags, lpReserved)
        return None

    # Every other known flag.
    if lpReserved is not None:
        raise ValueError("SaferComputeTokenFromLevel: lpReserved must be NULL for these flags")
    _SaferComputeTokenFromLevel(LevelHandle, InAccessToken, byref(OutAccessToken), dwFlags, None)
    return TokenHandle(OutAccessToken.value)

# BOOL WINAPI SaferCloseLevel(
#   __in  SAFER_LEVEL_HANDLE hLevelHandle
# );
def SaferCloseLevel(hLevelHandle):
    _SaferCloseLevel = windll.advapi32.SaferCloseLevel
    _SaferCloseLevel.argtypes = [SAFER_LEVEL_HANDLE]
    _SaferCloseLevel.restype  = BOOL
    _SaferCloseLevel.errcheck = RaiseIfZero

    if hasattr(hLevelHandle, 'value'):
        _SaferCloseLevel(hLevelHandle.value)
    else:
        _SaferCloseLevel(hLevelHandle)

# BOOL SaferiIsExecutableFileType(
#   __in  LPCWSTR szFullPath,
#   __in  BOOLEAN bFromShellExecute
# );
def SaferiIsExecutableFileType(szFullPath, bFromShellExecute = False):
    _SaferiIsExecutableFileType = windll.advapi32.SaferiIsExecutableFileType
    _SaferiIsExecutableFileType.argtypes = [LPWSTR, BOOLEAN]
    _SaferiIsExecutableFileType.restype  = BOOL
    _SaferiIsExecutableFileType.errcheck = RaiseIfLastError

    SetLastError(ERROR_SUCCESS)
    return bool(_SaferiIsExecutableFileType(unicode(szFullPath), bFromShellExecute))

# useful alias since I'm likely to misspell it :P
SaferIsExecutableFileType = SaferiIsExecutableFileType

#------------------------------------------------------------------------------

# LONG WINAPI RegCloseKey(
#   __in  HKEY hKey
# );
def RegCloseKey(hKey):
    if hasattr(hKey, 'value'):
        value = hKey.value
    else:
        value = hKey

    if value in (
            HKEY_CLASSES_ROOT,
            HKEY_CURRENT_USER,
            HKEY_LOCAL_MACHINE,
            HKEY_USERS,
            HKEY_PERFORMANCE_DATA,
            HKEY_CURRENT_CONFIG
        ):
        return

    _RegCloseKey = windll.advapi32.RegCloseKey
    _RegCloseKey.argtypes = [HKEY]
    _RegCloseKey.restype  = LONG
    _RegCloseKey.errcheck = RaiseIfNotErrorSuccess
    _RegCloseKey(hKey)

# LONG WINAPI RegConnectRegistry(
#   __in_opt  LPCTSTR lpMachineName,
#   __in      HKEY hKey,
#   __out     PHKEY phkResult
# );
def RegConnectRegistryA(lpMachineName = None, hKey = HKEY_LOCAL_MACHINE):
    _RegConnectRegistryA = windll.advapi32.RegConnectRegistryA
    _RegConnectRegistryA.argtypes = [LPSTR, HKEY, PHKEY]
    _RegConnectRegistryA.restype  = LONG
    _RegConnectRegistryA.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegConnectRegistryA(lpMachineName, hKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

def RegConnectRegistryW(lpMachineName = None, hKey = HKEY_LOCAL_MACHINE):
    _RegConnectRegistryW = windll.advapi32.RegConnectRegistryW
    _RegConnectRegistryW.argtypes = [LPWSTR, HKEY, PHKEY]
    _RegConnectRegistryW.restype  = LONG
    _RegConnectRegistryW.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegConnectRegistryW(lpMachineName, hKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

RegConnectRegistry = GuessStringType(RegConnectRegistryA, RegConnectRegistryW)

# LONG WINAPI RegCreateKey(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpSubKey,
#   __out     PHKEY phkResult
# );
def RegCreateKeyA(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None):
    _RegCreateKeyA = windll.advapi32.RegCreateKeyA
    _RegCreateKeyA.argtypes = [HKEY, LPSTR, PHKEY]
    _RegCreateKeyA.restype  = LONG
    _RegCreateKeyA.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegCreateKeyA(hKey, lpSubKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

def RegCreateKeyW(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None):
    _RegCreateKeyW = windll.advapi32.RegCreateKeyW
    _RegCreateKeyW.argtypes = [HKEY, LPWSTR, PHKEY]
    _RegCreateKeyW.restype  = LONG
    _RegCreateKeyW.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegCreateKeyW(hKey, lpSubKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

RegCreateKey = GuessStringType(RegCreateKeyA, RegCreateKeyW)

# LONG WINAPI RegCreateKeyEx(
#   __in        HKEY hKey,
#   __in        LPCTSTR lpSubKey,
#   __reserved  DWORD Reserved,
#   __in_opt    LPTSTR lpClass,
#   __in        DWORD dwOptions,
#   __in        REGSAM samDesired,
#   __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   __out       PHKEY phkResult,
#   __out_opt   LPDWORD lpdwDisposition
# );

# XXX TODO

# LONG WINAPI RegOpenKey(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpSubKey,
#   __out     PHKEY phkResult
# );
def RegOpenKeyA(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None):
    _RegOpenKeyA = windll.advapi32.RegOpenKeyA
    _RegOpenKeyA.argtypes = [HKEY, LPSTR, PHKEY]
    _RegOpenKeyA.restype  = LONG
    _RegOpenKeyA.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenKeyA(hKey, lpSubKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

def RegOpenKeyW(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None):
    _RegOpenKeyW = windll.advapi32.RegOpenKeyW
    _RegOpenKeyW.argtypes = [HKEY, LPWSTR, PHKEY]
    _RegOpenKeyW.restype  = LONG
    _RegOpenKeyW.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenKeyW(hKey, lpSubKey, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

RegOpenKey = GuessStringType(RegOpenKeyA, RegOpenKeyW)

# LONG WINAPI RegOpenKeyEx(
#   __in        HKEY hKey,
#   __in_opt    LPCTSTR lpSubKey,
#   __reserved  DWORD ulOptions,
#   __in        REGSAM samDesired,
#   __out       PHKEY phkResult
# );
def RegOpenKeyExA(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None, samDesired = KEY_ALL_ACCESS):
    _RegOpenKeyExA = windll.advapi32.RegOpenKeyExA
    _RegOpenKeyExA.argtypes = [HKEY, LPSTR, DWORD, REGSAM, PHKEY]
    _RegOpenKeyExA.restype  = LONG
    _RegOpenKeyExA.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenKeyExA(hKey, lpSubKey, 0, samDesired, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

def RegOpenKeyExW(hKey = HKEY_LOCAL_MACHINE, lpSubKey = None, samDesired = KEY_ALL_ACCESS):
    _RegOpenKeyExW = windll.advapi32.RegOpenKeyExW
    _RegOpenKeyExW.argtypes = [HKEY, LPWSTR, DWORD, REGSAM, PHKEY]
    _RegOpenKeyExW.restype  = LONG
    _RegOpenKeyExW.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenKeyExW(hKey, lpSubKey, 0, samDesired, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

RegOpenKeyEx = GuessStringType(RegOpenKeyExA, RegOpenKeyExW)

# LONG WINAPI RegOpenCurrentUser(
#   __in   REGSAM samDesired,
#   __out  PHKEY phkResult
# );
def RegOpenCurrentUser(samDesired = KEY_ALL_ACCESS):
    _RegOpenCurrentUser = windll.advapi32.RegOpenCurrentUser
    _RegOpenCurrentUser.argtypes = [REGSAM, PHKEY]
    _RegOpenCurrentUser.restype  = LONG
    _RegOpenCurrentUser.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenCurrentUser(samDesired, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

# LONG WINAPI RegOpenUserClassesRoot(
#   __in        HANDLE hToken,
#   __reserved  DWORD dwOptions,
#   __in        REGSAM samDesired,
#   __out       PHKEY phkResult
# );
def RegOpenUserClassesRoot(hToken, samDesired = KEY_ALL_ACCESS):
    _RegOpenUserClassesRoot = windll.advapi32.RegOpenUserClassesRoot
    _RegOpenUserClassesRoot.argtypes = [HANDLE, DWORD, REGSAM, PHKEY]
    _RegOpenUserClassesRoot.restype  = LONG
    _RegOpenUserClassesRoot.errcheck = RaiseIfNotErrorSuccess

    hkResult = HKEY(INVALID_HANDLE_VALUE)
    _RegOpenUserClassesRoot(hToken, 0, samDesired, byref(hkResult))
    return RegistryKeyHandle(hkResult.value)

# LONG WINAPI RegQueryValue(
#   __in         HKEY hKey,
#   __in_opt     LPCTSTR lpSubKey,
#   __out_opt    LPTSTR lpValue,
#   __inout_opt  PLONG lpcbValue
# );
def RegQueryValueA(hKey, lpSubKey = None):
    _RegQueryValueA = windll.advapi32.RegQueryValueA
    _RegQueryValueA.argtypes = [HKEY, LPSTR, LPVOID, PLONG]
    _RegQueryValueA.restype  = LONG
    _RegQueryValueA.errcheck = RaiseIfNotErrorSuccess

    cbValue = LONG(0)
    _RegQueryValueA(hKey, lpSubKey, None, byref(cbValue))
    lpValue = ctypes.create_string_buffer(cbValue.value)
    _RegQueryValueA(hKey, lpSubKey, lpValue, byref(cbValue))
    return lpValue.value

def RegQueryValueW(hKey, lpSubKey = None):
    _RegQueryValueW = windll.advapi32.RegQueryValueW
    _RegQueryValueW.argtypes = [HKEY, LPWSTR, LPVOID, PLONG]
    _RegQueryValueW.restype  = LONG
    _RegQueryValueW.errcheck = RaiseIfNotErrorSuccess

    cbValue = LONG(0)
    _RegQueryValueW(hKey, lpSubKey, None, byref(cbValue))
    lpValue = ctypes.create_unicode_buffer(cbValue.value * sizeof(WCHAR))
    _RegQueryValueW(hKey, lpSubKey, lpValue, byref(cbValue))
    return lpValue.value

RegQueryValue = GuessStringType(RegQueryValueA, RegQueryValueW)

# LONG WINAPI RegQueryValueEx(
#   __in         HKEY hKey,
#   __in_opt     LPCTSTR lpValueName,
#   __reserved   LPDWORD lpReserved,
#   __out_opt    LPDWORD lpType,
#   __out_opt    LPBYTE lpData,
#   __inout_opt  LPDWORD lpcbData
# );
def _internal_RegQueryValueEx(ansi, hKey, lpValueName = None, bGetData = True):
    _RegQueryValueEx = _caller_RegQueryValueEx(ansi)

    cbData = DWORD(0)
    dwType = DWORD(-1)
    _RegQueryValueEx(hKey, lpValueName, None, byref(dwType), None, byref(cbData))
    Type = dwType.value

    if not bGetData:
        return cbData.value, Type

    if Type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):   # REG_DWORD_LITTLE_ENDIAN
        if cbData.value != 4:
            raise ValueError("REG_DWORD value of size %d" % cbData.value)
        dwData = DWORD(0)
        _RegQueryValueEx(hKey, lpValueName, None, None, byref(dwData), byref(cbData))
        return dwData.value, Type

    if Type == REG_QWORD:   # REG_QWORD_LITTLE_ENDIAN
        if cbData.value != 8:
            raise ValueError("REG_QWORD value of size %d" % cbData.value)
        qwData = QWORD(0L)
        _RegQueryValueEx(hKey, lpValueName, None, None, byref(qwData), byref(cbData))
        return qwData.value, Type

    if Type in (REG_SZ, REG_EXPAND_SZ):
        if ansi:
            szData = ctypes.create_string_buffer(cbData.value)
        else:
            szData = ctypes.create_unicode_buffer(cbData.value)
        _RegQueryValueEx(hKey, lpValueName, None, None, byref(szData), byref(cbData))
        return szData.value, Type

    if Type == REG_MULTI_SZ:
        if ansi:
            szData = ctypes.create_string_buffer(cbData.value)
        else:
            szData = ctypes.create_unicode_buffer(cbData.value)
        _RegQueryValueEx(hKey, lpValueName, None, None, byref(szData), byref(cbData))
        Data = szData[:]
        if ansi:
            aData = Data.split('\0')
        else:
            aData = Data.split(u'\0')
        aData = [token for token in aData if token]
        return aData, Type

    if Type == REG_LINK:
        szData = ctypes.create_unicode_buffer(cbData.value)
        _RegQueryValueEx(hKey, lpValueName, None, None, byref(szData), byref(cbData))
        return szData.value, Type

    # REG_BINARY, REG_NONE, and any future types
    szData = ctypes.create_string_buffer(cbData.value)
    _RegQueryValueEx(hKey, lpValueName, None, None, byref(szData), byref(cbData))
    return szData.raw, Type

def _caller_RegQueryValueEx(ansi):
    if ansi:
        _RegQueryValueEx = windll.advapi32.RegQueryValueExA
        _RegQueryValueEx.argtypes = [HKEY, LPSTR, LPVOID, PDWORD, LPVOID, PDWORD]
    else:
        _RegQueryValueEx = windll.advapi32.RegQueryValueExW
        _RegQueryValueEx.argtypes = [HKEY, LPWSTR, LPVOID, PDWORD, LPVOID, PDWORD]
    _RegQueryValueEx.restype  = LONG
    _RegQueryValueEx.errcheck = RaiseIfNotErrorSuccess
    return _RegQueryValueEx

# see _internal_RegQueryValueEx
def RegQueryValueExA(hKey, lpValueName = None, bGetData = True):
    return _internal_RegQueryValueEx(True, hKey, lpValueName, bGetData)

# see _internal_RegQueryValueEx
def RegQueryValueExW(hKey, lpValueName = None, bGetData = True):
    return _internal_RegQueryValueEx(False, hKey, lpValueName, bGetData)

RegQueryValueEx = GuessStringType(RegQueryValueExA, RegQueryValueExW)

# LONG WINAPI RegSetValueEx(
#   __in        HKEY hKey,
#   __in_opt    LPCTSTR lpValueName,
#   __reserved  DWORD Reserved,
#   __in        DWORD dwType,
#   __in_opt    const BYTE *lpData,
#   __in        DWORD cbData
# );
def RegSetValueEx(hKey, lpValueName = None, lpData = None, dwType = None):

    # Determine which version of the API to use, ANSI or Widechar.
    if lpValueName is None:
        if isinstance(lpData, GuessStringType.t_ansi):
            ansi = True
        elif isinstance(lpData, GuessStringType.t_unicode):
            ansi = False
        else:
            ansi = (GuessStringType.t_ansi == GuessStringType.t_default)
    elif isinstance(lpValueName, GuessStringType.t_ansi):
        ansi = True
    elif isinstance(lpValueName, GuessStringType.t_unicode):
        ansi = False
    else:
        raise TypeError("String expected, got %s instead" % type(lpValueName))

    # Autodetect the type when not given.
    # TODO: improve detection of DWORD and QWORD by seeing if the value "fits".
    if dwType is None:
        if lpValueName is None:
            dwType = REG_SZ
        elif lpData is None:
            dwType = REG_NONE
        elif isinstance(lpData, GuessStringType.t_ansi):
            dwType = REG_SZ
        elif isinstance(lpData, GuessStringType.t_unicode):
            dwType = REG_SZ
        elif isinstance(lpData, int):
            dwType = REG_DWORD
        elif isinstance(lpData, long):
            dwType = REG_QWORD
        else:
            dwType = REG_BINARY

    # Load the ctypes caller.
    if ansi:
        _RegSetValueEx = windll.advapi32.RegSetValueExA
        _RegSetValueEx.argtypes = [HKEY, LPSTR, DWORD, DWORD, LPVOID, DWORD]
    else:
        _RegSetValueEx = windll.advapi32.RegSetValueExW
        _RegSetValueEx.argtypes = [HKEY, LPWSTR, DWORD, DWORD, LPVOID, DWORD]
    _RegSetValueEx.restype  = LONG
    _RegSetValueEx.errcheck = RaiseIfNotErrorSuccess

    # Convert the arguments so ctypes can understand them.
    if lpData is None:
        DataRef  = None
        DataSize = 0
    else:
        if dwType in (REG_DWORD, REG_DWORD_BIG_ENDIAN):  # REG_DWORD_LITTLE_ENDIAN
            Data = DWORD(lpData)
        elif dwType == REG_QWORD:   # REG_QWORD_LITTLE_ENDIAN
            Data = QWORD(lpData)
        elif dwType in (REG_SZ, REG_EXPAND_SZ):
            if ansi:
                Data = ctypes.create_string_buffer(lpData)
            else:
                Data = ctypes.create_unicode_buffer(lpData)
        elif dwType == REG_MULTI_SZ:
            if ansi:
                Data = ctypes.create_string_buffer('\0'.join(lpData) + '\0\0')
            else:
                Data = ctypes.create_unicode_buffer(u'\0'.join(lpData) + u'\0\0')
        elif dwType == REG_LINK:
            Data = ctypes.create_unicode_buffer(lpData)
        else:
            Data = ctypes.create_string_buffer(lpData)
        DataRef  = byref(Data)
        DataSize = sizeof(Data)

    # Call the API with the converted arguments.
    _RegSetValueEx(hKey, lpValueName, 0, dwType, DataRef, DataSize)

# No "GuessStringType" here since detection is done inside.
RegSetValueExA = RegSetValueExW = RegSetValueEx

# LONG WINAPI RegEnumKey(
#   __in   HKEY hKey,
#   __in   DWORD dwIndex,
#   __out  LPTSTR lpName,
#   __in   DWORD cchName
# );
def RegEnumKeyA(hKey, dwIndex):
    _RegEnumKeyA = windll.advapi32.RegEnumKeyA
    _RegEnumKeyA.argtypes = [HKEY, DWORD, LPSTR, DWORD]
    _RegEnumKeyA.restype  = LONG

    cchName = 1024
    while True:
        lpName = ctypes.create_string_buffer(cchName)
        errcode = _RegEnumKeyA(hKey, dwIndex, lpName, cchName)
        if errcode != ERROR_MORE_DATA:
            break
        cchName = cchName + 1024
        if cchName > 65536:
            raise ctypes.WinError(errcode)
    if errcode == ERROR_NO_MORE_ITEMS:
        return None
    if errcode != ERROR_SUCCESS:
        raise ctypes.WinError(errcode)
    return lpName.value

def RegEnumKeyW(hKey, dwIndex):
    _RegEnumKeyW = windll.advapi32.RegEnumKeyW
    _RegEnumKeyW.argtypes = [HKEY, DWORD, LPWSTR, DWORD]
    _RegEnumKeyW.restype  = LONG

    cchName = 512
    while True:
        lpName = ctypes.create_unicode_buffer(cchName)
        errcode = _RegEnumKeyW(hKey, dwIndex, lpName, cchName * 2)
        if errcode != ERROR_MORE_DATA:
            break
        cchName = cchName + 512
        if cchName > 32768:
            raise ctypes.WinError(errcode)
    if errcode == ERROR_NO_MORE_ITEMS:
        return None
    if errcode != ERROR_SUCCESS:
        raise ctypes.WinError(errcode)
    return lpName.value

RegEnumKey = DefaultStringType(RegEnumKeyA, RegEnumKeyW)

# LONG WINAPI RegEnumKeyEx(
#   __in         HKEY hKey,
#   __in         DWORD dwIndex,
#   __out        LPTSTR lpName,
#   __inout      LPDWORD lpcName,
#   __reserved   LPDWORD lpReserved,
#   __inout      LPTSTR lpClass,
#   __inout_opt  LPDWORD lpcClass,
#   __out_opt    PFILETIME lpftLastWriteTime
# );

# XXX TODO

# LONG WINAPI RegEnumValue(
#   __in         HKEY hKey,
#   __in         DWORD dwIndex,
#   __out        LPTSTR lpValueName,
#   __inout      LPDWORD lpcchValueName,
#   __reserved   LPDWORD lpReserved,
#   __out_opt    LPDWORD lpType,
#   __out_opt    LPBYTE lpData,
#   __inout_opt  LPDWORD lpcbData
# );
def _internal_RegEnumValue(ansi, hKey, dwIndex, bGetData = True):
    if ansi:
        _RegEnumValue = windll.advapi32.RegEnumValueA
        _RegEnumValue.argtypes = [HKEY, DWORD, LPSTR, LPDWORD, LPVOID, LPDWORD, LPVOID, LPDWORD]
    else:
        _RegEnumValue = windll.advapi32.RegEnumValueW
        _RegEnumValue.argtypes = [HKEY, DWORD, LPWSTR, LPDWORD, LPVOID, LPDWORD, LPVOID, LPDWORD]
    _RegEnumValue.restype  = LONG

    cchValueName = DWORD(1024)
    dwType = DWORD(-1)
    lpcchValueName = byref(cchValueName)
    lpType = byref(dwType)
    if ansi:
        lpValueName = ctypes.create_string_buffer(cchValueName.value)
    else:
        lpValueName = ctypes.create_unicode_buffer(cchValueName.value)
    if bGetData:
        cbData = DWORD(0)
        lpcbData = byref(cbData)
    else:
        lpcbData = None
    lpData = None
    errcode = _RegEnumValue(hKey, dwIndex, lpValueName, lpcchValueName, None, lpType, lpData, lpcbData)

    if errcode == ERROR_MORE_DATA or (bGetData and errcode == ERROR_SUCCESS):
        if ansi:
            cchValueName.value = cchValueName.value + sizeof(CHAR)
            lpValueName = ctypes.create_string_buffer(cchValueName.value)
        else:
            cchValueName.value = cchValueName.value + sizeof(WCHAR)
            lpValueName = ctypes.create_unicode_buffer(cchValueName.value)

        if bGetData:
            Type = dwType.value

            if Type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):   # REG_DWORD_LITTLE_ENDIAN
                if cbData.value != sizeof(DWORD):
                    raise ValueError("REG_DWORD value of size %d" % cbData.value)
                Data = DWORD(0)

            elif Type == REG_QWORD:   # REG_QWORD_LITTLE_ENDIAN
                if cbData.value != sizeof(QWORD):
                    raise ValueError("REG_QWORD value of size %d" % cbData.value)
                Data = QWORD(0L)

            elif Type in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
                if ansi:
                    Data = ctypes.create_string_buffer(cbData.value)
                else:
                    Data = ctypes.create_unicode_buffer(cbData.value)

            elif Type == REG_LINK:
                Data = ctypes.create_unicode_buffer(cbData.value)

            else:       # REG_BINARY, REG_NONE, and any future types
                Data = ctypes.create_string_buffer(cbData.value)

            lpData = byref(Data)

        errcode = _RegEnumValue(hKey, dwIndex, lpValueName, lpcchValueName, None, lpType, lpData, lpcbData)

    if errcode == ERROR_NO_MORE_ITEMS:
        return None
    #if errcode  != ERROR_SUCCESS:
    #    raise ctypes.WinError(errcode)

    if not bGetData:
        return lpValueName.value, dwType.value

    if Type in (REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD, REG_SZ, REG_EXPAND_SZ, REG_LINK): # REG_DWORD_LITTLE_ENDIAN, REG_QWORD_LITTLE_ENDIAN
        return lpValueName.value, dwType.value, Data.value

    if Type == REG_MULTI_SZ:
        sData = Data[:]
        del Data
        if ansi:
            aData = sData.split('\0')
        else:
            aData = sData.split(u'\0')
        aData = [token for token in aData if token]
        return lpValueName.value, dwType.value, aData

    # REG_BINARY, REG_NONE, and any future types
    return lpValueName.value, dwType.value, Data.raw

def RegEnumValueA(hKey, dwIndex, bGetData = True):
    return _internal_RegEnumValue(True, hKey, dwIndex, bGetData)

def RegEnumValueW(hKey, dwIndex, bGetData = True):
    return _internal_RegEnumValue(False, hKey, dwIndex, bGetData)

RegEnumValue = DefaultStringType(RegEnumValueA, RegEnumValueW)

# XXX TODO

# LONG WINAPI RegSetKeyValue(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpSubKey,
#   __in_opt  LPCTSTR lpValueName,
#   __in      DWORD dwType,
#   __in_opt  LPCVOID lpData,
#   __in      DWORD cbData
# );

# XXX TODO

# LONG WINAPI RegQueryMultipleValues(
#   __in         HKEY hKey,
#   __out        PVALENT val_list,
#   __in         DWORD num_vals,
#   __out_opt    LPTSTR lpValueBuf,
#   __inout_opt  LPDWORD ldwTotsize
# );

# XXX TODO

# LONG WINAPI RegDeleteValue(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpValueName
# );
def RegDeleteValueA(hKeySrc, lpValueName = None):
    _RegDeleteValueA = windll.advapi32.RegDeleteValueA
    _RegDeleteValueA.argtypes = [HKEY, LPSTR]
    _RegDeleteValueA.restype  = LONG
    _RegDeleteValueA.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteValueA(hKeySrc, lpValueName)
def RegDeleteValueW(hKeySrc, lpValueName = None):
    _RegDeleteValueW = windll.advapi32.RegDeleteValueW
    _RegDeleteValueW.argtypes = [HKEY, LPWSTR]
    _RegDeleteValueW.restype  = LONG
    _RegDeleteValueW.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteValueW(hKeySrc, lpValueName)
RegDeleteValue = GuessStringType(RegDeleteValueA, RegDeleteValueW)

# LONG WINAPI RegDeleteKeyValue(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpSubKey,
#   __in_opt  LPCTSTR lpValueName
# );
def RegDeleteKeyValueA(hKeySrc, lpSubKey = None, lpValueName = None):
    _RegDeleteKeyValueA = windll.advapi32.RegDeleteKeyValueA
    _RegDeleteKeyValueA.argtypes = [HKEY, LPSTR, LPSTR]
    _RegDeleteKeyValueA.restype  = LONG
    _RegDeleteKeyValueA.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyValueA(hKeySrc, lpSubKey, lpValueName)
def RegDeleteKeyValueW(hKeySrc, lpSubKey = None, lpValueName = None):
    _RegDeleteKeyValueW = windll.advapi32.RegDeleteKeyValueW
    _RegDeleteKeyValueW.argtypes = [HKEY, LPWSTR, LPWSTR]
    _RegDeleteKeyValueW.restype  = LONG
    _RegDeleteKeyValueW.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyValueW(hKeySrc, lpSubKey, lpValueName)
RegDeleteKeyValue = GuessStringType(RegDeleteKeyValueA, RegDeleteKeyValueW)

# LONG WINAPI RegDeleteKey(
#   __in  HKEY hKey,
#   __in  LPCTSTR lpSubKey
# );
def RegDeleteKeyA(hKeySrc, lpSubKey = None):
    _RegDeleteKeyA = windll.advapi32.RegDeleteKeyA
    _RegDeleteKeyA.argtypes = [HKEY, LPSTR]
    _RegDeleteKeyA.restype  = LONG
    _RegDeleteKeyA.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyA(hKeySrc, lpSubKey)
def RegDeleteKeyW(hKeySrc, lpSubKey = None):
    _RegDeleteKeyW = windll.advapi32.RegDeleteKeyW
    _RegDeleteKeyW.argtypes = [HKEY, LPWSTR]
    _RegDeleteKeyW.restype  = LONG
    _RegDeleteKeyW.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyW(hKeySrc, lpSubKey)
RegDeleteKey = GuessStringType(RegDeleteKeyA, RegDeleteKeyW)

# LONG WINAPI RegDeleteKeyEx(
#   __in        HKEY hKey,
#   __in        LPCTSTR lpSubKey,
#   __in        REGSAM samDesired,
#   __reserved  DWORD Reserved
# );

def RegDeleteKeyExA(hKeySrc, lpSubKey = None, samDesired = KEY_WOW64_32KEY):
    _RegDeleteKeyExA = windll.advapi32.RegDeleteKeyExA
    _RegDeleteKeyExA.argtypes = [HKEY, LPSTR, REGSAM, DWORD]
    _RegDeleteKeyExA.restype  = LONG
    _RegDeleteKeyExA.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyExA(hKeySrc, lpSubKey, samDesired, 0)
def RegDeleteKeyExW(hKeySrc, lpSubKey = None, samDesired = KEY_WOW64_32KEY):
    _RegDeleteKeyExW = windll.advapi32.RegDeleteKeyExW
    _RegDeleteKeyExW.argtypes = [HKEY, LPWSTR, REGSAM, DWORD]
    _RegDeleteKeyExW.restype  = LONG
    _RegDeleteKeyExW.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteKeyExW(hKeySrc, lpSubKey, samDesired, 0)
RegDeleteKeyEx = GuessStringType(RegDeleteKeyExA, RegDeleteKeyExW)

# LONG WINAPI RegCopyTree(
#   __in      HKEY hKeySrc,
#   __in_opt  LPCTSTR lpSubKey,
#   __in      HKEY hKeyDest
# );
def RegCopyTreeA(hKeySrc, lpSubKey, hKeyDest):
    _RegCopyTreeA = windll.advapi32.RegCopyTreeA
    _RegCopyTreeA.argtypes = [HKEY, LPSTR, HKEY]
    _RegCopyTreeA.restype  = LONG
    _RegCopyTreeA.errcheck = RaiseIfNotErrorSuccess
    _RegCopyTreeA(hKeySrc, lpSubKey, hKeyDest)
def RegCopyTreeW(hKeySrc, lpSubKey, hKeyDest):
    _RegCopyTreeW = windll.advapi32.RegCopyTreeW
    _RegCopyTreeW.argtypes = [HKEY, LPWSTR, HKEY]
    _RegCopyTreeW.restype  = LONG
    _RegCopyTreeW.errcheck = RaiseIfNotErrorSuccess
    _RegCopyTreeW(hKeySrc, lpSubKey, hKeyDest)
RegCopyTree = GuessStringType(RegCopyTreeA, RegCopyTreeW)

# LONG WINAPI RegDeleteTree(
#   __in      HKEY hKey,
#   __in_opt  LPCTSTR lpSubKey
# );
def RegDeleteTreeA(hKey, lpSubKey = None):
    _RegDeleteTreeA = windll.advapi32.RegDeleteTreeA
    _RegDeleteTreeA.argtypes = [HKEY, LPWSTR]
    _RegDeleteTreeA.restype  = LONG
    _RegDeleteTreeA.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteTreeA(hKey, lpSubKey)
def RegDeleteTreeW(hKey, lpSubKey = None):
    _RegDeleteTreeW = windll.advapi32.RegDeleteTreeW
    _RegDeleteTreeW.argtypes = [HKEY, LPWSTR]
    _RegDeleteTreeW.restype  = LONG
    _RegDeleteTreeW.errcheck = RaiseIfNotErrorSuccess
    _RegDeleteTreeW(hKey, lpSubKey)
RegDeleteTree = GuessStringType(RegDeleteTreeA, RegDeleteTreeW)

# LONG WINAPI RegFlushKey(
#   __in  HKEY hKey
# );
def RegFlushKey(hKey):
    _RegFlushKey = windll.advapi32.RegFlushKey
    _RegFlushKey.argtypes = [HKEY]
    _RegFlushKey.restype  = LONG
    _RegFlushKey.errcheck = RaiseIfNotErrorSuccess
    _RegFlushKey(hKey)
