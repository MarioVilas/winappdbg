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
Advanced API.
"""

__revision__ = "$Id$"

from kernel import *

#--- Structures ---------------------------------------------------------------

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

#--- Functions ----------------------------------------------------------------

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
    success = ctypes.windll.advapi32.OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, ctypes.byref(TokenHandle))
    if success == FALSE:
        raise ctypes.WinError()
    return Handle(TokenHandle.value)

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
