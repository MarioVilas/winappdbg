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
        lpImageBase = (LPVOID * (size // unit))()
        success = ctypes.windll.psapi.EnumDeviceDrivers(ctypes.byref(lpImageBase), lpcbNeeded, ctypes.byref(lpcbNeeded))
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lpImageBase[index] for index in xrange(0, (needed // unit)) ]

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
        ProcessIds = (DWORD * (size // unit))()
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
        lphModule = (HMODULE * (size // unit))()
        success = ctypes.windll.psapi.EnumProcessModules(hProcess, ctypes.byref(lphModule), lpcbNeeded, ctypes.byref(lpcbNeeded))
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in xrange(0, int(needed // unit)) ]

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
        lphModule = (HMODULE * (size // unit))()
        success = ctypes.windll.psapi.EnumProcessModulesEx(hProcess, ctypes.byref(lphModule), lpcbNeeded, ctypes.byref(lpcbNeeded), dwFilterFlag)
        if success == FALSE:
            raise ctypes.WinError()
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in xrange(0, (needed // unit)) ]

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
GetDeviceDriverBaseName = GuessStringType(GetDeviceDriverBaseNameA, GetDeviceDriverBaseNameW)

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
GetDeviceDriverFileName = GuessStringType(GetDeviceDriverFileNameA, GetDeviceDriverFileNameW)

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
        nCopied = ctypes.windll.psapi.GetMappedFileNameA(hProcess, lpv, ctypes.byref(lpFilename), nSize)
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
        nCopied = ctypes.windll.psapi.GetMappedFileNameW(hProcess, lpv, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetMappedFileName = GuessStringType(GetMappedFileNameA, GetMappedFileNameW)

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
        nCopied = ctypes.windll.psapi.GetModuleFileNameExA(hProcess, hModule, ctypes.byref(lpFilename), nSize)
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
        nCopied = ctypes.windll.psapi.GetModuleFileNameExW(hProcess, hModule, ctypes.byref(lpFilename), nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value
GetModuleFileNameEx = GuessStringType(GetModuleFileNameExA, GetModuleFileNameExW)

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
GetProcessImageFileName = GuessStringType(GetProcessImageFileNameA, GetProcessImageFileNameW)
