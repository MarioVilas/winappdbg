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

UNDNAME_32_BIT_DECODE           = 0x0800
UNDNAME_COMPLETE                = 0x0000
UNDNAME_NAME_ONLY               = 0x1000
UNDNAME_NO_ACCESS_SPECIFIERS    = 0x0080
UNDNAME_NO_ALLOCATION_LANGUAGE  = 0x0010
UNDNAME_NO_ALLOCATION_MODEL     = 0x0008
UNDNAME_NO_ARGUMENTS            = 0x2000
UNDNAME_NO_CV_THISTYPE          = 0x0040
UNDNAME_NO_FUNCTION_RETURNS     = 0x0004
UNDNAME_NO_LEADING_UNDERSCORES  = 0x0001
UNDNAME_NO_MEMBER_TYPE          = 0x0200
UNDNAME_NO_MS_KEYWORDS          = 0x0002
UNDNAME_NO_MS_THISTYPE          = 0x0020
UNDNAME_NO_RETURN_UDT_MODEL     = 0x0400
UNDNAME_NO_SPECIAL_SYMS         = 0x4000
UNDNAME_NO_THISTYPE             = 0x0060
UNDNAME_NO_THROW_SIGNATURES     = 0x0100

#--- IMAGEHLP_MODULE structure and related ------------------------------------

SYMOPT_ALLOW_ABSOLUTE_SYMBOLS       = 0x00000800
SYMOPT_ALLOW_ZERO_ADDRESS           = 0x01000000
SYMOPT_AUTO_PUBLICS                 = 0x00010000
SYMOPT_CASE_INSENSITIVE             = 0x00000001
SYMOPT_DEBUG                        = 0x80000000
SYMOPT_DEFERRED_LOADS               = 0x00000004
SYMOPT_DISABLE_SYMSRV_AUTODETECT    = 0x02000000
SYMOPT_EXACT_SYMBOLS                = 0x00000400
SYMOPT_FAIL_CRITICAL_ERRORS         = 0x00000200
SYMOPT_FAVOR_COMPRESSED             = 0x00800000
SYMOPT_FLAT_DIRECTORY               = 0x00400000
SYMOPT_IGNORE_CVREC                 = 0x00000080
SYMOPT_IGNORE_IMAGEDIR              = 0x00200000
SYMOPT_IGNORE_NT_SYMPATH            = 0x00001000
SYMOPT_INCLUDE_32BIT_MODULES        = 0x00002000
SYMOPT_LOAD_ANYTHING                = 0x00000040
SYMOPT_LOAD_LINES                   = 0x00000010
SYMOPT_NO_CPP                       = 0x00000008
SYMOPT_NO_IMAGE_SEARCH              = 0x00020000
SYMOPT_NO_PROMPTS                   = 0x00080000
SYMOPT_NO_PUBLICS                   = 0x00008000
SYMOPT_NO_UNQUALIFIED_LOADS         = 0x00000100
SYMOPT_OVERWRITE                    = 0x00100000
SYMOPT_PUBLICS_ONLY                 = 0x00004000
SYMOPT_SECURE                       = 0x00040000
SYMOPT_UNDNAME                      = 0x00000002

##SSRVOPT_DWORD
##SSRVOPT_DWORDPTR
##SSRVOPT_GUIDPTR
##
##SSRVOPT_CALLBACK
##SSRVOPT_DOWNSTREAM_STORE
##SSRVOPT_FLAT_DEFAULT_STORE
##SSRVOPT_FAVOR_COMPRESSED
##SSRVOPT_NOCOPY
##SSRVOPT_OVERWRITE
##SSRVOPT_PARAMTYPE
##SSRVOPT_PARENTWIN
##SSRVOPT_PROXY
##SSRVOPT_RESET
##SSRVOPT_SECURE
##SSRVOPT_SETCONTEXT
##SSRVOPT_TRACE
##SSRVOPT_UNATTENDED

#    typedef enum
#    {
#        SymNone = 0,
#        SymCoff,
#        SymCv,
#        SymPdb,
#        SymExport,
#        SymDeferred,
#        SymSym,
#        SymDia,
#        SymVirtual,
#        NumSymTypes
#    } SYM_TYPE;
SymNone     = 0
SymCoff     = 1
SymCv       = 2
SymPdb      = 3
SymExport   = 4
SymDeferred = 5
SymSym      = 6
SymDia      = 7
SymVirtual  = 8
NumSymTypes = 9

#    typedef struct _IMAGEHLP_MODULE64 {
#      DWORD    SizeOfStruct;
#      DWORD64  BaseOfImage;
#      DWORD    ImageSize;
#      DWORD    TimeDateStamp;
#      DWORD    CheckSum;
#      DWORD    NumSyms;
#      SYM_TYPE SymType;
#      TCHAR    ModuleName[32];
#      TCHAR    ImageName[256];
#      TCHAR    LoadedImageName[256];
#      TCHAR    LoadedPdbName[256];
#      DWORD    CVSig;
#      TCHAR    CVData[MAX_PATH*3];
#      DWORD    PdbSig;
#      GUID     PdbSig70;
#      DWORD    PdbAge;
#      BOOL     PdbUnmatched;
#      BOOL     DbgUnmatched;
#      BOOL     LineNumbers;
#      BOOL     GlobalSymbols;
#      BOOL     TypeInfo;
#      BOOL     SourceIndexed;
#      BOOL     Publics;
#    } IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;

class IMAGEHLP_MODULE (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
    ]
PIMAGEHLP_MODULE = POINTER(IMAGEHLP_MODULE)

class IMAGEHLP_MODULE64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
        ("LoadedPdbName",   CHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          CHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULE64 = POINTER(IMAGEHLP_MODULE64)

class IMAGEHLP_MODULEW (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
    ]
PIMAGEHLP_MODULEW = POINTER(IMAGEHLP_MODULEW)

class IMAGEHLP_MODULEW64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
        ("LoadedPdbName",   WCHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          WCHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULEW64 = POINTER(IMAGEHLP_MODULEW64)

#--- dbghelp.dll --------------------------------------------------------------

# XXX the ANSI versions of these functions don't end in "A" as expected!

# BOOL WINAPI SymInitialize(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR UserSearchPath,
#   __in      BOOL fInvadeProcess
# );
def SymInitialize(hProcess, UserSearchPath = None, fInvadeProcess = False):
    _SymInitialize = windll.dbghelp.SymInitialize
    _SymInitialize.argtypes = [HANDLE, LPSTR, BOOL]
    _SymInitialize.restype = bool
    _SymInitialize.errcheck = RaiseIfZero
    if not UserSearchPath:
        UserSearchPath = None
    _SymInitialize(hProcess, UserSearchPath, fInvadeProcess)

# BOOL WINAPI SymCleanup(
#   __in  HANDLE hProcess
# );
def SymCleanup(hProcess):
    _SymCleanup = windll.dbghelp.SymCleanup
    _SymCleanup.argtypes = [HANDLE]
    _SymCleanup.restype = bool
    _SymCleanup.errcheck = RaiseIfZero
    _SymCleanup(hProcess)

# BOOL WINAPI SymRefreshModuleList(
#   __in  HANDLE hProcess
# );
def SymRefreshModuleList(hProcess):
    _SymRefreshModuleList = windll.dbghelp.SymRefreshModuleList
    _SymRefreshModuleList.argtypes = [HANDLE]
    _SymRefreshModuleList.restype = bool
    _SymRefreshModuleList.errcheck = RaiseIfZero
    _SymRefreshModuleList(hProcess)

# BOOL WINAPI SymSetParentWindow(
#   __in  HWND hwnd
# );
def SymSetParentWindow(hwnd):
    _SymSetParentWindow = windll.dbghelp.SymSetParentWindow
    _SymSetParentWindow.argtypes = [HWND]
    _SymSetParentWindow.restype = bool
    _SymSetParentWindow.errcheck = RaiseIfZero
    _SymSetParentWindow(hwnd)

# DWORD WINAPI SymSetOptions(
#   __in  DWORD SymOptions
# );
def SymSetOptions(SymOptions):
    _SymSetOptions = windll.dbghelp.SymSetOptions
    _SymSetOptions.argtypes = [DWORD]
    _SymSetOptions.restype = DWORD
    _SymSetOptions.errcheck = RaiseIfZero
    _SymSetOptions(SymOptions)

# DWORD WINAPI SymGetOptions(void);
def SymGetOptions():
    _SymGetOptions = windll.dbghelp.SymGetOptions
    _SymGetOptions.argtypes = []
    _SymGetOptions.restype = DWORD
    return _SymGetOptions()

# DWORD WINAPI SymLoadModule(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD BaseOfDll,
#   __in      DWORD SizeOfDll
# );
def SymLoadModule(hProcess, hFile = None, ImageName = None, ModuleName = None, BaseOfDll = None, SizeOfDll = None):
    _SymLoadModule = windll.dbghelp.SymLoadModule
    _SymLoadModule.argtypes = [HANDLE, HANDLE, LPSTR, LPSTR, DWORD, DWORD]
    _SymLoadModule.restype = DWORD
    
    if not ImageName:
        ImageName = None
    if not ModuleName:
        ModuleName = None
    if not BaseOfDll:
        BaseOfDll = 0
    if not SizeOfDll:
        SizeOfDll = 0
    lpBaseAddress = _SymLoadModule(hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll)
    if lpBaseAddress == NULL:
        dwErrorCode = GetLastError()
        if dwErrorCode != ERROR_SUCCESS:
            raise ctypes.WinError(dwErrorCode)
    return lpBaseAddress

# DWORD64 WINAPI SymLoadModule64(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in      DWORD SizeOfDll
# );
def SymLoadModule64(hProcess, hFile = None, ImageName = None, ModuleName = None, BaseOfDll = None, SizeOfDll = None):
    _SymLoadModule64 = windll.dbghelp.SymLoadModule64
    _SymLoadModule64.argtypes = [HANDLE, HANDLE, LPSTR, LPSTR, DWORD64, DWORD]
    _SymLoadModule64.restype = DWORD64

    if not ImageName:
        ImageName = None
    if not ModuleName:
        ModuleName = None
    if not BaseOfDll:
        BaseOfDll = 0
    if not SizeOfDll:
        SizeOfDll = 0
    lpBaseAddress = _SymLoadModule64(hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll)
    if lpBaseAddress == NULL:
        dwErrorCode = GetLastError()
        if dwErrorCode != ERROR_SUCCESS:
            raise ctypes.WinError(dwErrorCode)
    return lpBaseAddress

# BOOL WINAPI SymUnloadModule(
#   __in  HANDLE hProcess,
#   __in  DWORD BaseOfDll
# );
def SymUnloadModule(hProcess, BaseOfDll):
    _SymUnloadModule = windll.dbghelp.SymUnloadModule
    _SymUnloadModule.argtypes = [HANDLE, DWORD]
    _SymUnloadModule.restype = bool
    _SymUnloadModule.errcheck = RaiseIfZero
    _SymUnloadModule(hProcess, BaseOfDll)

# BOOL WINAPI SymUnloadModule64(
#   __in  HANDLE hProcess,
#   __in  DWORD64 BaseOfDll
# );
def SymUnloadModule64(hProcess, BaseOfDll):
    _SymUnloadModule64 = windll.dbghelp.SymUnloadModule64
    _SymUnloadModule64.argtypes = [HANDLE, DWORD64]
    _SymUnloadModule64.restype = bool
    _SymUnloadModule64.errcheck = RaiseIfZero
    _SymUnloadModule64(hProcess, BaseOfDll)

# BOOL WINAPI SymGetModuleInfo(
#   __in   HANDLE hProcess,
#   __in   DWORD dwAddr,
#   __out  PIMAGEHLP_MODULE ModuleInfo
# );
def SymGetModuleInfoA(hProcess, dwAddr):
    _SymGetModuleInfo = windll.dbghelp.SymGetModuleInfo
    _SymGetModuleInfo.argtypes = [HANDLE, DWORD, PIMAGEHLP_MODULE]
    _SymGetModuleInfo.restype = bool
    _SymGetModuleInfo.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULE()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfo(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    return ModuleInfo

def SymGetModuleInfoW(hProcess, dwAddr):
    _SymGetModuleInfoW = windll.dbghelp.SymGetModuleInfoW
    _SymGetModuleInfoW.argtypes = [HANDLE, DWORD, PIMAGEHLP_MODULEW]
    _SymGetModuleInfoW.restype = bool
    _SymGetModuleInfoW.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULEW()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfoW(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    return ModuleInfo

SymGetModuleInfo = GuessStringType(SymGetModuleInfoA, SymGetModuleInfoW)

# BOOL WINAPI SymGetModuleInfo64(
#   __in   HANDLE hProcess,
#   __in   DWORD64 dwAddr,
#   __out  PIMAGEHLP_MODULE64 ModuleInfo
# );
def SymGetModuleInfo64A(hProcess, dwAddr):
    _SymGetModuleInfo64 = windll.dbghelp.SymGetModuleInfo64
    _SymGetModuleInfo64.argtypes = [HANDLE, DWORD64, PIMAGEHLP_MODULE64]
    _SymGetModuleInfo64.restype = bool
    _SymGetModuleInfo64.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULE64()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfo64(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    return ModuleInfo

def SymGetModuleInfo64W(hProcess, dwAddr):
    _SymGetModuleInfo64W = windll.dbghelp.SymGetModuleInfo64W
    _SymGetModuleInfo64W.argtypes = [HANDLE, DWORD64, PIMAGEHLP_MODULE64W]
    _SymGetModuleInfo64W.restype = bool
    _SymGetModuleInfo64W.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULE64W()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfo64W(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    return ModuleInfo

SymGetModuleInfo64 = GuessStringType(SymGetModuleInfo64A, SymGetModuleInfo64W)

# BOOL CALLBACK SymEnumerateModulesProc(
#   __in      PCTSTR ModuleName,
#   __in      DWORD BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK    = WINFUNCTYPE(BOOL, LPSTR,  DWORD,   PVOID)
PSYM_ENUMMODULES_CALLBACKW   = WINFUNCTYPE(BOOL, LPWSTR, DWORD,   PVOID)

# BOOL CALLBACK SymEnumerateModulesProc64(
#   __in      PCTSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK64  = WINFUNCTYPE(BOOL, LPSTR,  DWORD64, PVOID)
PSYM_ENUMMODULES_CALLBACKW64 = WINFUNCTYPE(BOOL, LPWSTR, DWORD64, PVOID)

# BOOL WINAPI SymEnumerateModules(
#   __in      HANDLE hProcess,
#   __in      PSYM_ENUMMODULES_CALLBACK EnumModulesCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateModulesA(hProcess, EnumModulesCallback, UserContext = None):
    _SymEnumerateModules = windll.dbghelp.SymEnumerateModules
    _SymEnumerateModules.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACK, PVOID]
    _SymEnumerateModules.restype = bool
    _SymEnumerateModules.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModules(hProcess, EnumModulesCallback, UserContext)

def SymEnumerateModulesW(hProcess, EnumModulesCallback, UserContext = None):
    _SymEnumerateModulesW = windll.dbghelp.SymEnumerateModulesW
    _SymEnumerateModulesW.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACKW, PVOID]
    _SymEnumerateModulesW.restype = bool
    _SymEnumerateModulesW.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACKW(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModulesW(hProcess, EnumModulesCallback, UserContext)

SymEnumerateModules = GuessStringType(SymEnumerateModulesA, SymEnumerateModulesW)

# BOOL WINAPI SymEnumerateModules64(
#   __in      HANDLE hProcess,
#   __in      PSYM_ENUMMODULES_CALLBACK64 EnumModulesCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateModules64A(hProcess, EnumModulesCallback, UserContext = None):
    _SymEnumerateModules64 = windll.dbghelp.SymEnumerateModules64
    _SymEnumerateModules64.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACK64, PVOID]
    _SymEnumerateModules64.restype = bool
    _SymEnumerateModules64.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK64(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext)

def SymEnumerateModules64W(hProcess, EnumModulesCallback, UserContext = None):
    _SymEnumerateModules64W = windll.dbghelp.SymEnumerateModules64W
    _SymEnumerateModules64W.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACK64W, PVOID]
    _SymEnumerateModules64W.restype = bool
    _SymEnumerateModules64W.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK64W(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModules64W(hProcess, EnumModulesCallback, UserContext)

SymEnumerateModules64 = GuessStringType(SymEnumerateModules64A, SymEnumerateModules64W)

# BOOL CALLBACK SymEnumerateSymbolsProc(
#   __in      PCTSTR SymbolName,
#   __in      DWORD SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK    = WINFUNCTYPE(BOOL, LPSTR,  DWORD,   ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW   = WINFUNCTYPE(BOOL, LPWSTR, DWORD,   ULONG, PVOID)

# BOOL CALLBACK SymEnumerateSymbolsProc64(
#   __in      PCTSTR SymbolName,
#   __in      DWORD64 SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK64  = WINFUNCTYPE(BOOL, LPSTR,  DWORD64, ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW64 = WINFUNCTYPE(BOOL, LPWSTR, DWORD64, ULONG, PVOID)

# BOOL WINAPI SymEnumerateSymbols(
#   __in      HANDLE hProcess,
#   __in      ULONG BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbolsA(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    _SymEnumerateSymbols = windll.dbghelp.SymEnumerateSymbols
    _SymEnumerateSymbols.argtypes = [HANDLE, ULONG, PSYM_ENUMSYMBOLS_CALLBACK, PVOID]
    _SymEnumerateSymbols.restype = bool
    _SymEnumerateSymbols.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbols(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

def SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    _SymEnumerateSymbolsW = windll.dbghelp.SymEnumerateSymbolsW
    _SymEnumerateSymbolsW.argtypes = [HANDLE, ULONG, PSYM_ENUMSYMBOLS_CALLBACKW, PVOID]
    _SymEnumerateSymbolsW.restype = bool
    _SymEnumerateSymbolsW.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACKW(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

SymEnumerateSymbols = GuessStringType(SymEnumerateSymbolsA, SymEnumerateSymbolsW)

# BOOL WINAPI SymEnumerateSymbols64(
#   __in      HANDLE hProcess,
#   __in      ULONG64 BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK64 EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbols64A(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    _SymEnumerateSymbols64 = windll.dbghelp.SymEnumerateSymbols64
    _SymEnumerateSymbols64.argtypes = [HANDLE, ULONG64, PSYM_ENUMSYMBOLS_CALLBACK64, PVOID]
    _SymEnumerateSymbols64.restype = bool
    _SymEnumerateSymbols64.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK64(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbols64(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

def SymEnumerateSymbols64W(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    _SymEnumerateSymbols64W = windll.dbghelp.SymEnumerateSymbols64W
    _SymEnumerateSymbols64W.argtypes = [HANDLE, ULONG64, PSYM_ENUMSYMBOLS_CALLBACK64W, PVOID]
    _SymEnumerateSymbols64W.restype = bool
    _SymEnumerateSymbols64W.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK64W(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbols64W(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

SymEnumerateSymbols64 = GuessStringType(SymEnumerateSymbols64A, SymEnumerateSymbols64W)

# DWORD WINAPI UnDecorateSymbolName(
#   __in   PCTSTR DecoratedName,
#   __out  PTSTR UnDecoratedName,
#   __in   DWORD UndecoratedLength,
#   __in   DWORD Flags
# );
def UnDecorateSymbolNameA(DecoratedName, Flags = UNDNAME_COMPLETE):
    _UnDecorateSymbolNameA = windll.dbghelp.UnDecorateSymbolName
    _UnDecorateSymbolNameA.argtypes = [LPSTR, LPSTR, DWORD, DWORD]
    _UnDecorateSymbolNameA.restype = DWORD
    _UnDecorateSymbolNameA.errcheck = RaiseIfZero

    UndecoratedLength = _UnDecorateSymbolNameA(DecoratedName, None, 0, Flags)
    UnDecoratedName = ctypes.create_string_buffer('', UndecoratedLength + 1)
    _UnDecorateSymbolNameA(DecoratedName, UnDecoratedName, UndecoratedLength, Flags)
    return UnDecoratedName.value

def UnDecorateSymbolNameW(DecoratedName, Flags = UNDNAME_COMPLETE):
    _UnDecorateSymbolNameW = windll.dbghelp.UnDecorateSymbolNameW
    _UnDecorateSymbolNameW.argtypes = [LPWSTR, LPWSTR, DWORD, DWORD]
    _UnDecorateSymbolNameW.restype = DWORD
    _UnDecorateSymbolNameW.errcheck = RaiseIfZero

    UndecoratedLength = _UnDecorateSymbolNameW(DecoratedName, None, 0, Flags)
    UnDecoratedName = ctypes.create_unicode_buffer(u'', UndecoratedLength + 1)
    _UnDecorateSymbolNameW(DecoratedName, UnDecoratedName, UndecoratedLength, Flags)
    return UnDecoratedName.value

UnDecorateSymbolName = GuessStringType(UnDecorateSymbolNameA, UnDecorateSymbolNameW)

# BOOL WINAPI SymGetSearchPath(
#   __in   HANDLE hProcess,
#   __out  PTSTR SearchPath,
#   __in   DWORD SearchPathLength
# );
def SymGetSearchPathA(hProcess):
    _SymGetSearchPath = windll.dbghelp.SymGetSearchPath
    _SymGetSearchPath.argtypes = [HANDLE, LPSTR, DWORD]
    _SymGetSearchPath.restype = bool
    _SymGetSearchPath.errcheck = RaiseIfZero

    SearchPathLength = MAX_PATH
    SearchPath = ctypes.create_string_buffer("", SearchPathLength)
    _SymGetSearchPath(hProcess, ctypes.byref(SearchPath), SearchPathLength)
    return SearchPath.value

def SymGetSearchPathW(hProcess):
    _SymGetSearchPathW = windll.dbghelp.SymGetSearchPathW
    _SymGetSearchPathW.argtypes = [HANDLE, LPWSTR, DWORD]
    _SymGetSearchPathW.restype = bool
    _SymGetSearchPathW.errcheck = RaiseIfZero

    SearchPathLength = MAX_PATH
    SearchPath = ctypes.create_unicode_buffer("", SearchPathLength)
    _SymGetSearchPathW(hProcess, ctypes.byref(SearchPath), SearchPathLength)
    return SearchPath.value

SymGetSearchPath = GuessStringType(SymGetSearchPathA, SymGetSearchPathW)

# BOOL WINAPI SymSetSearchPath(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR SearchPath
# );
def SymSetSearchPathA(hProcess, SearchPath = None):
    _SymSetSearchPath = windll.dbghelp.SymSetSearchPath
    _SymSetSearchPath.argtypes = [HANDLE, LPSTR]
    _SymSetSearchPath.restype = bool
    _SymSetSearchPath.errcheck = RaiseIfZero
    if not SearchPath:
        SearchPath = None
    _SymSetSearchPath(hProcess, SearchPath)

def SymSetSearchPathW(hProcess, SearchPath = None):
    _SymSetSearchPathW = windll.dbghelp.SymSetSearchPathW
    _SymSetSearchPathW.argtypes = [HANDLE, LPWSTR]
    _SymSetSearchPathW.restype = bool
    _SymSetSearchPathW.errcheck = RaiseIfZero
    if not SearchPath:
        SearchPath = None
    _SymSetSearchPathW(hProcess, SearchPath)

SymSetSearchPath = GuessStringType(SymSetSearchPathA, SymSetSearchPathW)
