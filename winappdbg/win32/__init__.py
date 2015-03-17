#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2015, Mario Vilas
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
"""

#-----------------------------------------------------------------------------
# Monkey patch for Cygwin, which does not load some features correctly since
# it believes to be running on Linux.

# Detect whether we need to patch or not.
try:
    from ctypes import WINFUNCTYPE
except ImportError:
    import ctypes

    # Fix FormatError.
    ##from _ctypes import FormatError
    ##ctypes.FormatError = FormatError

    # Fix FUNCFLAG_STDCALL.
    ctypes.FUNCFLAG_STDCALL = FUNCFLAG_STDCALL = _FUNCFLAG_STDCALL = 0

    # Fix WINFUNCTYPE.
    _win_functype_cache = {}
    def WINFUNCTYPE(restype, *argtypes, **kw):
        flags = _FUNCFLAG_STDCALL
        if kw.pop("use_errno", False):
            flags |= ctypes._FUNCFLAG_USE_ERRNO
        if kw.pop("use_last_error", False):
            flags |= ctypes._FUNCFLAG_USE_LASTERROR
        if kw:
            raise ValueError("unexpected keyword argument(s) %s" % kw.keys())
        try:
            return _win_functype_cache[(restype, argtypes, flags)]
        except KeyError:
            class WinFunctionType(ctypes._CFuncPtr):
                _argtypes_ = argtypes
                _restype_ = restype
                _flags_ = flags
            _win_functype_cache[(restype, argtypes, flags)] = WinFunctionType
            return WinFunctionType
    if WINFUNCTYPE.__doc__:
        WINFUNCTYPE.__doc__ = ctypes.CFUNCTYPE.__doc__.replace(
            "CFUNCTYPE", "WINFUNCTYPE")
    ctypes.WINFUNCTYPE = WINFUNCTYPE

    # Fix _reset_cache.
    _original_reset_cache = ctypes._reset_cache
    def _reset_cache():
        ctypes._win_functype_cache.clear()
        _original_reset_cache()
    ctypes._reset_cache = _reset_cache

    # Fix the string conversion mode.
    if hasattr(ctypes, "set_conversion_mode"):
        ctypes.set_conversion_mode("mbcs", "ignore")

    # Fix WinDLL.
    class WinDLL(ctypes.CDLL):
        """This class represents a dll exporting functions using the
        Windows stdcall calling convention.
        """
        _func_flags_ = _FUNCFLAG_STDCALL
    ctypes.WinDLL = WinDLL

    # Fix HRESULT.
    from _ctypes import _SimpleCData
    class HRESULT(_SimpleCData):
        _type_ = "l"
        ##_check_retval_ = _check_HRESULT
    ctypes.HRESULT = HRESULT

    # Fix OleDLL.
    class OleDLL(ctypes.CDLL):
        """This class represents a dll exporting functions using the
        Windows stdcall calling convention, and returning HRESULT.
        HRESULT error values are automatically raised as WindowsError
        exceptions.
        """
        _func_flags_ = _FUNCFLAG_STDCALL
        _func_restype_ = HRESULT
    ctypes.OleDLL = OleDLL

    # Fix windll, oledll and GetLastError.
    ctypes.windll = ctypes.LibraryLoader(WinDLL)
    ctypes.oledll = ctypes.LibraryLoader(OleDLL)
    ctypes.GetLastError = ctypes.windll.kernel32.GetLastError

    # Fix get_last_error and set_last_error.
    ctypes.get_last_error = ctypes.windll.kernel32.GetLastError
    ctypes.set_last_error = ctypes.windll.kernel32.SetLastError

    # Fix FormatError.
    def FormatError(code):
        code = int(long(code))
        try:
            if GuessStringType.t_default == GuessStringType.t_ansi:
                FormatMessage = windll.kernel32.FormatMessageA
                FormatMessage.argtypes = [DWORD, LPVOID, DWORD, DWORD, LPSTR, DWORD]
                FormatMessage.restype  = DWORD
                lpBuffer = ctypes.create_string_buffer(1024)
            else:
                FormatMessage = windll.kernel32.FormatMessageW
                FormatMessage.argtypes = [DWORD, LPVOID, DWORD, DWORD, LPWSTR, DWORD]
                FormatMessage.restype  = DWORD
                lpBuffer = ctypes.create_unicode_buffer(1024)
            ##FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
            ##FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
            success = FormatMessage(0x1200, None, code, 0, lpBuffer, 1024)
            if success:
                return lpBuffer.value
        except Exception:
            pass
        if GuessStringType.t_default == GuessStringType.t_ansi:
            return "Error code 0x%.8X" % code
        return u"Error code 0x%.8X" % code
    ctypes.FormatError = FormatError

    # Fix WinError.
    def WinError(code=None, descr=None):
        if code is None:
            code = ctypes.GetLastError()
        if descr is None:
            descr = ctypes.FormatError(code).strip()
        return WindowsError(code, descr)
    ctypes.WinError = WinError

    # Fix DllGetClassObject.
    def DllGetClassObject(rclsid, riid, ppv):
        try:
            ccom = __import__(
                "comtypes.server.inprocserver", globals(), locals(), ['*'])
        except ImportError:
            return -2147221231 # CLASS_E_CLASSNOTAVAILABLE
        else:
            return ccom.DllGetClassObject(rclsid, riid, ppv)
    ctypes.DllGetClassObject = DllGetClassObject

    # Fix DllCanUnloadNow.
    def DllCanUnloadNow():
        try:
            ccom = __import__(
                "comtypes.server.inprocserver", globals(), locals(), ['*'])
        except ImportError:
            return 0 # S_OK
        return ccom.DllCanUnloadNow()
    ctypes.DllCanUnloadNow = DllCanUnloadNow

#-----------------------------------------------------------------------------

# Import all submodules into this namespace.
# Required for compatibility with older versions of WinAppDbg.
import defines
import kernel32
import user32
import advapi32
import wtsapi32
import shell32
import shlwapi
import psapi
import dbghelp
import ntdll

# Import all symbols from submodules into this namespace.
# Required for compatibility with older versions of WinAppDbg.
from defines    import *
from kernel32   import *
from user32     import *
from advapi32   import *
from wtsapi32   import *
from shell32    import *
from shlwapi    import *
from psapi      import *
from dbghelp    import *
from ntdll      import *

# This calculates the list of exported symbols.
_all = set()
_all.update(defines._all)
_all.update(kernel32._all)
_all.update(user32._all)
_all.update(advapi32._all)
_all.update(wtsapi32._all)
_all.update(shell32._all)
_all.update(shlwapi._all)
_all.update(psapi._all)
_all.update(dbghelp._all)
_all.update(ntdll._all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
