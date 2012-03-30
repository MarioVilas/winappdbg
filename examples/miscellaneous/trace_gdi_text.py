#!~/.wine/drive_c/Python25/python.exe
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

# $Id$

from winappdbg import Debug, EventHandler, DebugLog
from ctypes import *

#------------------------------------------------------------------------------

# BOOL TextOut(
#   __in  HDC hdc,
#   __in  int nXStart,
#   __in  int nYStart,
#   __in  LPCTSTR lpString,
#   __in  int cbString
# );

def TextOutA(event, ra, hdc, nXStart, nYStart, lpString, cbString):
    log_ansi(event, "TextOutA", lpString, cbString)

def TextOutW(event, ra, hdc, nXStart, nYStart, lpString, cbString):
    log_wide(event, "TextOutW", lpString, cbString)

# BOOL ExtTextOut(
#   __in  HDC hdc,
#   __in  int X,
#   __in  int Y,
#   __in  UINT fuOptions,
#   __in  const RECT *lprc,
#   __in  LPCTSTR lpString,
#   __in  UINT cbCount,
#   __in  const INT *lpDx
# );
def ExtTextOutA(event, ra, hdc, X, Y, fuOptions, lprc, lpString, cbCount, lpDx):
    log_ansi(event, "ExtTextOutA", lpString, cbCount)

def ExtTextOutW(event, ra, hdc, X, Y, fuOptions, lprc, lpString, cbCount, lpDx):
    log_wide(event, "ExtTextOutW", lpString, cbCount)

# typedef struct _POLYTEXT {
#   int     x;
#   int     y;
#   UINT    n;
#   LPCTSTR lpstr;
#   UINT    uiFlags;
#   RECT    rcl;
#   int     *pdx;
# } POLYTEXT, *PPOLYTEXT;
class POLYTEXT(Structure):
    _fields_ = [
        ('x',       c_int),
        ('y',       c_int),
        ('n',       c_uint),
        ('lpstr',   c_void_p),
        ('uiFlags', c_uint),
        ('rcl',     c_uint * 4),
        ('pdx',     POINTER(c_int)),
    ]

# BOOL PolyTextOut(
#   __in  HDC hdc,
#   __in  const POLYTEXT *pptxt,
#   __in  int cStrings
# );

def PolyTextOutA(event, ra, hdc, pptxt, cStrings):
    process = event.get_process()
    sizeof_polytext = sizeof(POLYTEXT)
    while cStrings:
        txt = process.read_structure(pptxt, POLYTEXT)
        log_ansi(event, "PolyTextOutA", txt.lpstr, txt.n)
        pptxt = pptxt + sizeof_polytext
        cStrings = cStrings - 1

def PolyTextOutW(event, ra, hdc, pptxt, cStrings):
    process = event.get_process()
    sizeof_polytext = sizeof(POLYTEXT)
    while cStrings:
        txt = process.read_structure(pptxt, POLYTEXT)
        log_wide(event, "PolyTextOutW", txt.lpstr, txt.n)
        pptxt = pptxt + sizeof_polytext
        cStrings = cStrings - 1

#------------------------------------------------------------------------------

def log_ansi(event, fn, lpString, nCount):
    if lpString and nCount:
        if c_int(nCount).value == -1:
            lpString = event.get_process().peek_string(lpString, fUnicode = False)
        else:
            lpString = event.get_process().peek(lpString, nCount)
        print DebugLog.log_text("%s( %r );" % (fn, lpString))

def log_wide(event, fn, lpString, nCount):
    if lpString and nCount:
        if c_int(nCount).value == -1:
            lpString = event.get_process().peek_string(lpString, fUnicode = True)
        else:
            lpString = event.get_process().peek(lpString, nCount * 2)
            lpString = unicode(lpString, 'U16', 'replace')
        print DebugLog.log_text("%s( %r );" % (fn, lpString))

class MyEventHandler( EventHandler ):
    def load_dll(self, event):
        pid = event.get_pid()
        module = event.get_module()
        if module.match_name("gdi32.dll"):
            event.debug.hook_function(pid, module.resolve("TextOutA"),       TextOutA,       paramCount = 5)
            event.debug.hook_function(pid, module.resolve("TextOutW"),       TextOutW,       paramCount = 5)
            event.debug.hook_function(pid, module.resolve("ExtTextOutA"),    ExtTextOutA,    paramCount = 8)
            event.debug.hook_function(pid, module.resolve("ExtTextOutW"),    ExtTextOutW,    paramCount = 8)
            event.debug.hook_function(pid, module.resolve("PolyTextOutA"),   PolyTextOutA,   paramCount = 2)
            event.debug.hook_function(pid, module.resolve("PolyTextOutW"),   PolyTextOutW,   paramCount = 2)

def simple_debugger(argv):
    print DebugLog.log_text("Trace started on %s" % argv[0])
    debug = Debug( MyEventHandler() )
    try:
        debug.execv(argv)
        debug.loop()
    finally:
        debug.stop()
    print DebugLog.log_text("Trace stopped on %s" % argv[0])

# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
