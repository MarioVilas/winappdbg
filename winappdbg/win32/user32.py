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

# GetWindowLong / SetWindowLong / GetWindowLongPtr / SetWindowLongPtr
GWL_WNDPROC                          = -4
GWL_HINSTANCE                        = -6
GWL_HWNDPARENT                       = -8
GWL_STYLE                            = -16
GWL_EXSTYLE                          = -20
GWL_USERDATA                         = -21
GWL_ID                               = -12

# ShowWindow
SW_HIDE                             = 0
SW_SHOWNORMAL                       = 1
SW_NORMAL                           = 1
SW_SHOWMINIMIZED                    = 2
SW_SHOWMAXIMIZED                    = 3
SW_MAXIMIZE                         = 3
SW_SHOWNOACTIVATE                   = 4
SW_SHOW                             = 5
SW_MINIMIZE                         = 6
SW_SHOWMINNOACTIVE                  = 7
SW_SHOWNA                           = 8
SW_RESTORE                          = 9
SW_SHOWDEFAULT                      = 10
SW_FORCEMINIMIZE                    = 11

# SendMessageTimeout flags
SMTO_NORMAL                         = 0
SMTO_BLOCK                          = 1
SMTO_ABORTIFHUNG                    = 2
SMTO_NOTIMEOUTIFNOTHUNG 			= 8
SMTO_ERRORONEXIT                    = 0x20

#--- Window messages ----------------------------------------------------------

WM_USER                              = 0x400
WM_NULL                              = 0
WM_CREATE                            = 1
WM_DESTROY                           = 2
WM_MOVE                              = 3
WM_SIZE                              = 5
WM_ACTIVATE                          = 6
WA_INACTIVE                          = 0
WA_ACTIVE                            = 1
WA_CLICKACTIVE                       = 2
WM_SETFOCUS                          = 7
WM_KILLFOCUS                         = 8
WM_ENABLE                            = 0x0A
WM_SETREDRAW                         = 0x0B
WM_SETTEXT                           = 0x0C
WM_GETTEXT                           = 0x0D
WM_GETTEXTLENGTH                     = 0x0E
WM_PAINT                             = 0x0F
WM_CLOSE                             = 0x10
WM_QUERYENDSESSION                   = 0x11
WM_QUIT                              = 0x12
WM_QUERYOPEN                         = 0x13
WM_ERASEBKGND                        = 0x14
WM_SYSCOLORCHANGE                    = 0x15
WM_ENDSESSION                        = 0x16
WM_SHOWWINDOW                        = 0x18
WM_WININICHANGE                      = 0x1A
WM_SETTINGCHANGE                	 = WM_WININICHANGE
WM_DEVMODECHANGE                     = 0x1B
WM_ACTIVATEAPP                       = 0x1C
WM_FONTCHANGE                        = 0x1D
WM_TIMECHANGE                        = 0x1E
WM_CANCELMODE                        = 0x1F
WM_SETCURSOR                         = 0x20
WM_MOUSEACTIVATE                     = 0x21
WM_CHILDACTIVATE                     = 0x22
WM_QUEUESYNC                         = 0x23
WM_GETMINMAXINFO                     = 0x24
WM_PAINTICON                         = 0x26
WM_ICONERASEBKGND                    = 0x27
WM_NEXTDLGCTL                        = 0x28
WM_SPOOLERSTATUS                     = 0x2A
WM_DRAWITEM                          = 0x2B
WM_MEASUREITEM                       = 0x2C
WM_DELETEITEM                        = 0x2D
WM_VKEYTOITEM                        = 0x2E
WM_CHARTOITEM                        = 0x2F
WM_SETFONT                           = 0x30
WM_GETFONT                           = 0x31
WM_SETHOTKEY                         = 0x32
WM_GETHOTKEY                         = 0x33
WM_QUERYDRAGICON                     = 0x37
WM_COMPAREITEM                       = 0x39
WM_GETOBJECT                    	 = 0x3D
WM_COMPACTING                        = 0x41
WM_OTHERWINDOWCREATED                = 0x42
WM_OTHERWINDOWDESTROYED              = 0x43
WM_COMMNOTIFY                        = 0x44
CN_RECEIVE                           = 0x1
CN_TRANSMIT                          = 0x2
CN_EVENT                             = 0x4
WM_WINDOWPOSCHANGING                 = 0x46
WM_WINDOWPOSCHANGED                  = 0x47
WM_POWER                             = 0x48
PWR_OK                               = 1
PWR_FAIL                             = -1
PWR_SUSPENDREQUEST                   = 1
PWR_SUSPENDRESUME                    = 2
PWR_CRITICALRESUME                   = 3
WM_COPYDATA                          = 0x4A
WM_CANCELJOURNAL                     = 0x4B
WM_NOTIFY                            = 0x4E
WM_INPUTLANGCHANGEREQUEST            = 0x50
WM_INPUTLANGCHANGE                   = 0x51
WM_TCARD                             = 0x52
WM_HELP                              = 0x53
WM_USERCHANGED                       = 0x54
WM_NOTIFYFORMAT                      = 0x55
WM_CONTEXTMENU                       = 0x7B
WM_STYLECHANGING                     = 0x7C
WM_STYLECHANGED                      = 0x7D
WM_DISPLAYCHANGE                     = 0x7E
WM_GETICON                           = 0x7F
WM_SETICON                           = 0x80
WM_NCCREATE                          = 0x81
WM_NCDESTROY                         = 0x82
WM_NCCALCSIZE                        = 0x83
WM_NCHITTEST                         = 0x84
WM_NCPAINT                           = 0x85
WM_NCACTIVATE                        = 0x86
WM_GETDLGCODE                        = 0x87
WM_SYNCPAINT                    	 = 0x88
WM_NCMOUSEMOVE                       = 0x0A0
WM_NCLBUTTONDOWN                     = 0x0A1
WM_NCLBUTTONUP                       = 0x0A2
WM_NCLBUTTONDBLCLK                   = 0x0A3
WM_NCRBUTTONDOWN                     = 0x0A4
WM_NCRBUTTONUP                       = 0x0A5
WM_NCRBUTTONDBLCLK                   = 0x0A6
WM_NCMBUTTONDOWN                     = 0x0A7
WM_NCMBUTTONUP                       = 0x0A8
WM_NCMBUTTONDBLCLK                   = 0x0A9
WM_KEYFIRST                          = 0x100
WM_KEYDOWN                           = 0x100
WM_KEYUP                             = 0x101
WM_CHAR                              = 0x102
WM_DEADCHAR                          = 0x103
WM_SYSKEYDOWN                        = 0x104
WM_SYSKEYUP                          = 0x105
WM_SYSCHAR                           = 0x106
WM_SYSDEADCHAR                       = 0x107
WM_KEYLAST                           = 0x108
WM_INITDIALOG                        = 0x110
WM_COMMAND                           = 0x111
WM_SYSCOMMAND                        = 0x112
WM_TIMER                             = 0x113
WM_HSCROLL                           = 0x114
WM_VSCROLL                           = 0x115
WM_INITMENU                          = 0x116
WM_INITMENUPOPUP                     = 0x117
WM_MENUSELECT                        = 0x11F
WM_MENUCHAR                          = 0x120
WM_ENTERIDLE                         = 0x121
WM_CTLCOLORMSGBOX                    = 0x132
WM_CTLCOLOREDIT                      = 0x133
WM_CTLCOLORLISTBOX                   = 0x134
WM_CTLCOLORBTN                       = 0x135
WM_CTLCOLORDLG                       = 0x136
WM_CTLCOLORSCROLLBAR                 = 0x137
WM_CTLCOLORSTATIC                    = 0x138
WM_MOUSEFIRST                        = 0x200
WM_MOUSEMOVE                         = 0x200
WM_LBUTTONDOWN                       = 0x201
WM_LBUTTONUP                         = 0x202
WM_LBUTTONDBLCLK                     = 0x203
WM_RBUTTONDOWN                       = 0x204
WM_RBUTTONUP                         = 0x205
WM_RBUTTONDBLCLK                     = 0x206
WM_MBUTTONDOWN                       = 0x207
WM_MBUTTONUP                         = 0x208
WM_MBUTTONDBLCLK                     = 0x209
WM_MOUSELAST                         = 0x209
WM_PARENTNOTIFY                      = 0x210
WM_ENTERMENULOOP                     = 0x211
WM_EXITMENULOOP                      = 0x212
WM_MDICREATE                         = 0x220
WM_MDIDESTROY                        = 0x221
WM_MDIACTIVATE                       = 0x222
WM_MDIRESTORE                        = 0x223
WM_MDINEXT                           = 0x224
WM_MDIMAXIMIZE                       = 0x225
WM_MDITILE                           = 0x226
WM_MDICASCADE                        = 0x227
WM_MDIICONARRANGE                    = 0x228
WM_MDIGETACTIVE                      = 0x229
WM_MDISETMENU                        = 0x230
WM_DROPFILES                         = 0x233
WM_MDIREFRESHMENU                    = 0x234
WM_CUT                               = 0x300
WM_COPY                              = 0x301
WM_PASTE                             = 0x302
WM_CLEAR                             = 0x303
WM_UNDO                              = 0x304
WM_RENDERFORMAT                      = 0x305
WM_RENDERALLFORMATS                  = 0x306
WM_DESTROYCLIPBOARD                  = 0x307
WM_DRAWCLIPBOARD                     = 0x308
WM_PAINTCLIPBOARD                    = 0x309
WM_VSCROLLCLIPBOARD                  = 0x30A
WM_SIZECLIPBOARD                     = 0x30B
WM_ASKCBFORMATNAME                   = 0x30C
WM_CHANGECBCHAIN                     = 0x30D
WM_HSCROLLCLIPBOARD                  = 0x30E
WM_QUERYNEWPALETTE                   = 0x30F
WM_PALETTEISCHANGING                 = 0x310
WM_PALETTECHANGED                    = 0x311
WM_HOTKEY                            = 0x312
WM_PRINT                        	 = 0x317
WM_PRINTCLIENT                       = 0x318
WM_PENWINFIRST                       = 0x380
WM_PENWINLAST                        = 0x38F

#--- user32.dll --------------------------------------------------------------

# Window enumerator class
class __WindowEnumerator (object):
    def __init__(self):
        self.hwnd = list()
    def __call__(self, hwnd, lParam):
        self.hwnd.append(hwnd)
        return TRUE

WNDENUMPROC = WINFUNCTYPE(BOOL, HWND, PVOID)

# HWND FindWindow(
#     LPCTSTR lpClassName,
#     LPCTSTR lpWindowName
# );
def FindWindowA(lpClassName = None, lpWindowName = None):
    if not lpClassName:
        lpClassName = NULL
    if not lpWindowName:
        lpWindowName = NULL
    hWnd = ctypes.windll.user32.FindWindowA(lpClassName, lpWindowName)
    if hWnd == NULL:
        raise ctypes.WinError()
    return hWnd
def FindWindowW(lpClassName = None, lpWindowName = None):
    if not lpClassName:
        lpClassName = NULL
    if not lpWindowName:
        lpWindowName = NULL
    hWnd = ctypes.windll.user32.FindWindowW(lpClassName, lpWindowName)
    if hWnd == NULL:
        raise ctypes.WinError()
    return hWnd
FindWindow = GuessStringType(FindWindowW, FindWindowW)

# int GetClassName(
#     HWND hWnd,
#     LPTSTR lpClassName,
#     int nMaxCount
# );
def GetClassNameA(hWnd):
    nMaxCount = 0x1000
    dwCharSize = sizeof(CHAR)
    while 1:
        lpClassName = ctypes.create_string_buffer("", nMaxCount)
        nCount = ctypes.windll.user32.GetClassNameA(hWnd, ctypes.byref(lpClassName), nMaxCount)
        if nCount == 0:
            raise ctypes.WinError()
        if nCount < nMaxCount - dwCharSize:
            break
        nMaxCount += 0x1000
    return lpClassName.value
def GetClassNameW(hWnd):
    nMaxCount = 0x1000
    dwCharSize = sizeof(WCHAR)
    while 1:
        lpClassName = ctypes.create_unicode_buffer(u"", nMaxCount)
        nCount = ctypes.windll.user32.GetClassNameW(hWnd, ctypes.byref(lpClassName), nMaxCount)
        if nCount == 0:
            raise ctypes.WinError()
        if nCount < nMaxCount - dwCharSize:
            break
        nMaxCount += 0x1000
    return lpClassName.value
GetClassName = GuessStringType(GetClassNameA, GetClassNameW)

# LONG GetWindowLong(
#     HWND hWnd,
#     int nIndex
# );
def GetWindowLongA(hWnd, nIndex = 0):
    return ctypes.windll.user32.GetWindowLongA(hWnd, nIndex)
def GetWindowLongW(hWnd, nIndex = 0):
    return ctypes.windll.user32.GetWindowLongW(hWnd, nIndex)
GetWindowLong = GuessStringType(GetWindowLongA, GetWindowLongW)

# DWORD GetWindowThreadProcessId(
#     HWND hWnd,
#     LPDWORD lpdwProcessId
# );
def GetWindowThreadProcessId(hWnd):
    dwProcessId = DWORD(0)
    dwThreadId = ctypes.windll.user32.GetWindowThreadProcessId(hWnd, ctypes.byref(dwProcessId))
    if dwThreadId == 0:
        raise ctypes.WinError()
    return dwThreadId, dwProcessId.value

# HWND GetParent(
#       HWND hWnd
# );
def GetParent(hWnd):
    hWndParent = ctypes.windll.user32.GetParent(hWnd)
    if hWndParent == NULL:
        winerr = GetLastError()
        if winerr != ERROR_SUCCESS:
            raise ctypes.WinError(winerr)
    return hWndParent

# BOOL EnableWindow(
#     HWND hWnd,
#     BOOL bEnable
# );
def EnableWindow(hWnd, bEnable = True):
    if bEnable:
        bEnable = TRUE
    else:
        bEnable = FALSE
    success = ctypes.windll.user32.EnableWindow(hWnd, bEnable)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL ShowWindow(
#     HWND hWnd,
#     int nCmdShow
# );
def ShowWindow(hWnd, nCmdShow = SW_SHOW):
    success = ctypes.windll.user32.ShowWindow(hWnd, nCmdShow)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL ShowWindowAsync(
#     HWND hWnd,
#     int nCmdShow
# );
def ShowWindowAsync(hWnd, nCmdShow = SW_SHOW):
    success = ctypes.windll.user32.ShowWindowAsync(hWnd, nCmdShow)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL CALLBACK EnumWndProc(
#     HWND hwnd,
#     LPARAM lParam
# );
class __EnumWndProc (__WindowEnumerator):
    pass

# BOOL EnumWindows(
#     DWORD dwThreadId,
#     WNDENUMPROC lpEnumFunc,
#     LPARAM lParam
# );
def EnumWindows():
    EnumFunc = __EnumWndProc()
    lpEnumFunc = WNDENUMPROC(EnumFunc)
    success = ctypes.windll.user32.EnumWindows(lpEnumFunc, 0)
    if success == FALSE:
        errcode = GetLastError()
        if errcode != ERROR_NO_MORE_FILES:
            raise ctypes.WinError(errcode)
    return EnumFunc.hwnd

# BOOL CALLBACK EnumThreadWndProc(
#     HWND hwnd,
#     LPARAM lParam
# );
class __EnumThreadWndProc (__WindowEnumerator):
    pass

# BOOL EnumThreadWindows(
#     DWORD dwThreadId,
#     WNDENUMPROC lpfn,
#     LPARAM lParam
# );
def EnumThreadWindows(dwThreadId):
    fn = __EnumThreadWndProc()
    lpfn = WNDENUMPROC(fn)
    success = ctypes.windll.user32.EnumThreadWindows(dwThreadId, lpfn, 0)
    if success == FALSE:
        errcode = GetLastError()
        if errcode != ERROR_NO_MORE_FILES:
            raise ctypes.WinError(errcode)
    return fn.hwnd

# BOOL CALLBACK EnumChildProc(
#     HWND hwnd,
#     LPARAM lParam
# );
class __EnumChildProc (__WindowEnumerator):
    pass

# BOOL EnumChildWindows(
#     HWND hWndParent,
#     WNDENUMPROC lpEnumFunc,
#     LPARAM lParam
# );
def EnumChildWindows(hWndParent = NULL):
    EnumFunc = __EnumChildProc()
    lpEnumFunc = WNDENUMPROC(EnumFunc)
    success = ctypes.windll.user32.EnumChildWindows(hWndParent, lpEnumFunc, 0)
##    if success == FALSE:
##        errcode = GetLastError()
##        if errcode != ERROR_NO_MORE_FILES:
##            raise ctypes.WinError(errcode)
    return EnumFunc.hwnd

# BOOL SendMessage(
#     HWND hWnd,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam
# );
def SendMessageA(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    return ctypes.windll.user32.SendMessageA(hWnd, Msg, wParam, lParam)
def SendMessageW(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    return ctypes.windll.user32.SendMessageW(hWnd, Msg, wParam, lParam)
SendMessage = GuessStringType(SendMessageA, SendMessageW)

# BOOL PostMessage(
#     HWND hWnd,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam
# );
def PostMessageA(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.PostMessageA(hWnd, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
def PostMessageW(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.PostMessageW(hWnd, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
PostMessage = GuessStringType(PostMessageA, PostMessageW)

# BOOL PostThreadMessage(
#     DWORD idThread,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam
# );
def PostThreadMessageA(idThread, Msg, wParam = 0, lParam = 0):
    if not idThread:
        idThread = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.PostThreadMessageA(idThread, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
def PostThreadMessageW(idThread, Msg, wParam = 0, lParam = 0):
    if not idThread:
        idThread = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.PostThreadMessageW(idThread, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
PostThreadMessage = GuessStringType(PostThreadMessageA, PostThreadMessageW)

# LRESULT SendMessageTimeout(
#     HWND hWnd,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam,
#     UINT fuFlags,
#     UINT uTimeout,
#     PDWORD_PTR lpdwResult
# );
def SendMessageTimeoutA(hWnd, Msg, wParam = 0, lParam = 0, fuFlags = 0, uTimeout = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    if not fuFlags:
        fuFlags = 0
    if not uTimeout:
        uTimeout = 0
    dwResult = DWORD(0)
    success = ctypes.windll.user32.SendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, ctypes.byref(dwResult))
    if success == 0:
        raise ctypes.WinError()
    return dwResult.value
def SendMessageTimeoutW(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    if not fuFlags:
        fuFlags = 0
    if not uTimeout:
        uTimeout = 0
    dwResult = DWORD(0)
    success = ctypes.windll.user32.SendMessageTimeoutW(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, ctypes.byref(dwResult))
    if success == 0:
        raise ctypes.WinError()
    return dwResult.value
SendMessageTimeout = GuessStringType(SendMessageTimeoutA, SendMessageTimeoutW)

# BOOL SendNotifyMessage(
#     HWND hWnd,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam
# );
def SendNotifyMessageA(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.SendNotifyMessageA(hWnd, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
def SendNotifyMessageW(hWnd, Msg, wParam = 0, lParam = 0):
    if not hWnd:
        hWnd = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    success = ctypes.windll.user32.SendNotifyMessageW(hWnd, Msg, wParam, lParam)
    if success == 0:
        raise ctypes.WinError()
SendNotifyMessage = GuessStringType(SendNotifyMessageA, SendNotifyMessageW)

# LRESULT SendDlgItemMessage(
#     HWND hDlg,
#     int nIDDlgItem,
#     UINT Msg,
#     WPARAM wParam,
#     LPARAM lParam
# );
def SendDlgItemMessageA(hDlg, nIDDlgItem, Msg, wParam = 0, lParam = 0):
    if not hDlg:
        hDlg = 0
    if not nIDDlgItem:
        nIDDlgItem = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    return ctypes.windll.user32.SendDlgItemMessageA(hDlg, nIDDlgItem, Msg, wParam, lParam)
def SendDlgItemMessageW(hDlg, nIDDlgItem, Msg, wParam = 0, lParam = 0):
    if not hDlg:
        hDlg = 0
    if not nIDDlgItem:
        nIDDlgItem = 0
    if not wParam:
        wParam = 0
    if not lParam:
        lParam = 0
    return ctypes.windll.user32.SendDlgItemMessageW(hDlg, nIDDlgItem, Msg, wParam, lParam)
SendDlgItemMessage = GuessStringType(SendDlgItemMessageA, SendDlgItemMessageW)

# UINT RegisterWindowMessage(
#     LPCTSTR lpString
# );
def RegisterWindowMessageA(lpString):
    lpString = ctypes.create_string_buffer(lpString)
    uMsg = ctypes.windll.user32.RegisterWindowMessageA(ctypes.byref(lpString))
    if uMsg == 0:
        raise ctypes.WinError()
    return uMsg
def RegisterWindowMessageW(lpString):
    lpString = ctypes.create_unicode_buffer(lpString)
    uMsg = ctypes.windll.user32.RegisterWindowMessageW(ctypes.byref(lpString))
    if uMsg == 0:
        raise ctypes.WinError()
    return uMsg
RegisterWindowMessage = GuessStringType(RegisterWindowMessageA, RegisterWindowMessageW)
