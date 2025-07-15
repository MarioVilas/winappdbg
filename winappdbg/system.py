#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
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

"""System settings."""

from __future__ import with_statement

__all__ = ["System"]

import ctypes
import glob
import ntpath
import os
import warnings
from os import getenv

from . import win32
from .process import _ProcessContainer
from .registry import Registry
from .util import IntelDebugRegister, MemoryAddresses, classproperty
from .window import Window

# ==============================================================================


class System(_ProcessContainer):
    """
    Interface to a batch of processes, plus some system wide settings.
    Contains a snapshot of processes.

    :cvar arch: Name of the processor architecture we're running on.
        For more details see :func:`~winappdbg.win32.version._get_arch`.
    :type arch: str

    :cvar bits: Size of the machine word in bits for the current architecture.
        For more details see :func:`~winappdbg.win32.version._get_bits`.
    :type bits: int

    :cvar os: Name of the Windows version we're runing on.
        For more details see :func:`~winappdbg.win32.version._get_os`.
    :type os: str

    :cvar wow64: ``True`` if the debugger is a 32 bits process running in a 64
        bits version of Windows, ``False`` otherwise.
    :type wow64: bool

    :cvar pageSize: Page size in bytes. Defaults to 0x1000 but it's
        automatically updated on runtime when importing the module.
    :type pageSize: int

    :cvar registry: Windows Registry for this machine.
    :type registry: :class:`~winappdbg.registry.Registry`
    """

    arch = win32.arch
    bits = win32.bits
    os = win32.os
    wow64 = win32.wow64

    @classproperty
    def pageSize(cls):
        pageSize = MemoryAddresses.pageSize
        cls.pageSize = pageSize
        return pageSize

    registry = Registry()

    # ------------------------------------------------------------------------------

    @staticmethod
    def find_window(className=None, windowName=None):
        """
        Find the first top-level window in the current desktop to match the
        given class name and/or window name. If neither are provided any
        top-level window will match.

        .. seealso:: :meth:`get_window_at`

        :type  className: str
        :param className: (Optional) Class name of the window to find.
            If ``None`` or not used any class name will match the search.

        :type  windowName: str
        :param windowName: (Optional) Caption text of the window to find.
            If ``None`` or not used any caption text will match the search.

        :rtype:  :class:`~.window.Window` or None
        :return: A window that matches the request. There may be more matching
            windows, but this method only returns one. If no matching window
            is found, the return value is ``None``.

        :raises WindowsError: An error occured while processing this request.
        """
        # I'd love to reverse the order of the parameters
        # but that might create some confusion. :(
        hWnd = win32.FindWindow(className, windowName)
        if hWnd:
            return Window(hWnd)

    @staticmethod
    def get_window_at(x, y):
        """
        Get the window located at the given coordinates in the desktop.
        If no such window exists an exception is raised.

        .. seealso:: :meth:`find_window`

        :type  x: int
        :param x: Horizontal coordinate.
        :type  y: int
        :param y: Vertical coordinate.

        :rtype:  :class:`~.window.Window`
        :return: Window at the requested position. If no such window
            exists a ``WindowsError`` exception is raised.

        :raises WindowsError: An error occured while processing this request.
        """
        return Window(win32.WindowFromPoint((x, y)))

    @staticmethod
    def get_foreground_window():
        """
        :rtype:  :class:`~.window.Window`
        :return: Returns the foreground window.
        :raises WindowsError: An error occured while processing this request.
        """
        return Window(win32.GetForegroundWindow())

    @staticmethod
    def get_desktop_window():
        """
        :rtype:  :class:`~.window.Window`
        :return: Returns the desktop window.
        :raises WindowsError: An error occured while processing this request.
        """
        return Window(win32.GetDesktopWindow())

    @staticmethod
    def get_shell_window():
        """
        :rtype:  :class:`~.window.Window`
        :return: Returns the shell window.
        :raises WindowsError: An error occured while processing this request.
        """
        return Window(win32.GetShellWindow())

    @staticmethod
    def get_top_level_windows():
        """
        :rtype:  list[:class:`~.window.Window`]
        :return: Returns the top-level windows in the current desktop.
        :raises WindowsError: An error occured while processing this request.
        """
        return [Window(hWnd) for hWnd in win32.EnumWindows()]

    # ------------------------------------------------------------------------------

    @classmethod
    def request_debug_privileges(cls, bIgnoreExceptions=False):
        """
        Requests debug privileges.

        This may be needed to debug processes running as SYSTEM
        (such as services) since Windows XP.

        :type  bIgnoreExceptions: bool
        :param bIgnoreExceptions: ``True`` to ignore any exceptions that may be
            raised when requesting debug privileges.

        :rtype:  bool
        :return: ``True`` on success, ``False`` on failure.

        :raises WindowsError: Raises an exception on error, unless
            ``bIgnoreExceptions`` is ``True``.
        """
        try:
            cls.request_privileges(win32.SE_DEBUG_NAME)
            return True
        except Exception:
            if not bIgnoreExceptions:
                raise
        return False

    @classmethod
    def drop_debug_privileges(cls, bIgnoreExceptions=False):
        """
        Drops debug privileges.

        This may be needed to avoid being detected
        by certain anti-debug tricks.

        :type  bIgnoreExceptions: bool
        :param bIgnoreExceptions: ``True`` to ignore any exceptions that may be
            raised when dropping debug privileges.

        :rtype:  bool
        :return: ``True`` on success, ``False`` on failure.

        :raises WindowsError: Raises an exception on error, unless
            ``bIgnoreExceptions`` is ``True``.
        """
        try:
            cls.drop_privileges(win32.SE_DEBUG_NAME)
            return True
        except Exception:
            if not bIgnoreExceptions:
                raise
        return False

    @classmethod
    def request_privileges(cls, *privileges):
        """
        Requests privileges.

        :type  privileges: int...
        :param privileges: Privileges to request.

        :raises WindowsError: Raises an exception on error.
        """
        cls.adjust_privileges(True, privileges)

    @classmethod
    def drop_privileges(cls, *privileges):
        """
        Drops privileges.

        :type  privileges: int...
        :param privileges: Privileges to drop.

        :raises WindowsError: Raises an exception on error.
        """
        cls.adjust_privileges(False, privileges)

    @staticmethod
    def adjust_privileges(state, privileges):
        """
        Requests or drops privileges.

        :type  state: bool
        :param state: ``True`` to request, ``False`` to drop.

        :type  privileges: list(int)
        :param privileges: Privileges to request or drop.

        :raises WindowsError: Raises an exception on error.
        """
        with win32.OpenProcessToken(
            win32.GetCurrentProcess(), win32.TOKEN_ADJUST_PRIVILEGES
        ) as hToken:
            NewState = ((priv, state) for priv in privileges)
            win32.AdjustTokenPrivileges(hToken, NewState)

    @staticmethod
    def is_admin():
        """
        :rtype:  bool
        :return: ``True`` if the current user as Administrator privileges,
            ``False`` otherwise. Since Windows Vista and above this means if
            the current process is running with UAC elevation or not.
        """
        return win32.IsUserAnAdmin()

    # ------------------------------------------------------------------------------

    __binary_types = {
        win32.VFT_APP: "application",
        win32.VFT_DLL: "dynamic link library",
        win32.VFT_STATIC_LIB: "static link library",
        win32.VFT_FONT: "font",
        win32.VFT_DRV: "driver",
        win32.VFT_VXD: "legacy driver",
    }

    __driver_types = {
        win32.VFT2_DRV_COMM: "communications driver",
        win32.VFT2_DRV_DISPLAY: "display driver",
        win32.VFT2_DRV_INSTALLABLE: "installable driver",
        win32.VFT2_DRV_KEYBOARD: "keyboard driver",
        win32.VFT2_DRV_LANGUAGE: "language driver",
        win32.VFT2_DRV_MOUSE: "mouse driver",
        win32.VFT2_DRV_NETWORK: "network driver",
        win32.VFT2_DRV_PRINTER: "printer driver",
        win32.VFT2_DRV_SOUND: "sound driver",
        win32.VFT2_DRV_SYSTEM: "system driver",
        win32.VFT2_DRV_VERSIONED_PRINTER: "versioned printer driver",
    }

    __font_types = {
        win32.VFT2_FONT_RASTER: "raster font",
        win32.VFT2_FONT_TRUETYPE: "TrueType font",
        win32.VFT2_FONT_VECTOR: "vector font",
    }

    __months = (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )

    __days_of_the_week = (
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    )

    @classmethod
    def get_file_version_info(cls, filename):
        """
        Get the program version from an executable file, if available.

        :type  filename: str
        :param filename: Pathname to the executable file to query.

        :rtype: tuple(str, str, bool, bool, str, str)
        :return: Tuple with version information extracted from the executable
            file metadata, containing the following:

            - File version number (``"major.minor"``).
            - Product version number (``"major.minor"``).
            - ``True`` for debug builds, ``False`` for production builds.
            - ``True`` for legacy OS builds (DOS, OS/2, Win16),
              ``False`` for modern OS builds.
            - Binary file type.
              May be one of the following values:

              - "application"
              - "dynamic link library"
              - "static link library"
              - "font"
              - "raster font"
              - "TrueType font"
              - "vector font"
              - "driver"
              - "communications driver"
              - "display driver"
              - "installable driver"
              - "keyboard driver"
              - "language driver"
              - "legacy driver"
              - "mouse driver"
              - "network driver"
              - "printer driver"
              - "sound driver"
              - "system driver"
              - "versioned printer driver"

            - Binary creation timestamp.

            Any of the fields may be ``None`` if not available.

        :raises WindowsError: Raises an exception on error.
        """

        # Get the file version info structure.
        if isinstance(filename, bytes):
            pBlock = win32.GetFileVersionInfoA(filename)
            pBuffer, dwLen = win32.VerQueryValueA(pBlock, b"\\")
        else:
            pBlock = win32.GetFileVersionInfoW(filename)
            pBuffer, dwLen = win32.VerQueryValueW(pBlock, "\\")
        if dwLen != ctypes.sizeof(win32.VS_FIXEDFILEINFO):
            raise ctypes.WinError(win32.ERROR_BAD_LENGTH)
        pVersionInfo = ctypes.cast(pBuffer, ctypes.POINTER(win32.VS_FIXEDFILEINFO))
        VersionInfo = pVersionInfo.contents
        if VersionInfo.dwSignature != 0xFEEF04BD:
            raise ctypes.WinError(win32.ERROR_BAD_ARGUMENTS)

        # File and product versions.
        FileVersion = "%d.%d" % (
            VersionInfo.dwFileVersionMS,
            VersionInfo.dwFileVersionLS,
        )
        ProductVersion = "%d.%d" % (
            VersionInfo.dwProductVersionMS,
            VersionInfo.dwProductVersionLS,
        )

        # Debug build?
        if VersionInfo.dwFileFlagsMask & win32.VS_FF_DEBUG:
            DebugBuild = (VersionInfo.dwFileFlags & win32.VS_FF_DEBUG) != 0
        else:
            DebugBuild = None

        # Legacy OS build?
        LegacyBuild = VersionInfo.dwFileOS != win32.VOS_NT_WINDOWS32

        # File type.
        FileType = cls.__binary_types.get(VersionInfo.dwFileType)
        if VersionInfo.dwFileType == win32.VFT_DRV:
            FileType = cls.__driver_types.get(VersionInfo.dwFileSubtype)
        elif VersionInfo.dwFileType == win32.VFT_FONT:
            FileType = cls.__font_types.get(VersionInfo.dwFileSubtype)

        # Timestamp, ex: "Monday, July 7, 2013 (12:20:50.126)".
        # FIXME: how do we know the time zone?
        FileDate = (VersionInfo.dwFileDateMS << 32) + VersionInfo.dwFileDateLS
        if FileDate:
            CreationTime = win32.FileTimeToSystemTime(FileDate)
            CreationTimestamp = "%s, %s %d, %d (%d:%d:%d.%d)" % (
                cls.__days_of_the_week[CreationTime.wDayOfWeek],
                cls.__months[
                    CreationTime.wMonth - 1
                ],  # Month is 1-based according to MSDN
                CreationTime.wDay,
                CreationTime.wYear,
                CreationTime.wHour,
                CreationTime.wMinute,
                CreationTime.wSecond,
                CreationTime.wMilliseconds,
            )
        else:
            CreationTimestamp = None

        # Return the file version info.
        return (
            FileVersion,
            ProductVersion,
            DebugBuild,
            LegacyBuild,
            FileType,
            CreationTimestamp,
        )

    def __iter__(self):
        yield from super().__iter__()

    # ------------------------------------------------------------------------------

    @classmethod
    def load_dbghelp(cls, pathname=None):
        """
        Load the specified version of the ``dbghelp.dll`` library.

        This library is shipped with the Debugging Tools for Windows, and it's
        required to load debug symbols.

        If you don't specify the pathname, this method will try to find the
        location of the dbghelp.dll library despite Microsoft's efforts to
        keep us from using it, since they keep moving it around...

        This method can be useful for bundling dbghelp.dll in your scripts, so
        users won't need to have the Microsoft SDK installed.

        Example::

            from winappdbg import Debug

            def simple_debugger( argv ):

                # Instance a Debug object, passing it the event handler callback
                debug = Debug( my_event_handler )
                try:

                    # Load a specific dbghelp.dll file
                    debug.system.load_dbghelp("C:\\\\Custom install path\\\\dbghelp.dll")

                    # Start a new process for debugging
                    debug.execv( argv )

                    # Wait for the debugee to finish
                    debug.loop()

                # Stop the debugger
                finally:
                    debug.stop()

        .. seealso:: `http://msdn.microsoft.com/en-us/library/ms679294(VS.85).aspx <http://msdn.microsoft.com/en-us/library/ms679294(VS.85).aspx>`__

        :type  pathname: str
        :param pathname:
            (Optional) Full pathname to the ``dbghelp.dll`` library.
            If not provided this method will try to autodetect it.

        :rtype:  ctypes.WinDLL
        :return: Loaded instance of ``dbghelp.dll``.

        :raises NotImplementedError: This feature was not implemented for the
            current architecture.

        :raises WindowsError: An error occured while processing this request.
        """

        # If a pathname was given, just load the library and return.
        # Raise an exception on error.
        if pathname:
            dbghelp = ctypes.windll.LoadLibrary(pathname)

        # If no pathname was provided, we try to autodetect the install path for the SDK.
        else:
            # This is where we'll keep all the candidate libraries.
            # There may be more than one, so we'll sort out later which one to load.
            candidates = []

            # The Microsoft SDK always seems to be installed in the "Program Files (x86)" folder on
            # Intel 64 bit machines, and "Program Files" on every other platform.
            sysdrive = getenv("SystemDrive", "C:")
            if win32.arch == win32.ARCH_AMD64:
                basedir = "%s\\Program Files (x86)" % sysdrive
                basedir = getenv("ProgramFiles(x86)", basedir)
            else:
                basedir = "%s\\Program Files" % sysdrive
                basedir = getenv("ProgramFiles", basedir)

            # Let's try the oldest known location for dbghelp.dll.
            # Oh, those were the days, when this was the same across all versions.
            candidates.append(
                ntpath.join(basedir, "Debugging Tools for Windows (x86)", "dbghelp.dll")
            )

            # Then the debugger got embedded into the SDK. This path is different for each version.
            # The format is different too. And they bundled 32 and 64 bits together.
            # Then on later versions there's also binaries for other, incompatible architectures too???
            # I gave up on trying to make sense of it, let's just try all combinations to be safe.
            # (We only support x86 and x64 though. In the future we may have to update this.)
            # This StackOverflow answer helped me a lot: https://stackoverflow.com/a/24478856
            if win32.bits == 32:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Windows Kits",
                            "*",
                            "Debuggers",
                            "x86",
                            "dbghelp.dll",
                        )
                    )
                )
            else:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Windows Kits",
                            "*",
                            "Debuggers",
                            "x64",
                            "dbghelp.dll",
                        )
                    )
                )
            if win32.bits == 32:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Microsoft SDKs",
                            "Windows",
                            "*",
                            "Debuggers",
                            "x86",
                            "dbghelp.dll",
                        )
                    )
                )
            else:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Microsoft SDKs",
                            "Windows",
                            "*",
                            "Debuggers",
                            "x64",
                            "dbghelp.dll",
                        )
                    )
                )
            if win32.bits == 32:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Microsoft",
                            "Microsoft SDKs",
                            "Windows",
                            "*",
                            "Debuggers",
                            "x86",
                            "dbghelp.dll",
                        )
                    )
                )
            else:
                candidates.extend(
                    glob.glob(
                        ntpath.join(
                            basedir,
                            "Microsoft",
                            "Microsoft SDKs",
                            "Windows",
                            "*",
                            "Debuggers",
                            "x64",
                            "dbghelp.dll",
                        )
                    )
                )

            # All of the above only works for the scenario where the SDK was installed globally.
            # But after who knows what version they also allow installing the SDK on a user's home.
            # So we need to check the Windows Registry for that.
            # ...unfortunately the registry keys are just as chaotic and inconsistent as the default paths. :(

            # TODO: I feel too tired and angry to implement this right now. Will do it later. Pinky promise.

            # Now that we have a list of potential locations for dbghelp.dll, let's check them out.
            # The idea here is 1) test if the file exists, 2) read the metadata, 3) pick the best one.

            # Sort the list and remove duplicates (there shouldn't be any, but why not, it's fast anyway).
            candidates = sorted(set(candidates))

            # Discard any pathnames where the file cannot be found.
            candidates = [x for x in candidates if ntpath.exists(x)]

            # Get the metadata for each file found. Sort them by version, newer first.
            by_version = []
            for pathname in candidates:
                pBlock = win32.GetFileVersionInfoW(pathname)
                pBuffer, dwLen = win32.VerQueryValueW(pBlock, "\\")
                if dwLen != ctypes.sizeof(win32.VS_FIXEDFILEINFO):
                    # raise ctypes.WinError(win32.ERROR_BAD_LENGTH)
                    continue
                pVersionInfo = ctypes.cast(
                    pBuffer, ctypes.POINTER(win32.VS_FIXEDFILEINFO)
                )
                VersionInfo = pVersionInfo.contents
                if VersionInfo.dwSignature != 0xFEEF04BD:
                    # raise ctypes.WinError(win32.ERROR_BAD_ARGUMENTS)
                    continue
                FileVersion = (VersionInfo.dwFileVersionMS, VersionInfo.dwFileVersionLS)
                ProductVersion = (
                    VersionInfo.dwProductVersionMS,
                    VersionInfo.dwProductVersionLS,
                )
                if FileVersion > ProductVersion:
                    by_version.append((FileVersion, pathname))
                else:
                    by_version.append((ProductVersion, pathname))
            by_version.sort()
            by_version = by_version[::-1]

            # Try loading them all, starting with the newer versions.
            # Stop once we got one to load successfully.
            dbghelp = None
            for _, pathname in by_version:
                try:
                    dbghelp = ctypes.windll.LoadLibrary(pathname)
                    break
                except Exception:
                    continue

            # If we couldn't load the SDK library, try the system default one.
            # It's an outdated version generally, but still better than nothing.
            # Issue a warning to let the user know they should install the SDK.
            if dbghelp is None:
                pathname = ntpath.join(
                    getenv("WINDIR", "C:\\WINDOWS"), "System32", "dbghelp.dll"
                )
                try:
                    dbghelp = ctypes.windll.LoadLibrary(pathname)
                except Exception:
                    dbghelp = None

                # If no library could be loaded, fail with an exception.
                if dbghelp is None:
                    msg = "Could not find a compatible dbghelp.dll in the system. Tried the following: %r"
                    msg = msg % (candidates + [pathname],)
                    raise NotImplementedError(msg)

                # If we loaded the system default, issue a warning.
                warnings.warn(
                    "Microsoft SDK not found, using the system default dbghelp.dll."
                )

        # Set it globally as the library to be used.
        ctypes.windll.dbghelp = dbghelp

        # Return the library.
        return dbghelp

    @staticmethod
    def fix_symbol_store_path(symbol_store_path=None, remote=True, force=False):
        """
        Fix the symbol store path. Equivalent to the ``.symfix`` command in
        Microsoft WinDbg.

        If the symbol store path environment variable hasn't been set, this
        method will provide a default one.

        :type  symbol_store_path: str or None
        :param symbol_store_path: (Optional) Symbol store path to set.

        :type  remote: bool
        :param remote: (Optional) Defines the symbol store path to set when the
            ``symbol_store_path`` is ``None``.

            If ``True`` the default symbol store path is set to the Microsoft
            symbol server. Debug symbols will be downloaded through HTTP.
            This gives the best results but is also quite slow.

            If ``False`` the default symbol store path is set to the local
            cache only. This prevents debug symbols from being downloaded and
            is faster, but unless you've installed the debug symbols on this
            machine or downloaded them in a previous debugging session, some
            symbols may be missing.

            If the ``symbol_store_path`` argument is not ``None``, this argument
            is ignored entirely.

        :type  force: bool
        :param force: (Optional) If ``True`` the new symbol store path is set
            always. If ``False`` the new symbol store path is only set if
            missing.

            This allows you to call this method preventively to ensure the
            symbol server is always set up correctly when running your script,
            but without messing up whatever configuration the user has.

            Example::

                from winappdbg import Debug, System

                def simple_debugger( argv ):

                    # Instance a Debug object
                    debug = Debug( MyEventHandler() )
                    try:

                        # Make sure the remote symbol store is set
                        System.fix_symbol_store_path(remote = True,
                                                      force = False)

                        # Start a new process for debugging
                        debug.execv( argv )

                        # Wait for the debugee to finish
                        debug.loop()

                    # Stop the debugger
                    finally:
                        debug.stop()

        :rtype:  str or None
        :return: The previously set symbol store path if any,
            otherwise returns ``None``.
        """
        try:
            if symbol_store_path is None:
                local_path = "C:\\SYMBOLS"
                if not ntpath.isdir(local_path):
                    local_path = "C:\\Windows\\Symbols"
                    if not ntpath.isdir(local_path):
                        local_path = ntpath.abspath(".")
                if remote:
                    symbol_store_path = (
                        "cache*;SRV*" + local_path + "*"
                        "http://msdl.microsoft.com/download/symbols"
                    )
                else:
                    symbol_store_path = "cache*;SRV*" + local_path
            previous = os.environ.get("_NT_SYMBOL_PATH", None)
            if not previous or force:
                os.environ["_NT_SYMBOL_PATH"] = symbol_store_path
            return previous
        except Exception as e:
            warnings.warn("Cannot fix symbol path, reason: %s" % str(e), RuntimeWarning)

    # ------------------------------------------------------------------------------

    @staticmethod
    def set_kill_on_exit_mode(bKillOnExit=False):
        """
        Defines the behavior of the debugged processes when the debugging
        thread dies. This method only affects the calling thread.

        Works on the following platforms:

         - Microsoft Windows XP and above.
         - Wine (Windows Emulator).

        Fails on the following platforms:

         - Microsoft Windows 2000 and below.
         - ReactOS.

        :type  bKillOnExit: bool
        :param bKillOnExit: ``True`` to automatically kill processes when the
            debugger thread dies. ``False`` to automatically detach from
            processes when the debugger thread dies.

        :rtype:  bool
        :return: ``True`` on success, ``False`` on error.

        .. note::
            This call will fail if a debug port was not created. That is, if
            the debugger isn't attached to at least one process. For more info
            see: `http://msdn.microsoft.com/en-us/library/ms679307.aspx <http://msdn.microsoft.com/en-us/library/ms679307.aspx>`__
        """
        try:
            # won't work before calling CreateProcess or DebugActiveProcess
            win32.DebugSetProcessKillOnExit(bKillOnExit)
        except (AttributeError, WindowsError):
            return False
        return True

    @staticmethod
    def read_msr(address):
        """
        Read the contents of the specified MSR (Machine Specific Register).

        :type  address: int
        :param address: MSR to read.

        :rtype:  int
        :return: Value of the specified MSR.

        :raises WindowsError:
            Raises an exception on error.

        :raises NotImplementedError:
            Current architecture is not ``i386`` or ``amd64``.

        .. warning::
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.
        """
        if win32.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            raise NotImplementedError(
                "MSR reading is only supported on i386 or amd64 processors."
            )
        msr = win32.SYSDBG_MSR()
        msr.Address = address
        msr.Data = 0
        win32.NtSystemDebugControl(
            win32.SysDbgReadMsr, InputBuffer=msr, OutputBuffer=msr
        )
        return msr.Data

    @staticmethod
    def write_msr(address, value):
        """
        Set the contents of the specified MSR (Machine Specific Register).

        :type  address: int
        :param address: MSR to write.

        :type  value: int
        :param value: Contents to write on the MSR.

        :raises WindowsError:
            Raises an exception on error.

        :raises NotImplementedError:
            Current architecture is not ``i386`` or ``amd64``.

        .. warning::
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.
        """
        if win32.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            raise NotImplementedError(
                "MSR writing is only supported on i386 or amd64 processors."
            )
        msr = win32.SYSDBG_MSR()
        msr.Address = address
        msr.Data = value
        win32.NtSystemDebugControl(win32.SysDbgWriteMsr, InputBuffer=msr)

    @classmethod
    def enable_step_on_branch_mode(cls):
        """
        When tracing, call this on every single step event
        for step on branch mode.

        :raises WindowsError:
            Raises ``ERROR_DEBUGGER_INACTIVE`` if the debugger is not attached
            to least one process.

        :raises NotImplementedError:
            Current architecture is not ``i386`` or ``amd64``.

        .. warning::
            This method uses the processor's machine specific registers (MSR).
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.

        .. note::
            It doesn't seem to work in VMWare or VirtualBox machines.
            Maybe it fails in other virtualization/emulation environments,
            no extensive testing was made so far.
        """
        cls.write_msr(
            IntelDebugRegister.DebugCtlMSR,
            IntelDebugRegister.BranchTrapFlag | IntelDebugRegister.LastBranchRecord,
        )

    @classmethod
    def get_last_branch_location(cls):
        """
        Returns the source and destination addresses of the last taken branch.

        :rtype: tuple( int, int )
        :return: Source and destination addresses of the last taken branch.

        :raises WindowsError:
            Raises an exception on error.

        :raises NotImplementedError:
            Current architecture is not ``i386`` or ``amd64``.

        .. warning::
            This method uses the processor's machine specific registers (MSR).
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.

        .. note::
            It doesn't seem to work in VMWare or VirtualBox machines.
            Maybe it fails in other virtualization/emulation environments,
            no extensive testing was made so far.
        """
        LastBranchFromIP = cls.read_msr(IntelDebugRegister.LastBranchFromIP)
        LastBranchToIP = cls.read_msr(IntelDebugRegister.LastBranchToIP)
        return (LastBranchFromIP, LastBranchToIP)

    # ------------------------------------------------------------------------------

    @classmethod
    def get_postmortem_debugger(cls, bits=None):
        """
        Returns the postmortem debugging settings from the Registry.

        .. seealso:: :meth:`set_postmortem_debugger`

        :type  bits: int
        :param bits: Set to ``32`` for the 32 bits debugger, or ``64`` for the
            64 bits debugger. Set to {None} for the default (:attr:`System.bits`).

        :rtype:  tuple( str, bool, int )
        :return: A tuple containing the command line string to the postmortem
            debugger, a boolean specifying if user interaction is allowed
            before attaching, and an integer specifying a user defined hotkey.
            Any member of the tuple may be ``None``.
            See :meth:`set_postmortem_debugger` for more details.

        :raises WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
        else:
            keyname = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"

        key = cls.registry[keyname]

        debugger = key.get("Debugger")
        auto = key.get("Auto")
        hotkey = key.get("UserDebuggerHotkey")

        if auto is not None:
            auto = bool(auto)

        return (debugger, auto, hotkey)

    @classmethod
    def get_postmortem_exclusion_list(cls, bits=None):
        """
        Returns the exclusion list for the postmortem debugger.

        .. seealso:: :meth:`get_postmortem_debugger`

        :type  bits: int
        :param bits: Set to ``32`` for the 32 bits debugger, or ``64`` for the
            64 bits debugger. Set to ``None`` for the default (:attr:`System.bits`).

        :rtype:  list( str )
        :return: List of excluded application filenames.

        :raises WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"
        else:
            keyname = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"

        try:
            key = cls.registry[keyname]
        except KeyError:
            return []

        return [name for (name, enabled) in key.items() if enabled]

    @classmethod
    def set_postmortem_debugger(cls, cmdline, auto=None, hotkey=None, bits=None):
        """
        Sets the postmortem debugging settings in the Registry.

        .. warning:: This method requires administrative rights.

        .. seealso:: :meth:`get_postmortem_debugger`

        :type  cmdline: str
        :param cmdline: Command line to the new postmortem debugger.
            When the debugger is invoked, the first "%ld" is replaced with the
            process ID and the second "%ld" is replaced with the event handle.
            Don't forget to enclose the program filename in double quotes if
            the path contains spaces.

        :type  auto: bool
        :param auto: Set to ``True`` if no user interaction is allowed, ``False``
            to prompt a confirmation dialog before attaching.
            Use ``None`` to leave this value unchanged.

        :type  hotkey: int
        :param hotkey: Virtual key scan code for the user defined hotkey.
            Use ``0`` to disable the hotkey.
            Use ``None`` to leave this value unchanged.

        :type  bits: int
        :param bits: Set to ``32`` for the 32 bits debugger, or ``64`` for the
            64 bits debugger. Set to {None} for the default (:attr:`System.bits`).

        :rtype:  tuple( str, bool, int )
        :return: Previously defined command line and auto flag.

        :raises WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
        else:
            keyname = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"

        key = cls.registry[keyname]

        if cmdline is not None:
            key["Debugger"] = cmdline
        if auto is not None:
            key["Auto"] = int(bool(auto))
        if hotkey is not None:
            key["UserDebuggerHotkey"] = int(hotkey)

    @classmethod
    def add_to_postmortem_exclusion_list(cls, pathname, bits=None):
        """
        Adds the given filename to the exclusion list for postmortem debugging.

        .. warning:: This method requires administrative rights.

        .. seealso:: :meth:`get_postmortem_exclusion_list`

        :type  pathname: str
        :param pathname:
            Application pathname to exclude from postmortem debugging.

        :type  bits: int
        :param bits: Set to ``32`` for the 32 bits debugger, or ``64`` for the
            64 bits debugger. Set to {None} for the default (:attr:`System.bits`).

        :raises WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"
        else:
            keyname = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"

        try:
            key = cls.registry[keyname]
        except KeyError:
            key = cls.registry.create(keyname)

        key[pathname] = 1

    @classmethod
    def remove_from_postmortem_exclusion_list(cls, pathname, bits=None):
        """
        Removes the given filename to the exclusion list for postmortem
        debugging from the Registry.

        .. warning:: This method requires administrative rights.

        .. warning:: Don't ever delete entries you haven't created yourself!
            Some entries are set by default for your version of Windows.
            Deleting them might deadlock your system under some circumstances.

            For more details see:
            `http://msdn.microsoft.com/en-us/library/bb204634(v=vs.85).aspx <http://msdn.microsoft.com/en-us/library/bb204634(v=vs.85).aspx>`__

        .. seealso:: :meth:`get_postmortem_exclusion_list`

        :type  pathname: str
        :param pathname: Application pathname to remove from the postmortem
            debugging exclusion list.

        :type  bits: int
        :param bits: Set to ``32`` for the 32 bits debugger, or ``64`` for the
            64 bits debugger. Set to {None} for the default (:attr:`System.bits`).

        :raises WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"
        else:
            keyname = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList"

        try:
            key = cls.registry[keyname]
        except KeyError:
            return

        try:
            del key[pathname]
        except KeyError:
            return

    # ------------------------------------------------------------------------------

    @staticmethod
    def get_services():
        """
        Retrieve a list of all system services.

        .. seealso::
            :meth:`get_active_services`,
            :meth:`start_service`, :meth:`stop_service`,
            :meth:`pause_service`, :meth:`resume_service`

        :rtype:  list of win32.ServiceStatusProcessEntry
        :return: List of service status descriptors.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_ENUMERATE_SERVICE
        ) as hSCManager:
            try:
                return win32.EnumServicesStatusEx(hSCManager)
            except AttributeError:
                return win32.EnumServicesStatus(hSCManager)

    @staticmethod
    def get_active_services():
        """
        Retrieve a list of all active system services.

        .. seealso::
            :meth:`get_services`,
            :meth:`start_service`, :meth:`stop_service`,
            :meth:`pause_service`, :meth:`resume_service`

        :rtype:  list of win32.ServiceStatusProcessEntry
        :return: List of service status descriptors.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_ENUMERATE_SERVICE
        ) as hSCManager:
            return [
                entry
                for entry in win32.EnumServicesStatusEx(
                    hSCManager,
                    dwServiceType=win32.SERVICE_WIN32,
                    dwServiceState=win32.SERVICE_ACTIVE,
                )
                if entry.ProcessId
            ]

    @staticmethod
    def get_service(name):
        """
        Get the service descriptor for the given service name.

        .. seealso::
            :meth:`start_service`, :meth:`stop_service`,
            :meth:`pause_service`, :meth:`resume_service`

        :type  name: str
        :param name: Service unique name. You can get this value from the
            ``ServiceName`` member of the service descriptors returned by
            :meth:`get_services` or :meth:`get_active_services`.

        :rtype:  win32.ServiceStatusProcess
        :return: Service status descriptor.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_ENUMERATE_SERVICE
        ) as hSCManager:
            with win32.OpenService(
                hSCManager, name, dwDesiredAccess=win32.SERVICE_QUERY_STATUS
            ) as hService:
                try:
                    return win32.QueryServiceStatusEx(hService)
                except AttributeError:
                    return win32.QueryServiceStatus(hService)

    @staticmethod
    def get_service_display_name(name):
        """
        Get the service display name for the given service name.

        .. seealso:: :meth:`get_service`

        :type  name: str
        :param name: Service unique name. You can get this value from the
            ``ServiceName`` member of the service descriptors returned by
            :meth:`get_services` or :meth:`get_active_services`.

        :rtype:  str
        :return: Service display name.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_ENUMERATE_SERVICE
        ) as hSCManager:
            return win32.GetServiceDisplayName(hSCManager, name)

    @staticmethod
    def get_service_from_display_name(displayName):
        """
        Get the service unique name given its display name.

        .. seealso:: :meth:`get_service`

        :type  displayName: str
        :param displayName: Service display name. You can get this value from
            the ``DisplayName`` member of the service descriptors returned by
            :meth:`get_services` or :meth:`get_active_services`.

        :rtype:  str
        :return: Service unique name.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_ENUMERATE_SERVICE
        ) as hSCManager:
            return win32.GetServiceKeyName(hSCManager, displayName)

    @staticmethod
    def start_service(name, argv=None):
        """
        Start the service given by name.

        .. warning:: This method requires UAC elevation in Windows Vista and above.

        .. seealso:: :meth:`stop_service`, :meth:`pause_service`, :meth:`resume_service`

        :type  name: str
        :param name: Service unique name. You can get this value from the
            ``ServiceName`` member of the service descriptors returned by
            :meth:`get_services` or :meth:`get_active_services`.
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_CONNECT
        ) as hSCManager:
            with win32.OpenService(
                hSCManager, name, dwDesiredAccess=win32.SERVICE_START
            ) as hService:
                win32.StartService(hService)

    @staticmethod
    def stop_service(name):
        """
        Stop the service given by name.

        .. warning:: This method requires UAC elevation in Windows Vista and above.

        .. seealso::
            :meth:`get_services`, :meth:`get_active_services`,
            :meth:`start_service`, :meth:`pause_service`, :meth:`resume_service`
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_CONNECT
        ) as hSCManager:
            with win32.OpenService(
                hSCManager, name, dwDesiredAccess=win32.SERVICE_STOP
            ) as hService:
                win32.ControlService(hService, win32.SERVICE_CONTROL_STOP)

    @staticmethod
    def pause_service(name):
        """
        Pause the service given by name.

        .. warning:: This method requires UAC elevation in Windows Vista and above.

        .. note:: Not all services support this.

        .. seealso::
            :meth:`get_services`, :meth:`get_active_services`,
            :meth:`start_service`, :meth:`stop_service`, :meth:`resume_service`
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_CONNECT
        ) as hSCManager:
            with win32.OpenService(
                hSCManager, name, dwDesiredAccess=win32.SERVICE_PAUSE_CONTINUE
            ) as hService:
                win32.ControlService(hService, win32.SERVICE_CONTROL_PAUSE)

    @staticmethod
    def resume_service(name):
        """
        Resume the service given by name.

        .. warning:: This method requires UAC elevation in Windows Vista and above.

        .. note:: Not all services support this.

        .. seealso::
            :meth:`get_services`, :meth:`get_active_services`,
            :meth:`start_service`, :meth:`stop_service`, :meth:`pause_service`
        """
        with win32.OpenSCManager(
            dwDesiredAccess=win32.SC_MANAGER_CONNECT
        ) as hSCManager:
            with win32.OpenService(
                hSCManager, name, dwDesiredAccess=win32.SERVICE_PAUSE_CONTINUE
            ) as hService:
                win32.ControlService(hService, win32.SERVICE_CONTROL_CONTINUE)

    # TODO: create_service, delete_service
