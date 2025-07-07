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

"""
Registry access.

@group Instrumentation:
    Registry, RegistryKey
"""

__all__ = ["Registry"]

import collections
import warnings

from . import win32

# ==============================================================================


class _RegistryContainer:
    """
    Base class for :class:`Registry` and :class:`RegistryKey`.
    """

    # Dummy object to detect empty arguments.
    class __EmptyArgument:
        pass

    __emptyArgument = __EmptyArgument()

    def __init__(self):
        self.__default = None

    def get(self, name, default=__emptyArgument):
        try:
            return self[name]
        except KeyError:
            if default is _RegistryContainer.__emptyArgument:
                return self.__default
            return default

    def setdefault(self, default):
        self.__default = default

    def __iter__(self):
        return self.keys()


# ==============================================================================


class RegistryKey(_RegistryContainer):
    """
    Exposes a single Windows Registry key as a dictionary-like object.

    .. seealso:: :class:`Registry`

    :type path: str
    :ivar path: Registry key path.

    :type handle: :class:`~.win32.RegistryKeyHandle`
    :ivar handle: Registry key handle.
    """

    def __init__(self, path, handle):
        """
        :param str path: Registry key path.
        :param ~win32.RegistryKeyHandle handle: Registry key handle.
        """
        super().__init__()
        if path.endswith("\\"):
            path = path[:-1]
        self._path = path
        self._handle = handle

    @property
    def path(self):
        return self._path

    @property
    def handle(self):
        # if not self._handle:
        #    msg = "This Registry key handle has already been closed."
        #    raise RuntimeError(msg)
        return self._handle

    def __contains__(self, name):
        try:
            win32.RegQueryValueEx(self.handle, name, False)
            return True
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                return False
            raise

    def __getitem__(self, name):
        try:
            return win32.RegQueryValueEx(self.handle, name)[0]
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                raise KeyError(name)
            raise

    def __setitem__(self, name, value):
        win32.RegSetValueEx(self.handle, name, value)

    def __delitem__(self, name):
        win32.RegDeleteValue(self.handle, name)

    def keys(self):
        handle = self.handle
        index = 0
        while True:
            resp = win32.RegEnumValue(handle, index, False)
            if resp is None:
                break
            yield resp[0]
            index += 1

    def values(self):
        handle = self.handle
        index = 0
        while True:
            resp = win32.RegEnumValue(handle, index)
            if resp is None:
                break
            yield resp[2]
            index += 1

    def items(self):
        handle = self.handle
        index = 0
        while True:
            resp = win32.RegEnumValue(handle, index)
            if resp is None:
                break
            yield resp[0], resp[2]
            index += 1

    def get_value_type(self, name):
        """
        Retrieves the low-level data type for the given value.

        :param str name: Registry value name.
        :rtype: int
        :return: One of the following constants:
         - :const:`~.win32.REG_NONE` (0)
         - :const:`~.win32.REG_SZ` (1)
         - :const:`~.win32.REG_EXPAND_SZ` (2)
         - :const:`~.win32.REG_BINARY` (3)
         - :const:`~.win32.REG_DWORD` (4)
         - :const:`~.win32.REG_DWORD_BIG_ENDIAN` (5)
         - :const:`~.win32.REG_LINK` (6)
         - :const:`~.win32.REG_MULTI_SZ` (7)
         - :const:`~.win32.REG_RESOURCE_LIST` (8)
         - :const:`~.win32.REG_FULL_RESOURCE_DESCRIPTOR` (9)
         - :const:`~.win32.REG_RESOURCE_REQUIREMENTS_LIST` (10)
         - :const:`~.win32.REG_QWORD` (11)
        :raises KeyError: The specified value could not be found.
        """
        try:
            return win32.RegQueryValueEx(self.handle, name)[1]
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                raise KeyError(name)
            raise

    def clear(self):
        handle = self.handle
        while True:
            resp = win32.RegEnumValue(handle, 0, False)
            if resp is None:
                break
            win32.RegDeleteValue(handle, resp[0])

    def __str__(self):
        try:
            return str(self[""])
        except KeyError:
            return ""

    def __repr__(self):
        return '<Registry key: "%s">' % self._path

    def iterchildren(self):
        """
        Iterates the subkeys for this Registry key.

        :rtype: iter of :class:`RegistryKey`
        :return: Iterator of subkeys.
        """
        handle = self.handle
        index = 0
        while True:
            subkey = win32.RegEnumKey(handle, index)
            if subkey is None:
                break
            yield self.child(subkey)
            index += 1

    def children(self):
        """
        Returns a list of subkeys for this Registry key.

        :rtype: list(:class:`RegistryKey`)
        :return: List of subkeys.
        """
        return list(self.iterchildren())

    def child(self, subkey):
        """
        Retrieves a subkey for this Registry key, given its name.

        :param str subkey: Name of the subkey.
        :rtype: :class:`RegistryKey`
        :return: Subkey.
        """
        path = self._path + "\\" + subkey
        handle = win32.RegOpenKey(self.handle, subkey)
        return RegistryKey(path, handle)

    def flush(self):
        """
        Flushes changes immediately to disk.

        This method is normally not needed, as the Registry writes changes
        to disk by itself. This mechanism is provided to ensure the write
        happens immediately, as opposed to whenever the OS wants to.

        .. warning:: Calling this method too often may degrade performance.
        """
        win32.RegFlushKey(self.handle)


# ==============================================================================

# TODO: possibly cache the RegistryKey objects
# to avoid opening and closing handles many times on code sequences like this:
#
# r = Registry()
# r['HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run']['Example 1'] = 'example1.exe'
# r['HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run']['Example 2'] = 'example2.exe'
# r['HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run']['Example 3'] = 'example3.exe'

# TODO: support for access flags?
# TODO: should be possible to disable the safety checks (see __delitem__)

# TODO: workaround for an API bug described by a user in MSDN
#
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa379776(v=vs.85).aspx
#
# Apparently RegDeleteTree won't work remotely from Win7 to WinXP, and the only
# solution is to recursively call RegDeleteKey.


class Registry(_RegistryContainer):
    """
    Exposes the Windows Registry as a Python container.

    :type machine: str or None
    :ivar machine: For a remote Registry, the machine name.
        For a local Registry, the value is ``None``.
    """

    _hives_by_name = {
        # Short names
        "HKCR": win32.HKEY_CLASSES_ROOT,
        "HKCU": win32.HKEY_CURRENT_USER,
        "HKLM": win32.HKEY_LOCAL_MACHINE,
        "HKU": win32.HKEY_USERS,
        "HKPD": win32.HKEY_PERFORMANCE_DATA,
        "HKCC": win32.HKEY_CURRENT_CONFIG,
        # Long names
        "HKEY_CLASSES_ROOT": win32.HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_USER": win32.HKEY_CURRENT_USER,
        "HKEY_LOCAL_MACHINE": win32.HKEY_LOCAL_MACHINE,
        "HKEY_USERS": win32.HKEY_USERS,
        "HKEY_PERFORMANCE_DATA": win32.HKEY_PERFORMANCE_DATA,
        "HKEY_CURRENT_CONFIG": win32.HKEY_CURRENT_CONFIG,
    }

    _hives_by_value = {
        win32.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
        win32.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
        win32.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
        win32.HKEY_USERS: "HKEY_USERS",
        win32.HKEY_PERFORMANCE_DATA: "HKEY_PERFORMANCE_DATA",
        win32.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG",
    }

    _hives = sorted(_hives_by_value.values())

    def __init__(self, machine=None):
        """
        Opens a local or remote registry.

        :param str machine: Optional machine name. If ``None`` it opens the local
            registry.
        """
        self._machine = machine
        self._remote_hives = {}

    @property
    def machine(self):
        return self._machine

    def _split_path(self, path):
        """
        Splits a Registry path and returns the hive and key.

        :param str path: Registry path.
        :rtype: tuple( int, str )
        :return: Tuple containing the hive handle and the subkey path.
            The hive handle is always one of the following integer constants:
             - :const:`~.win32.HKEY_CLASSES_ROOT`
             - :const:`~.win32.HKEY_CURRENT_USER`
             - :const:`~.win32.HKEY_LOCAL_MACHINE`
             - :const:`~.win32.HKEY_USERS`
             - :const:`~.win32.HKEY_PERFORMANCE_DATA`
             - :const:`~.win32.HKEY_CURRENT_CONFIG`
        """
        if "\\" in path:
            p = path.find("\\")
            hive = path[:p]
            path = path[p + 1 :]
        else:
            hive = path
            path = None
        handle = self._hives_by_name[hive.upper()]
        return handle, path

    def _parse_path(self, path):
        """
        Parses a Registry path and returns the hive and key.

        :param str path: Registry path.
        :rtype: tuple( int, str )
        :return: Tuple containing the hive handle and the subkey path.
            For a local Registry, the hive handle is an integer.
            For a remote Registry, the hive handle is a
            :class:`~.win32.RegistryKeyHandle`.
        """
        handle, path = self._split_path(path)
        if self._machine is not None:
            handle = self._connect_hive(handle)
        return handle, path

    def _join_path(self, hive, subkey):
        """
        Joins the hive and key to make a Registry path.

        :param int hive: Registry hive handle.
            The hive handle must be one of the following integer constants:
             - :const:`~.win32.HKEY_CLASSES_ROOT`
             - :const:`~.win32.HKEY_CURRENT_USER`
             - :const:`~.win32.HKEY_LOCAL_MACHINE`
             - :const:`~.win32.HKEY_USERS`
             - :const:`~.win32.HKEY_PERFORMANCE_DATA`
             - :const:`~.win32.HKEY_CURRENT_CONFIG`
        :param str subkey: Subkey path.
        :rtype: str
        :return: Registry path.
        """
        path = self._hives_by_value[hive]
        if subkey:
            path = path + "\\" + subkey
        return path

    def _sanitize_path(self, path):
        """
        Sanitizes the given Registry path.

        :param str path: Registry path.
        :rtype: str
        :return: Registry path.
        """
        return self._join_path(*self._split_path(path))

    def _connect_hive(self, hive):
        """
        Connect to the specified hive of a remote Registry.

        .. note:: The connection will be cached, to close all connections and
            erase this cache call the :meth:`close` method.

        :param int hive: Hive to connect to.
        :rtype: :class:`~.win32.RegistryKeyHandle`
        :return: Open handle to the remote Registry hive.
        """
        try:
            handle = self._remote_hives[hive]
        except KeyError:
            handle = win32.RegConnectRegistry(self._machine, hive)
            self._remote_hives[hive] = handle
        return handle

    def close(self):
        """
        Closes all open connections to the remote Registry.

        No exceptions are raised, even if an error occurs.

        This method has no effect when opening the local Registry.

        The remote Registry will still be accessible after calling this method
        (new connections will be opened automatically on access).
        """
        while self._remote_hives:
            hive = self._remote_hives.popitem()[1]
            try:
                hive.close()
            except Exception as e:
                try:
                    msg = "Cannot close registry hive handle %s, reason: %s"
                    msg %= (hive.value, str(e))
                    warnings.warn(msg)
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __repr__(self):
        if self._machine:
            return '<Remote Registry at "%s">' % self._machine
        return "<Local Registry>"

    def __contains__(self, path):
        hive, subpath = self._parse_path(path)
        try:
            with win32.RegOpenKey(hive, subpath):
                return True
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                return False
            raise

    def __getitem__(self, path):
        path = self._sanitize_path(path)
        hive, subpath = self._parse_path(path)
        try:
            handle = win32.RegOpenKey(hive, subpath)
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                raise KeyError(path)
            raise
        return RegistryKey(path, handle)

    def __setitem__(self, path, value):
        do_copy = isinstance(value, RegistryKey)
        if not do_copy and not isinstance(value, str):
            if isinstance(value, object):
                t = value.__class__.__name__
            else:
                t = type(value)
            raise TypeError("Expected string or RegistryKey, got %s" % t)
        hive, subpath = self._parse_path(path)
        with win32.RegCreateKey(hive, subpath) as handle:
            if do_copy:
                win32.RegCopyTree(value.handle, None, handle)
            else:
                win32.RegSetValueEx(handle, None, value)

    # XXX FIXME currently not working!
    # It's probably best to call RegDeleteKey recursively, even if slower.
    def __delitem__(self, path):
        hive, subpath = self._parse_path(path)
        if not subpath:
            raise TypeError(
                "Are you SURE you want to wipe out an entire hive?!"
                " Call win32.RegDeleteTree() directly if you must..."
            )
        try:
            win32.RegDeleteTree(hive, subpath)
        except WindowsError as e:
            if e.winerror == win32.ERROR_FILE_NOT_FOUND:
                raise KeyError(path)
            raise

    def create(self, path):
        """
        Creates a new Registry key.

        :param str path: Registry key path.
        :rtype: :class:`RegistryKey`
        :return: The newly created Registry key.
        """
        path = self._sanitize_path(path)
        hive, subpath = self._parse_path(path)
        handle = win32.RegCreateKey(hive, subpath)
        return RegistryKey(path, handle)

    def subkeys(self, path):
        """
        Returns a list of subkeys for the given Registry key.

        :param str path: Registry key path.
        :rtype: list(str)
        :return: List of subkey names.
        """
        result = list()
        hive, subpath = self._parse_path(path)
        with win32.RegOpenKey(hive, subpath) as handle:
            index = 0
            while 1:
                name = win32.RegEnumKey(handle, index)
                if name is None:
                    break
                result.append(name)
                index += 1
        return result

    def iterate(self, path):
        """
        Returns a recursive iterator on the specified key and its subkeys.

        :param str path: Registry key path.
        :rtype: iterator
        :return: Recursive iterator that returns Registry key paths.
        :raises KeyError: The specified path does not exist.
        """
        if path.endswith("\\"):
            path = path[:-1]
        if path not in self:
            raise KeyError(path)
        stack = collections.deque()
        stack.appendleft(path)
        return self.__iterate(stack)

    def iterkeys(self):
        """
        Returns an iterator that crawls the entire Windows Registry.
        """
        stack = collections.deque(self._hives)
        stack.reverse()
        return self.__iterate(stack)

    def __iterate(self, stack):
        while stack:
            path = stack.popleft()
            yield path
            try:
                subkeys = self.subkeys(path)
            except WindowsError:
                continue
            prefix = path + "\\"
            subkeys = [prefix + name for name in subkeys]
            stack.extendleft(subkeys)
