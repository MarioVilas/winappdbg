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
Module instrumentation.

Here is the logic for handling DLL libraries loaded by debugees.
"""

__all__ = ['Module', 'DebugSymbolsWarning']

from . import win32
from .textio import HexInput, HexDump
from .util import PathOperations

# delayed imports
Process = None

import warnings
import traceback

#==============================================================================

class DebugSymbolsWarning (UserWarning):
    """
    This warning is issued if the support for debug symbols
    isn't working properly.
    """

#==============================================================================

class Module:
    """
    Interface to a DLL library loaded in the context of another process.

    :cvar unknown: Suggested tag for unknown modules.
    :type unknown: str

    :ivar lpBaseOfDll: Base of DLL module.
        Use :meth:`get_base` instead.
    :type lpBaseOfDll: int

    :ivar hFile: Handle to the module file.
        Use :meth:`get_handle` instead.
    :type hFile: :class:`~winappdbg.win32.FileHandle`

    :ivar fileName: Module filename.
        Use :meth:`get_filename` instead.
    :type fileName: str

    :ivar SizeOfImage: Size of the module.
        Use :meth:`get_size` instead.
    :type SizeOfImage: int

    :ivar EntryPoint: Entry point of the module.
        Use :meth:`get_entry_point` instead.
    :type EntryPoint: int

    :ivar process: Process where the module is loaded.
        Use the :meth:`get_process` method instead.
    :type process: :class:`Process`
    """

    unknown = '<unknown>'

    class _SymbolEnumerator:
        """
        Internally used by :class:`Module` to enumerate symbols in a module.
        """

        def __init__(self, undecorate = False):
            self.symbols = list()
            self.undecorate = undecorate

        def __call__(self, SymbolName, SymbolAddress, SymbolSize, UserContext):
            """
            Callback that receives symbols and stores them in a Python list.
            """
            if self.undecorate:
                try:
                    SymbolName = win32.UnDecorateSymbolName(SymbolName)
                except Exception:
                    pass # not all symbols are decorated!
            try:
                name = SymbolName.decode()
            except UnicodeDecodeError:
                name = SymbolName.decode('latin-1', 'replace')
            self.symbols.append( (name, SymbolAddress, SymbolSize) )
            return win32.TRUE

    def __init__(self, lpBaseOfDll, hFile = None, fileName    = None,
                                                  SizeOfImage = None,
                                                  EntryPoint  = None,
                                                  process     = None):
        """
        :param int lpBaseOfDll: Base address of the module.
        :param hFile: (Optional) Handle to the module file.
        :type  hFile: :class:`~winappdbg.win32.FileHandle`
        :param str fileName: (Optional) Module filename.
        :param int SizeOfImage: (Optional) Size of the module.
        :param int EntryPoint: (Optional) Entry point of the module.
        :param process: (Optional) Process where the module is loaded.
        :type  process: :class:`Process`
        """
        self.lpBaseOfDll    = lpBaseOfDll
        self.fileName       = fileName
        self.SizeOfImage    = SizeOfImage
        self.EntryPoint     = EntryPoint

        self.__symbols = list()

        self.set_handle(hFile)
        self.set_process(process)

    def get_handle(self):
        """
        :returns: File handle.
            Returns ``None`` if unknown.
        :rtype:  :class:`~winappdbg.win32.Handle`
        """
        # no way to guess!
        return self.__hFile

    def set_handle(self, hFile):
        """
        :param hFile: File handle. Use ``None`` to clear.
        :type  hFile: :class:`~winappdbg.win32.Handle`
        """
        if hFile == win32.INVALID_HANDLE_VALUE:
            hFile = None
        self.__hFile = hFile

    hFile = property(get_handle, set_handle, doc="")

    def get_process(self):
        """
        :returns: Parent Process object.
            Returns ``None`` if unknown.
        :rtype:  :class:`Process`
        """
        # no way to guess!
        return self.__process

    def set_process(self, process = None):
        """
        Manually set the parent process. Use with care!

        :param process: (Optional) Process object. Use ``None`` for no process.
        :type  process: :class:`Process`
        """
        if process is None:
            self.__process = None
        else:
            global Process      # delayed import
            if Process is None:
                from .process import Process
            if not isinstance(process, Process):
                msg  = "Parent process must be a Process instance, "
                msg += "got %s instead" % type(process)
                raise TypeError(msg)
            self.__process = process

    process = property(get_process, set_process, doc="")

    def get_pid(self):
        """
        :returns: Parent process global ID.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        process = self.get_process()
        if process is not None:
            return process.get_pid()

    def get_base(self):
        """
        :returns: Base address of the module.
            Returns ``None`` if unknown.
        :rtype:  int or None
        """
        return self.lpBaseOfDll

    def get_size(self):
        """
        :returns: Base size of the module.
            Returns ``None`` if unknown.
        :rtype:  int or None
        """
        if not self.SizeOfImage:
            self.__get_size_and_entry_point()
        return self.SizeOfImage

    def get_entry_point(self):
        """
        :returns: Entry point of the module.
            Returns ``None`` if unknown.
        :rtype:  int or None
        """
        if not self.EntryPoint:
            self.__get_size_and_entry_point()
        return self.EntryPoint

    def __get_size_and_entry_point(self):
        "Get the size and entry point of the module using the Win32 API."
        process = self.get_process()
        if process:
            try:
                handle = process.get_handle( win32.PROCESS_VM_READ |
                                             win32.PROCESS_QUERY_INFORMATION )
                base   = self.get_base()
                mi     = win32.GetModuleInformation(handle, base)
                self.SizeOfImage = mi.SizeOfImage
                self.EntryPoint  = mi.EntryPoint
            except WindowsError as e:
                # GetModuleInformation can fail during early process initialization
                # when the target process hasn't fully set up its module table yet.
                # This is common during debugging when module events are fired
                # before the process is fully initialized.
                # See: https://devblogs.microsoft.com/oldnewthing/20150716-00/?p=45131
                if e.winerror == win32.ERROR_INVALID_HANDLE:
                    # Don't warn for this case - it's expected during early debugging
                    pass
                else:
                    warnings.warn(
                        "Cannot get size and entry point of module %s, reason: %s"\
                        % (self.get_name(), e.strerror), RuntimeWarning)

    def get_filename(self):
        """
        :returns: Module filename.
            Returns ``None`` if unknown.
        :rtype:  str or None
        """
        if self.fileName is None:
            if self.hFile not in (None, win32.INVALID_HANDLE_VALUE):
                fileName = self.hFile.get_filename()
                if fileName:
                    fileName = PathOperations.native_to_win32_pathname(fileName)
                    self.fileName = fileName
        return self.fileName

    def __filename_to_modname(self, pathname):
        """
        :param str pathname: Pathname to a module.
        :returns: Module name.
        :rtype:  str
        """
        filename = PathOperations.pathname_to_filename(pathname)
        if filename:
            filename = filename.lower()
            filepart, extpart = PathOperations.split_extension(filename)
            if filepart and extpart:
                modName = filepart
            else:
                modName = filename
        else:
            modName = pathname
        return modName

    def get_name(self):
        """
        :returns: Module name, as used in labels.
        :rtype:  str

        .. warning:: Names are **NOT** guaranteed to be unique.

            If you need unique identification for a loaded module,
            use the base address instead.

        .. seealso:: :meth:`get_label`
        """
        pathname = self.get_filename()
        if pathname:
            modName = self.__filename_to_modname(pathname)
        else:
            modName = "0x%x" % self.get_base()
        return modName

    def match_name(self, name):
        """
        :returns:
            ``True`` if the given name could refer to this module.
            It may not be exactly the same returned by :meth:`get_name`.
        :rtype:  bool
        """

        # If the given name is exactly our name, return True.
        # Comparison is case insensitive.
        my_name = self.get_name().lower()
        if name.lower() == my_name:
            return True

        # If the given name is a base address, compare it with ours.
        try:
            base = HexInput.integer(name)
        except ValueError:
            base = None
        if base is not None and base == self.get_base():
            return True

        # If the given name is a filename, convert it to a module name.
        # Then compare it with ours, case insensitive.
        modName = self.__filename_to_modname(name)
        if modName.lower() == my_name:
            return True

        # No match.
        return False

#------------------------------------------------------------------------------

    def open_handle(self):
        """
        Opens a new handle to the module.

        The new handle is stored in the :attr:`hFile` property.
        """

        if not self.get_filename():
            msg = "Cannot retrieve filename for module at %s"
            msg = msg % HexDump.address( self.get_base() )
            raise Exception(msg)

        hFile = win32.CreateFile(self.get_filename(),
                                           dwShareMode = win32.FILE_SHARE_READ,
                                 dwCreationDisposition = win32.OPEN_EXISTING)

        # In case hFile was set to an actual handle value instead of a Handle
        # object. This shouldn't happen unless the user tinkered with hFile.
        if not hasattr(self.hFile, '__del__'):
            self.close_handle()

        self.hFile = hFile

    def close_handle(self):
        """
        Closes the handle to the module.

        .. note:: Normally you don't need to call this method. All handles
            created by *WinAppDbg* are automatically closed when the garbage
            collector claims them. So unless you've been tinkering with it,
            setting :attr:`hFile` to ``None`` should be enough.
        """
        try:
            if hasattr(self.hFile, 'close'):
                self.hFile.close()
            elif self.hFile not in (None, win32.INVALID_HANDLE_VALUE):
                win32.CloseHandle(self.hFile)
        finally:
            self.hFile = None

    def get_handle(self):
        """
        :returns: Handle to the module file.
        :rtype:  :class:`~winappdbg.win32.FileHandle`
        """
        if self.hFile in (None, win32.INVALID_HANDLE_VALUE):
            self.open_handle()
        return self.hFile

    def clear(self):
        """
        Clears the resources held by this object.
        """
        try:
            self.set_process(None)
        finally:
            self.close_handle()

#------------------------------------------------------------------------------

    # XXX FIXME
    # I've been told sometimes the debugging symbols APIs don't correctly
    # handle redirected exports (for example ws2_32!recv).
    # I haven't been able to reproduce the bug yet.
    def load_symbols(self):
        """
        Loads the debugging symbols for a module.
        Automatically called by :meth:`get_symbols`.
        """
        if win32.PROCESS_ALL_ACCESS == win32.PROCESS_ALL_ACCESS_VISTA:
            dwAccess = win32.PROCESS_QUERY_LIMITED_INFORMATION
        else:
            dwAccess = win32.PROCESS_QUERY_INFORMATION
        hProcess     = self.get_process().get_handle(dwAccess)
        hFile        = self.hFile
        BaseOfDll    = self.get_base()
        SizeOfDll    = self.get_size()
        Enumerator   = self._SymbolEnumerator()
        try:
            win32.SymInitialize(hProcess)
            SymOptions = win32.SymGetOptions()
            SymOptions |= (
                win32.SYMOPT_ALLOW_ZERO_ADDRESS     |
                win32.SYMOPT_CASE_INSENSITIVE       |
                win32.SYMOPT_FAVOR_COMPRESSED       |
                win32.SYMOPT_INCLUDE_32BIT_MODULES  |
                win32.SYMOPT_UNDNAME
            )
            SymOptions &= ~(
                win32.SYMOPT_LOAD_LINES         |
                win32.SYMOPT_NO_IMAGE_SEARCH    |
                win32.SYMOPT_NO_CPP             |
                win32.SYMOPT_IGNORE_NT_SYMPATH
            )
            win32.SymSetOptions(SymOptions)
            try:
                win32.SymSetOptions(
                    SymOptions | win32.SYMOPT_ALLOW_ABSOLUTE_SYMBOLS)
            except WindowsError:
                pass
            try:
                try:
                    success = win32.SymLoadModule64(
                        hProcess, hFile, None, None, BaseOfDll, SizeOfDll)
                except WindowsError:
                    success = 0
                if not success:
                    ImageName = self.get_filename()
                    success = win32.SymLoadModule64(
                        hProcess, None, ImageName, None, BaseOfDll, SizeOfDll)
                if success:
                    try:
                        win32.SymEnumerateSymbols64(
                            hProcess, BaseOfDll, Enumerator)
                    finally:
                        win32.SymUnloadModule64(hProcess, BaseOfDll)
            finally:
                win32.SymCleanup(hProcess)
        except WindowsError as e:
            msg = "Cannot load debug symbols for process ID %d, reason:\n%s"
            msg = msg % (self.get_pid(), traceback.format_exc(e))
            warnings.warn(msg, DebugSymbolsWarning)
        self.__symbols = Enumerator.symbols

    def unload_symbols(self):
        """
        Unloads the debugging symbols for a module.
        """
        self.__symbols = list()

    def get_symbols(self):
        """
        Returns the debugging symbols for a module.
        The symbols are automatically loaded when needed.

        :returns: List of symbols.
            Each symbol is represented by a tuple that contains:
            - Symbol name
            - Symbol memory address
            - Symbol size in bytes
        :rtype:  list(tuple(str, int, int))
        """
        if not self.__symbols:
            self.load_symbols()
        return list(self.__symbols)

    def iter_symbols(self):
        """
        Returns an iterator for the debugging symbols in a module,
        in no particular order.
        The symbols are automatically loaded when needed.

        :returns: Iterator of symbols.
            Each symbol is represented by a tuple that contains:
            - Symbol name
            - Symbol memory address
            - Symbol size in bytes
        :rtype:  iterator of tuple(str, int, int)
        """
        if not self.__symbols:
            self.load_symbols()
        return self.__symbols.__iter__()

    def resolve_symbol(self, symbol, bCaseSensitive = False):
        """
        Resolves a debugging symbol's address.

        :param str symbol: Name of the symbol to resolve.
        :param bool bCaseSensitive: ``True`` for case sensitive matches,
            ``False`` for case insensitive.

        :returns: Memory address of symbol. ``None`` if not found.
        :rtype:  int or None
        """
        if bCaseSensitive:
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                if symbol == SymbolName:
                    return SymbolAddress
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                try:
                    SymbolName = win32.UnDecorateSymbolName(SymbolName)
                except Exception:
                    continue
                if symbol == SymbolName:
                    return SymbolAddress
        else:
            symbol = symbol.lower()
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                if symbol == SymbolName.lower():
                    return SymbolAddress
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                try:
                    SymbolName = win32.UnDecorateSymbolName(SymbolName)
                except Exception:
                    continue
                if symbol == SymbolName.lower():
                    return SymbolAddress

    def get_symbol_at_address(self, address):
        """
        Tries to find the closest matching symbol for the given address.

        :param int address: Memory address to query.
        :returns: Returns a tuple consisting of:
             - Name
             - Address
             - Size (in bytes)

            Returns ``None`` if no symbol could be matched.
        :rtype: None or tuple(str, int, int)
        """
        result = None
        symbols = self.get_symbols()
        symbols.sort()
        for SymbolName, SymbolAddress, SymbolSize in symbols:
            if SymbolAddress > address:
                break
            result = (SymbolName, SymbolAddress, SymbolSize)
        return result

#------------------------------------------------------------------------------

    def get_label(self, function = None, offset = None):
        """
        Retrieves the label for the given function of this module or the module
        base address if no function name is given.

        :param function: (Optional) Exported function name.
        :type  function: str
        :param int offset: (Optional) Offset from the module base address.
        :returns: Label for the module base address, plus the offset if given.
        :rtype:  str
        """
        return _ModuleContainer.parse_label(self.get_name(), function, offset)

    def get_label_at_address(self, address, offset = None):
        """
        Creates a label from the given memory address.

        If the address belongs to the module, the label is made relative to
        it's base address.

        :param int address: Memory address.
        :param offset: (Optional) Offset value.
        :type  offset: None or int
        :returns: Label pointing to the given address.
        :rtype:  str
        """

        # Add the offset to the address.
        if offset:
            address = address + offset

        # Make the label relative to the base address if no match is found.
        module      = self.get_name()
        function    = None
        offset      = address - self.get_base()

        # Make the label relative to the entrypoint if no other match is found.
        # Skip if the entry point is unknown.
        start = self.get_entry_point()
        if start and start <= address:
            function    = "start"
            offset      = address - start

        # Enumerate exported functions and debug symbols,
        # then find the closest match, if possible.
        try:
            symbol = self.get_symbol_at_address(address)
            if symbol:
                (SymbolName, SymbolAddress, SymbolSize) = symbol
                new_offset = address - SymbolAddress
                if new_offset <= offset:
                    function    = SymbolName
                    offset      = new_offset
        except WindowsError:
            pass

        # Parse the label and return it.
        return _ModuleContainer.parse_label(module, function, offset)

    def is_address_here(self, address):
        """
        Tries to determine if the given address belongs to this module.

        :param int address: Memory address.
        :returns: ``True`` if the address belongs to the module,
            ``False`` if it doesn't,
            and ``None`` if it can't be determined.
        :rtype:  bool or None
        """
        base = self.get_base()
        size = self.get_size()
        if base and size:
            return base <= address < (base + size)
        return None

    def resolve(self, function):
        """
        Resolves a function exported by this module.

        :param function:
            - ``str``: Name of the function (Unicode).
            - ``bytes``: Name of the function (ANSI).
            - ``int``: Ordinal of the function.
        :type  function: str, bytes or int

        :returns: Memory address of the exported function in the process.
            Returns None on error.
        :rtype:  int
        """

        # Unknown DLL filename, there's nothing we can do.
        filename = self.get_filename()
        if not filename:
            return None

        # If the DLL is already mapped locally, resolve the function.
        try:
            hlib    = win32.GetModuleHandle(filename)
            address = win32.GetProcAddress(hlib, function)
        except WindowsError:

            # Load the DLL locally, resolve the function and unload it.
            try:
                hlib = win32.LoadLibraryEx(filename,
                                           win32.DONT_RESOLVE_DLL_REFERENCES)
                try:
                    address = win32.GetProcAddress(hlib, function)
                finally:
                    win32.FreeLibrary(hlib)
            except WindowsError:
                return None

        # A NULL pointer means the function was not found.
        if address in (None, 0):
            return None

        # Compensate for DLL base relocations locally and remotely.
        return address - hlib + self.lpBaseOfDll

    def resolve_label(self, label):
        """
        Resolves a label for this module only. If the label refers to another
        module, an exception is raised.

        :param str label: Label to resolve.

        :returns: Memory address pointed to by the label.
        :rtype:  int

        :raises ValueError: The label is malformed or impossible to resolve.
        :raises RuntimeError: Cannot resolve the module or function.
        """

        # Split the label into it's components.
        # Use the fuzzy mode whenever possible.
        aProcess = self.get_process()
        if aProcess is not None:
            (module, procedure, offset) = aProcess.split_label(label)
        else:
            (module, procedure, offset) = _ModuleContainer.split_label(label)

        # If a module name is given that doesn't match ours,
        # raise an exception.
        if module and not self.match_name(module):
            raise RuntimeError("Label does not belong to this module")

        # Resolve the procedure if given.
        if procedure:
            address = self.resolve(procedure)
            if address is None:

                # If it's a debug symbol, use the symbol.
                address = self.resolve_symbol(procedure)

                # If it's the keyword "start" use the entry point.
                if address is None and procedure == "start":
                    address = self.get_entry_point()

                # The procedure was not found.
                if address is None:
                    if not module:
                        module = self.get_name()
                    msg = "Can't find procedure %s in module %s"
                    raise RuntimeError(msg % (procedure, module))

        # If no procedure is given use the base address of the module.
        else:
            address = self.get_base()

        # Add the offset if given and return the resolved address.
        if offset:
            address = address + offset
        return address

#==============================================================================

# TODO
# An alternative approach to the toolhelp32 snapshots: parsing the PEB and
# fetching the list of loaded modules from there. That would solve the problem
# of toolhelp32 not working when the process hasn't finished initializing.
# See: http://pferrie.host22.com/misc/lowlevel3.htm

class _ModuleContainer:
    """
    Encapsulates the capability to contain Module objects.

    .. note:: Labels are an approximated way of referencing memory locations
        across different executions of the same process, or different processes
        with common modules. They are not meant to be perfectly unique, and
        some errors may occur when multiple modules with the same name are
        loaded, or when module filenames can't be retrieved.
    """

    def __init__(self):
        self.__moduleDict = dict()
        self.__system_breakpoints = dict()

        # Replace split_label with the fuzzy version on object instances.
        self.split_label = self.__use_fuzzy_mode

    def __initialize_snapshot(self):
        """
        Private method to automatically initialize the snapshot
        when you try to use it without calling any of the scan_*
        methods first. You don't need to call this yourself.
        """
        if not self.__moduleDict:
            try:
                self.scan_modules()
            except WindowsError:
                pass

    def __contains__(self, anObject):
        """
        :param anObject:
            - :class:`Module`: Module object to look for.
            - ``int``: Base address of the DLL to look for.
        :type  anObject: :class:`Module`, int

        :returns: ``True`` if the snapshot contains
            a :class:`Module` object with the same base address.
        :rtype:  bool
        """
        if isinstance(anObject, Module):
            anObject = anObject.lpBaseOfDll
        return self.has_module(anObject)

    def __iter__(self):
        """
        :returns: Iterator of :class:`Module` objects in this snapshot.
        :rtype:  dictionary-valueiterator

        .. seealso:: :meth:`iter_modules`
        """
        return self.iter_modules()

    def __len__(self):
        """
        :returns: Count of :class:`Module` objects in this snapshot.
        :rtype:  int

        .. seealso:: :meth:`get_module_count`
        """
        return self.get_module_count()

    def has_module(self, lpBaseOfDll):
        """
        :param int lpBaseOfDll: Base address of the DLL to look for.
        :returns: ``True`` if the snapshot contains a
            :class:`Module` object with the given base address.
        :rtype:  bool
        """
        self.__initialize_snapshot()
        return lpBaseOfDll in self.__moduleDict

    def get_module(self, lpBaseOfDll):
        """
        :param int lpBaseOfDll: Base address of the DLL to look for.
        :returns: Module object with the given base address.
        :rtype:  :class:`Module`
        """
        self.__initialize_snapshot()
        if lpBaseOfDll not in self.__moduleDict:
            msg = "Unknown DLL base address %s"
            msg = msg % HexDump.address(lpBaseOfDll)
            raise KeyError(msg)
        return self.__moduleDict[lpBaseOfDll]

    def iter_module_addresses(self):
        """
        :returns: Iterator of DLL base addresses in this snapshot.
        :rtype:  dictionary-keyiterator

        .. seealso:: :meth:`iter_modules`
        """
        self.__initialize_snapshot()
        return self.__moduleDict.keys()

    def iter_modules(self):
        """
        :returns: Iterator of :class:`Module` objects in this snapshot.
        :rtype:  dictionary-valueiterator

        .. seealso:: :meth:`iter_module_addresses`
        """
        self.__initialize_snapshot()
        return self.__moduleDict.values()

    def get_module_bases(self):
        """
        :returns: List of DLL base addresses in this snapshot.
        :rtype:  list(int)

        .. seealso:: :meth:`iter_module_addresses`
        """
        self.__initialize_snapshot()
        return list(self.__moduleDict.keys())

    def get_module_count(self):
        """
        :returns: Count of :class:`Module` objects in this snapshot.
        :rtype:  int
        """
        self.__initialize_snapshot()
        return len(self.__moduleDict)

#------------------------------------------------------------------------------

    def get_module_by_name(self, modName):
        """
        :param str modName:
            Name of the module to look for, as returned by :meth:`Module.get_name`.
            If two or more modules with the same name are loaded, only one
            of the matching modules is returned.

            You can also pass a full pathname to the DLL file.
            This works correctly even if two modules with the same name
            are loaded from different paths.

        :returns: :class:`Module` object that best matches the given name.
            Returns ``None`` if no :class:`Module` can be found.
        :rtype:  :class:`Module`
        """

        # Convert modName to lowercase.
        # This helps make case insensitive string comparisons.
        modName = modName.lower()

        # modName is an absolute pathname.
        if PathOperations.path_is_absolute(modName):
            for lib in self.iter_modules():
                if modName == lib.get_filename().lower():
                    return lib
            return None     # Stop trying to match the name.

        # Get all the module names.
        # This prevents having to iterate through the module list
        #  more than once.
        modDict = [ ( lib.get_name(), lib ) for lib in self.iter_modules() ]
        modDict = dict(modDict)

        # modName is a base filename.
        if modName in modDict:
            return modDict[modName]

        # modName is a base filename without extension.
        filepart, extpart = PathOperations.split_extension(modName)
        if filepart and extpart:
            if filepart in modDict:
                return modDict[filepart]

        # modName is a base address.
        try:
            baseAddress = HexInput.integer(modName)
        except ValueError:
            return None
        if self.has_module(baseAddress):
            return self.get_module(baseAddress)

        # Module not found.
        return None

    def get_module_at_address(self, address):
        """
        :param int address: Memory address to query.
        :returns: :class:`Module` object that best matches the given address.
            Returns ``None`` if no :class:`Module` can be found.
        :rtype:  :class:`Module`
        """
        bases = self.get_module_bases()
        bases = sorted(bases)
        bases.append(0x10000000000000000)  # max. 64 bit address + 1
        if address >= bases[0]:
            i = 0
            max_i = len(bases) - 1
            while i < max_i:
                begin, end = bases[i:i+2]
                if begin <= address < end:
                    module = self.get_module(begin)
                    here   = module.is_address_here(address)
                    if here is False:
                        break
                    else:   # True or None
                        return module
                i = i + 1
        return None

    # XXX this method musn't end up calling __initialize_snapshot by accident!
    def scan_modules(self):
        """
        Populates the snapshot with loaded modules.
        """

        # The module filenames may be spoofed by malware,
        # since this information resides in usermode space.
        # See: http://www.ragestorm.net/blogs/?p=163

        # Ignore special process IDs.
        # PID 0: System Idle Process. Also has a special meaning to the
        #        toolhelp APIs (current process).
        # PID 4: System Integrity Group. See this forum post for more info:
        #        http://tinyurl.com/ycza8jo
        #        (points to social.technet.microsoft.com)
        #        Only on XP and above
        # PID 8: System (?) only in Windows 2000 and below AFAIK.
        #        It's probably the same as PID 4 in XP and above.
        dwProcessId = self.get_pid()
        if dwProcessId in (0, 4, 8):
            return

        # It would seem easier to clear the snapshot first.
        # But then all open handles would be closed.
        found_bases = set()
        with win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPMODULE,
                                            dwProcessId) as hSnapshot:
            me = win32.Module32First(hSnapshot)
            while me is not None:
                lpBaseAddress = me.modBaseAddr
                fileName      = me.szExePath    # full pathname
                if not fileName:
                    fileName  = me.szModule     # filename only
                    if not fileName:
                        fileName = None
                else:
                    fileName = PathOperations.native_to_win32_pathname(fileName)
                found_bases.add(lpBaseAddress)
##                if not self.has_module(lpBaseAddress): # XXX triggers a scan
                if lpBaseAddress not in self.__moduleDict:
                    aModule = Module(lpBaseAddress, fileName = fileName,
                                           SizeOfImage = me.modBaseSize,
                                           process = self)
                    self._add_module(aModule)
                else:
                    aModule = self.get_module(lpBaseAddress)
                    if not aModule.fileName:
                        aModule.fileName    = fileName
                    if not aModule.SizeOfImage:
                        aModule.SizeOfImage = me.modBaseSize
                    if not aModule.process:
                        aModule.process     = self
                me = win32.Module32Next(hSnapshot)
##        for base in self.get_module_bases(): # XXX triggers a scan
        for base in list(self.__moduleDict.keys()):
            if base not in found_bases:
                self._del_module(base)

    def clear_modules(self):
        """
        Clears the modules snapshot.
        """
        for aModule in self.__moduleDict.values():
            aModule.clear()
        self.__moduleDict = dict()

#------------------------------------------------------------------------------

    @staticmethod
    def parse_label(module = None, function = None, offset = None):
        """
        Creates a label from a module and a function name, plus an offset.

        .. warning:: This method only creates the label, it doesn't make sure the
            label actually points to a valid memory location.

        :param module: (Optional) Module name.
        :type  module: None or str
        :param function: (Optional) Function name or ordinal.
        :type  function: None, str or int
        :param offset: (Optional) Offset value.

            If ``function`` is specified, offset from the function.

            If ``function`` is ``None``, offset from the module.
        :type  offset: None or int

        :returns:
            Label representing the given function in the given module.
        :rtype:  str

        :raises ValueError:
            The module or function name contain invalid characters.
        """

        # TODO
        # Invalid characters should be escaped or filtered.

        # Convert ordinals to strings.
        try:
            function = "#0x%x" % function
        except TypeError:
            pass

        # Validate the parameters.
        if module is not None and ('!' in module or '+' in module):
            raise ValueError("Invalid module name: %s" % module)
        if function is not None and ('!' in str(function) or '+' in str(function)):
            raise ValueError("Invalid function name: %s" % function)

        # Parse the label.
        if module:
            if function:
                if offset:
                    label = "%s!%s+0x%x" % (module, function, offset)
                else:
                    label = "%s!%s" % (module, function)
            else:
                if offset:
##                    label = "%s+0x%x!" % (module, offset)
                    label = "%s!0x%x" % (module, offset)
                else:
                    label = "%s!" % module
        else:
            if function:
                if offset:
                    label = "!%s+0x%x" % (function, offset)
                else:
                    label = "!%s" % function
            else:
                if offset:
                    label = "0x%x" % offset
                else:
                    label = "0x0"

        return label

    @staticmethod
    def split_label_strict(label):
        """
        Splits a label created with :meth:`parse_label`.

        To parse labels with a less strict syntax, use the :meth:`split_label_fuzzy`
        method instead.

        .. warning:: This method only parses the label, it doesn't make sure the
            label actually points to a valid memory location.

        :param str label: Label to split.
        :returns: Tuple containing the ``module`` name,
            the ``function`` name or ordinal, and the ``offset`` value.

            If the label doesn't specify a module,
            then ``module`` is ``None``.

            If the label doesn't specify a function,
            then ``function`` is ``None``.

            If the label doesn't specify an offset,
            then ``offset`` is ``0``.
        :rtype:  tuple(str or None, str or int or None, int or None)

        :raises ValueError: The label is malformed.
        """
        module = function = None
        offset = 0

        # Special case: None
        if not label:
            label = "0x0"
        else:

            # Remove all blanks.
            label = label.replace(' ', '')
            label = label.replace('\t', '')
            label = label.replace('\r', '')
            label = label.replace('\n', '')

            # Special case: empty label.
            if not label:
                label = "0x0"

        # * ! *
        if '!' in label:
            try:
                module, function = label.split('!')
            except ValueError:
                raise ValueError("Malformed label: %s" % label)

            # module ! function
            if function:
                if '+' in module:
                    raise ValueError("Malformed label: %s" % label)

                # module ! function + offset
                if '+' in function:
                    try:
                        function, offset = function.split('+')
                    except ValueError:
                        raise ValueError("Malformed label: %s" % label)
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError("Malformed label: %s" % label)
                else:

                    # module ! offset
                    try:
                        offset   = HexInput.integer(function)
                        function = None
                    except ValueError:
                        pass
            else:

                # module + offset !
                if '+' in module:
                    try:
                        module, offset = module.split('+')
                    except ValueError:
                        raise ValueError("Malformed label: %s" % label)
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError("Malformed label: %s" % label)

                else:

                    # module !
                    try:
                        offset = HexInput.integer(module)
                        module = None

                    # offset !
                    except ValueError:
                        pass

            if not module:
                module   = None
            if not function:
                function = None

        # *
        else:

            # offset
            try:
                offset = HexInput.integer(label)

            # # ordinal
            except ValueError:
                if label.startswith('#'):
                    function = label
                    try:
                        HexInput.integer(function[1:])

                    # module?
                    # function?
                    except ValueError:
                        raise ValueError("Ambiguous label: %s" % label)

                # module?
                # function?
                else:
                    raise ValueError("Ambiguous label: %s" % label)

        # Convert function ordinal strings into integers.
        if function and function.startswith('#'):
            try:
                function = HexInput.integer(function[1:])
            except ValueError:
                pass

        # Convert null offsets to None.
        if not offset:
            offset = None

        return (module, function, offset)

    def split_label_fuzzy(self, label):
        """
        Splits a label entered as user input.

        It's more flexible in it's syntax parsing than the :meth:`split_label_strict`
        method, as it allows the exclamation mark ``!`` to be omitted. The
        ambiguity is resolved by searching the modules in the snapshot to guess
        if a label refers to a module or a function. It also tries to rebuild
        labels when they contain hardcoded addresses.

        .. warning:: This method only parses the label, it doesn't make sure the
            label actually points to a valid memory location.

        :param str label: Label to split.
        :returns: Tuple containing the ``module`` name,
            the ``function`` name or ordinal, and the ``offset`` value.

            If the label doesn't specify a module,
            then ``module`` is ``None``.

            If the label doesn't specify a function,
            then ``function`` is ``None``.

            If the label doesn't specify an offset,
            then ``offset`` is ``0``.
        :rtype:  tuple(str or None, str or int or None, int or None)

        :raises ValueError: The label is malformed.
        """
        module = function = None
        offset = 0

        # Special case: None
        if not label:
            label = "0x0"
        else:

            # Remove all blanks.
            label = label.replace(' ', '')
            label = label.replace('\t', '')
            label = label.replace('\r', '')
            label = label.replace('\n', '')

            # Special case: empty label.
            if not label:
                label = "0x0"

        # If an exclamation sign is present, we know we can parse it strictly.
        if '!' in label:
            return self.split_label_strict(label)

##        # Try to parse it strictly, on error do it the fuzzy way.
##        try:
##            return self.split_label(label)
##        except ValueError:
##            pass

        # * + offset
        if '+' in label:
            try:
                prefix, offset = label.split('+')
            except ValueError:
                raise ValueError("Malformed label: %s" % label)
            try:
                offset = HexInput.integer(offset)
            except ValueError:
                raise ValueError("Malformed label: %s" % label)
            label = prefix

        # This parses both filenames and base addresses.
        modobj = self.get_module_by_name(label)
        if modobj:

            # module
            # module + offset
            module = modobj.get_name()

        else:

            # TODO
            # If 0xAAAAAAAA + 0xBBBBBBBB is given,
            # A is interpreted as a module base address,
            # and B as an offset.
            # If that fails, it'd be good to add A+B and try to
            # use the nearest loaded module.

            # offset
            # base address + offset (when no module has that base address)
            try:
                address = HexInput.integer(label)

                if offset:
                    # If 0xAAAAAAAA + 0xBBBBBBBB is given,
                    # A is interpreted as a module base address,
                    # and B as an offset.
                    # If that fails, we get here, meaning no module was found
                    # at A. Then add up A+B and work with that as a hardcoded
                    # address.
                    offset = address + offset
                else:
                    # If the label is a hardcoded address, we get here.
                    offset = address

                # If only a hardcoded address is given,
                # rebuild the label using get_label_at_address.
                # Then parse it again, but this time strictly,
                # both because there is no need for fuzzy syntax and
                # to prevent an infinite recursion if there's a bug here.
                try:
                    new_label = self.get_label_at_address(offset)
                    module, function, offset = \
                                             self.split_label_strict(new_label)
                except ValueError:
                    pass

            # function
            # function + offset
            except ValueError:
                function = label

        # Convert function ordinal strings into integers.
        if function and function.startswith('#'):
            try:
                function = HexInput.integer(function[1:])
            except ValueError:
                pass

        # Convert null offsets to None.
        if not offset:
            offset = None

        return (module, function, offset)

    @classmethod
    def split_label(cls, label):
        """
        Splits a label into it's ``module``, ``function`` and ``offset``
        components, as used in :meth:`parse_label`.

        When called as a static method, the strict syntax mode is used::

            winappdbg.Process.split_label( "kernel32!CreateFileA" )

        When called as an instance method, the fuzzy syntax mode is used::

            aProcessInstance.split_label( "CreateFileA" )

        :param str label: Label to split.
        :returns:
            Tuple containing the ``module`` name,
            the ``function`` name or ordinal, and the ``offset`` value.

            If the label doesn't specify a module,
            then ``module`` is ``None``.

            If the label doesn't specify a function,
            then ``function`` is ``None``.

            If the label doesn't specify an offset,
            then ``offset`` is ``0``.
        :rtype:  tuple(str or None, str or int or None, int or None)
        :raises ValueError: The label is malformed.

        .. seealso:: :meth:`split_label_strict`, :meth:`split_label_fuzzy`
        """

        # This function is overwritten by __init__
        # so here is the static implementation only.
        return cls.split_label_strict(label)

    # The split_label method is replaced with this function by __init__.
    def __use_fuzzy_mode(self, label):
        """
        .. seealso:: :meth:`split_label`
        """
        return self.split_label_fuzzy(label)
##    __use_fuzzy_mode.__doc__ = split_label.__doc__

    def sanitize_label(self, label):
        """
        Converts a label taken from user input into a well-formed label.

        :param str label: Label taken from user input.
        :returns: Sanitized label.
        :rtype:  str
        """
        (module, function, offset) = self.split_label_fuzzy(label)
        label = self.parse_label(module, function, offset)
        return label

    def resolve_label(self, label):
        """
        Resolve the memory address of the given label.

        .. note::
            If multiple modules with the same name are loaded,
            the label may be resolved at any of them. For a more precise
            way to resolve functions use the base address to get the :class:`Module`
            object (see :meth:`Process.get_module`) and then call :meth:`Module.resolve`.

            If no module name is specified in the label, the function may be
            resolved in any loaded module. If you want to resolve all functions
            with that name in all processes, call :meth:`Process.iter_modules` to
            iterate through all loaded modules, and then try to resolve the
            function in each one of them using :meth:`Module.resolve`.

        :param str label: Label to resolve.
        :returns: Memory address pointed to by the label.
        :rtype:  int

        :raises ValueError: The label is malformed or impossible to resolve.
        :raises RuntimeError: Cannot resolve the module or function.
        """

        # Split the label into module, function and offset components.
        module, function, offset = self.split_label_fuzzy(label)

        # Resolve the components into a memory address.
        address = self.resolve_label_components(module, function, offset)

        # Return the memory address.
        return address

    def resolve_label_components(self, module   = None,
                                       function = None,
                                       offset   = None):
        """
        Resolve the memory address of the given module, function and/or offset.

        .. note::
            If multiple modules with the same name are loaded,
            the label may be resolved at any of them. For a more precise
            way to resolve functions use the base address to get the :class:`Module`
            object (see :meth:`Process.get_module`) and then call :meth:`Module.resolve`.

            If no module name is specified in the label, the function may be
            resolved in any loaded module. If you want to resolve all functions
            with that name in all processes, call :meth:`Process.iter_modules` to
            iterate through all loaded modules, and then try to resolve the
            function in each one of them using :meth:`Module.resolve`.

        :param module: (Optional) Module name.
        :type  module: None or str
        :param function: (Optional) Function name or ordinal.
            - ``str``: Name of the function (Unicode).
            - ``bytes``: Name of the function (ANSI).
            - ``int``: Ordinal of the function.
        :type  function: None, str, bytes or int
        :param offset: (Optional) Offset value.

            If ``function`` is specified, offset from the function.

            If ``function`` is ``None``, offset from the module.
        :type  offset: None or int

        :returns: Memory address pointed to by the label.
        :rtype:  int

        :raises ValueError: The label is malformed or impossible to resolve.
        :raises RuntimeError: Cannot resolve the module or function.
        """
        # Default address if no module or function are given.
        # An offset may be added later.
        address = 0

        # Resolve the module.
        # If the module is not found, check for the special symbol "main".
        if module:
            modobj = self.get_module_by_name(module)
            if not modobj:
                if module == "main":
                    modobj = self.get_main_module()
                else:
                    raise RuntimeError("Module %r not found" % module)

            # Resolve the exported function or debugging symbol.
            # If all else fails, check for the special symbol "start".
            if function:
                address = modobj.resolve(function)
                if address is None:
                    address = modobj.resolve_symbol(function)
                    if address is None:
                        if function == "start":
                            address = modobj.get_entry_point()
                        if address is None:
                            msg = "Symbol %r not found in module %s"
                            raise RuntimeError(msg % (function, module))

            # No function, use the base address.
            else:
                address = modobj.get_base()

        # Resolve the function in any module.
        # If all else fails, check for the special symbols "main" and "start".
        elif function:
            for modobj in self.iter_modules():
                address = modobj.resolve(function)
                if address is not None:
                    break
            if address is None:
                if function == "start":
                    modobj = self.get_main_module()
                    address = modobj.get_entry_point()
                elif function == "main":
                    modobj = self.get_main_module()
                    address = modobj.get_base()
                else:
                    msg = "Function %r not found in any module" % function
                    raise RuntimeError(msg)

        # Return the address plus the offset.
        if offset:
            address = address + offset
        return address

    def get_label_at_address(self, address, offset = None):
        """
        Creates a label from the given memory address.

        .. warning:: This method uses the name of the nearest currently loaded
            module. If that module is unloaded later, the label becomes
            impossible to resolve.

        :param int address: Memory address.
        :param offset: (Optional) Offset value.
        :type  offset: None or int
        :returns: Label pointing to the given address.
        :rtype:  str
        """
        if offset:
            address = address + offset
        modobj = self.get_module_at_address(address)
        if modobj:
            label = modobj.get_label_at_address(address)
        else:
            label = self.parse_label(None, None, address)
        return label

#------------------------------------------------------------------------------

    # The memory addresses of system breakpoints are be cached, since they're
    # all in system libraries it's not likely they'll ever change their address
    # during the lifetime of the process... I don't suppose a program could
    # happily unload ntdll.dll and survive.
    def __get_system_breakpoint(self, label):
        try:
            return self.__system_breakpoints[label]
        except KeyError:
            try:
                address = self.resolve_label(label)
            except Exception:
                return None
            self.__system_breakpoints[label] = address
            return address

    # It's in kernel32 in Windows Server 2003, in ntdll since Windows Vista.
    # It can only be resolved if we have the debug symbols.
    def get_break_on_error_ptr(self):
        """
        :returns:
            If present, returns the address of the ``g_dwLastErrorToBreakOn``
            global variable for this process. If not, returns ``None``.
        :rtype: int
        """
        address = self.__get_system_breakpoint("ntdll!g_dwLastErrorToBreakOn")
        if not address:
            address = self.__get_system_breakpoint(
                                            "kernel32!g_dwLastErrorToBreakOn")
            # cheat a little :)
            if address:
                self.__system_breakpoints["ntdll!g_dwLastErrorToBreakOn"] = address
        return address

    def is_system_defined_breakpoint(self, address):
        """
        :param int address: Memory address.
        :returns: ``True`` if the given address points to a system defined
            breakpoint. System defined breakpoints are hardcoded into
            system libraries.
        :rtype:  bool
        """
        if address:
            module = self.get_module_at_address(address)
            if module:
                return module.match_name("ntdll")    or \
                       module.match_name("kernel32")
        return False

    # FIXME
    # In Wine, the system breakpoint seems to be somewhere in kernel32.
    def get_system_breakpoint(self):
        """
        :returns: Memory address of the system breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll!DbgBreakPoint")

    # I don't know when this breakpoint is actually used...
    def get_user_breakpoint(self):
        """
        :returns: Memory address of the user breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll!DbgUserBreakPoint")

    # On some platforms, this breakpoint can only be resolved
    # when the debugging symbols for ntdll.dll are loaded.
    def get_breakin_breakpoint(self):
        """
        :returns: Memory address of the remote breakin breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll!DbgUiRemoteBreakin")

    # Equivalent of ntdll!DbgBreakPoint in Wow64.
    def get_wow64_system_breakpoint(self):
        """
        :returns: Memory address of the Wow64 system breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll32!DbgBreakPoint")

    # Equivalent of ntdll!DbgUserBreakPoint in Wow64.
    def get_wow64_user_breakpoint(self):
        """
        :returns: Memory address of the Wow64 user breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll32!DbgUserBreakPoint")

    # Equivalent of ntdll!DbgUiRemoteBreakin in Wow64.
    def get_wow64_breakin_breakpoint(self):
        """
        :returns: Memory address of the Wow64 remote breakin breakpoint
            within the process address space.
            Returns ``None`` on error.
        :rtype:  int or None
        """
        return self.__get_system_breakpoint("ntdll32!DbgUiRemoteBreakin")

#------------------------------------------------------------------------------

    def load_symbols(self):
        """
        Loads the debugging symbols for all modules in this snapshot.
        Automatically called by :meth:`get_symbols`.
        """
        for aModule in self.iter_modules():
            aModule.load_symbols()

    def unload_symbols(self):
        """
        Unloads the debugging symbols for all modules in this snapshot.
        """
        for aModule in self.iter_modules():
            aModule.unload_symbols()

    def get_symbols(self):
        """
        Returns the debugging symbols for all modules in this snapshot.
        The symbols are automatically loaded when needed.

        :returns: List of symbols.
            Each symbol is represented by a tuple that contains:
            - Symbol name
            - Symbol memory address
            - Symbol size in bytes
        :rtype:  list(tuple(str, int, int))
        """
        symbols = list()
        for aModule in self.iter_modules():
            for symbol in aModule.iter_symbols():
                symbols.append(symbol)
        return symbols

    def iter_symbols(self):
        """
        Returns an iterator for the debugging symbols in all modules in this
        snapshot, in no particular order.
        The symbols are automatically loaded when needed.

        :returns: Iterator of symbols.
            Each symbol is represented by a tuple that contains:
            - Symbol name
            - Symbol memory address
            - Symbol size in bytes
        :rtype:  iterator of tuple(str, int, int)
        """
        for aModule in self.iter_modules():
            for symbol in aModule.iter_symbols():
                yield symbol

    def resolve_symbol(self, symbol, bCaseSensitive = False):
        """
        Resolves a debugging symbol's address.

        :param str symbol: Name of the symbol to resolve.
        :param bool bCaseSensitive: ``True`` for case sensitive matches,
            ``False`` for case insensitive.

        :returns: Memory address of symbol. ``None`` if not found.
        :rtype:  int or None
        """
        if bCaseSensitive:
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                if symbol == SymbolName:
                    return SymbolAddress
        else:
            symbol = symbol.lower()
            for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
                if symbol == SymbolName.lower():
                    return SymbolAddress

    def get_symbol_at_address(self, address):
        """
        Tries to find the closest matching symbol for the given address.

        :param int address: Memory address to query.
        :returns: Returns a tuple consisting of:
             - Name
             - Address
             - Size (in bytes)

            Returns ``None`` if no symbol could be matched.
        :rtype: None or tuple(str, int, int)
        """
        # Any module may have symbols pointing anywhere in memory, so there's
        # no easy way to optimize this. I guess we're stuck with brute force.
        found = None
        for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
            if SymbolAddress > address:
                continue

            if SymbolAddress == address:
                found = (SymbolName, SymbolAddress, SymbolSize)
                break

            if SymbolAddress < address:
                if found and (address - found[1]) < (address - SymbolAddress):
                    continue
                else:
                    found = (SymbolName, SymbolAddress, SymbolSize)
        return found

#------------------------------------------------------------------------------

    # XXX _notify_* methods should not trigger a scan

    def _add_module(self, aModule):
        """
        Private method to add a module object to the snapshot.

        :param aModule: Module object.
        :type  aModule: :class:`Module`
        """
##        if not isinstance(aModule, Module):
##            if hasattr(aModule, '__class__'):
##                typename = aModule.__class__.__name__
##            else:
##                typename = str(type(aModule))
##            msg = "Expected Module, got %s instead" % typename
##            raise TypeError(msg)
        lpBaseOfDll = aModule.get_base()
##        if lpBaseOfDll in self.__moduleDict:
##            msg = "Module already exists: %d" % lpBaseOfDll
##            raise KeyError(msg)
        aModule.set_process(self)
        self.__moduleDict[lpBaseOfDll] = aModule

    def _del_module(self, lpBaseOfDll):
        """
        Private method to remove a module object from the snapshot.

        :param int lpBaseOfDll: Module base address.
        """
        try:
            aModule = self.__moduleDict[lpBaseOfDll]
            del self.__moduleDict[lpBaseOfDll]
        except KeyError:
            aModule = None
            msg = "Unknown base address %d" % HexDump.address(lpBaseOfDll)
            warnings.warn(msg, RuntimeWarning)
        if aModule:
            aModule.clear()     # remove circular references

    def __add_loaded_module(self, event):
        """
        Private method to automatically add new module objects from debug events.

        :param event: Event object.
        :type  event: :class:`~winappdbg.event.Event`
        """
        lpBaseOfDll = event.get_module_base()
        hFile       = event.get_file_handle()
##        if not self.has_module(lpBaseOfDll):  # XXX this would trigger a scan
        if lpBaseOfDll not in self.__moduleDict:
            fileName = event.get_filename()
            if not fileName:
                fileName = None
            if hasattr(event, 'get_start_address'):
                EntryPoint = event.get_start_address()
            else:
                EntryPoint = None
            aModule  = Module(lpBaseOfDll, hFile, fileName = fileName,
                                                EntryPoint = EntryPoint,
                                                   process = self)
            self._add_module(aModule)
        else:
            aModule = self.get_module(lpBaseOfDll)
            if not aModule.hFile and hFile not in (None, 0,
                                                   win32.INVALID_HANDLE_VALUE):
                aModule.hFile = hFile
            if not aModule.process:
                aModule.process = self
            if aModule.EntryPoint is None and \
                                           hasattr(event, 'get_start_address'):
                aModule.EntryPoint = event.get_start_address()
            if not aModule.fileName:
                fileName = event.get_filename()
                if fileName:
                    aModule.fileName = fileName

    def _notify_create_process(self, event):
        """
        Notify the load of the main module.

        This is done automatically by the :class:`~winappdbg.debug.Debug` class, you shouldn't need
        to call it yourself.

        :param event: Create process event.
        :type  event: :class:`~winappdbg.event.CreateProcessEvent`
        :returns: ``True`` to call the user-defined handle, ``False`` otherwise.
        :rtype:  bool
        """
        self.__add_loaded_module(event)
        return True

    def _notify_load_dll(self, event):
        """
        Notify the load of a new module.

        This is done automatically by the :class:`~winappdbg.debug.Debug` class, you shouldn't need
        to call it yourself.

        :param event: Load DLL event.
        :type  event: :class:`~winappdbg.event.LoadDLLEvent`
        :returns: ``True`` to call the user-defined handle, ``False`` otherwise.
        :rtype:  bool
        """
        self.__add_loaded_module(event)
        return True

    def _notify_unload_dll(self, event):
        """
        Notify the release of a loaded module.

        This is done automatically by the :class:`~winappdbg.debug.Debug` class, you shouldn't need
        to call it yourself.

        :param event: Unload DLL event.
        :type  event: :class:`~winappdbg.event.UnloadDLLEvent`
        :returns: ``True`` to call the user-defined handle, ``False`` otherwise.
        :rtype:  bool
        """
        lpBaseOfDll = event.get_module_base()
##        if self.has_module(lpBaseOfDll):  # XXX this would trigger a scan
        if lpBaseOfDll in self.__moduleDict:
            self._del_module(lpBaseOfDll)
        return True
