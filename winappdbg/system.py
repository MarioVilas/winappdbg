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
Instrumentation module.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/Instrumentation}

@group Instrumentation:
    System, Process, Thread, Module
@group Capabilities (private):
    ModuleContainer, ThreadContainer, ProcessContainer, SymbolContainer,
    ThreadDebugOperations, ProcessDebugOperations,
    MemoryOperations, MemoryAddresses, SymbolOperations, PathOperations,
    SymbolEnumerator
"""

# this module can be imported directly
# to manipulate processes and threads
# without the need for the debugger

# FIXME
# I've been told the host process for the latest versions of VMWare
# can't be instrumented, because they try to stop code injection into the VMs.
# The solution appears to be to run the debugger from a user account that
# belongs to the VMware group. I haven't yet confirmed this.

__revision__ = "$Id$"

__all__ =   [
                # Instrumentation classes.
                'System',
                'Process',
                'Thread',
                'Module',

                # Static functions
                'MemoryAddresses',
                'PathOperations',
            ]

import win32
from textio import HexInput, HexDump

import re
import os
import sys
import ctypes
import struct

try:
    from distorm import Decode
except ImportError:
    def Decode(*argv, **argd):
        "PLEASE INSTALL DISTORM BEFORE GENERATING THE DOCUMENTATION"
        msg = ("diStorm is not installed or can't be found. "
        "Download it from: http://www.ragestorm.net/distorm/")
        raise NotImplementedError, msg

#==============================================================================

class PathOperations (object):
    """
    Static methods for filename and pathname manipulation.
    """

    @staticmethod
    def pathname_to_filename(pathname):
        """
        @type  pathname: str
        @param pathname: Absolute path.

        @rtype:  str
        @return: Relative path.
        """
        return win32.PathFindFileName(pathname)

    @staticmethod
    def filename_to_pathname(filename):
        """
        @type  filename: str
        @param filename: Relative path.

        @rtype:  str
        @return: Absolute path.
        """
        return win32.GetFullPathName(filename)

    @staticmethod
    def path_is_relative(path):
        """
        @see: L{path_is_absolute}

        @type  path: str
        @param path: Absolute or relative path.

        @rtype:  bool
        @return: C{True} if the path is relative, C{False} if it's absolute.
        """
        return win32.PathIsRelative(path)

    @staticmethod
    def path_is_absolute(path):
        """
        @see: L{path_is_relative}

        @type  path: str
        @param path: Absolute or relative path.

        @rtype:  bool
        @return: C{True} if the path is absolute, C{False} if it's relative.
        """
        return not win32.PathIsRelative(path)

    @staticmethod
    def split_extension(pathname):
        """
        @type  pathname: str
        @param pathname: Absolute path.

        @rtype:  tuple( str, str )
        @return:
            Tuple containing the file and extension components of the filename.
        """
        filepart = win32.PathRemoveExtension(pathname)
        extpart  = win32.PathFindExtension(pathname)
        return (filepart, extpart)

    @staticmethod
    def split_filename(pathname):
        """
        @type  pathname: str
        @param pathname: Absolute path.

        @rtype:  tuple( str, str )
        @return: Tuple containing the path to the file and the base filename.
        """
        filepart = win32.PathFindFileName(pathname)
        pathpart = win32.PathRemoveFileSpec(pathname)
        return (pathpart, filepart)

    @staticmethod
    def split_path(path):
        """
        @see: L{join_path}

        @type  path: str
        @param path: Absolute or relative path.

        @rtype:  list( str... )
        @return: List of path components.
        """
        components = list()
        while path:
            next = win32.PathFindNextComponent(path)
            if next:
                prev = path[ : -len(next) ]
                components.append(prev)
            path = next
        return components

    @staticmethod
    def join_path(*components):
        """
        @see: L{split_path}

        @type  components: tuple( str... )
        @param components: Path components.

        @rtype:  str
        @return: Absolute or relative path.
        """
        if components:
            path = components[0]
            for next in components[1:]:
                path = win32.PathAppend(path, next)
        else:
            path = ""
        return path

    @staticmethod
    def native_to_win32_pathname(name):
        """
        @type  name: str
        @param name: Native (NT) absolute pathname.

        @rtype:  str
        @return: Win32 absolute pathname.
        """
        if name.startswith("\\"):
            if name.startswith("\\??\\"):
                name = name[ 4: ]
            else:
                for drive_number in xrange(ord('A'), ord('Z') + 1):
                    drive_letter = '%c:' % drive_number
                    try:
                        device_native_path = win32.QueryDosDevice(drive_letter)
                    except WindowsError, e:
                        if e.winerror in (win32.ERROR_FILE_NOT_FOUND, \
                                          win32.ERROR_PATH_NOT_FOUND):
                            continue
                        raise
                    if not device_native_path.endswith('\\'):
                        device_native_path += '\\'
                    if name.startswith(device_native_path):
                        name = drive_letter + '\\' + \
                                              name[ len(device_native_path) : ]
                        break
        return name

#==============================================================================

class ModuleContainer (object):
    """
    Encapsulates the capability to contain Module objects.

    @group Modules snapshot:
        scan_modules,
        get_module, get_module_bases, get_module_count,
        get_module_at_address, get_module_by_name,
        has_module, iter_modules, iter_module_addresses,
        clear_modules

    @group Event notifications (private):
        notify_load_dll,
        notify_unload_dll
    """

    def __init__(self):
        super(ModuleContainer, self).__init__()
        self.__moduleDict = dict()

    def __contains__(self, anObject):
        """
        @type  anObject: L{Module}, int
        @param anObject:
            - C{Module}: Module object to look for.
            - C{int}: Base address of the DLL to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains
            a L{Module} object with the same base address.
        """
        if isinstance(anObject, Module):
            anObject = anObject.lpBaseOfDll
        return self.has_module(anObject)

    def __iter__(self):
        """
        @see:    L{iter_modules}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Module} objects in this snapshot.
        """
        return self.iter_modules()

    def __len__(self):
        """
        @see:    L{get_module_count}
        @rtype:  int
        @return: Count of L{Module} objects in this snapshot.
        """
        return self.get_module_count()

    def has_module(self, lpBaseOfDll):
        """
        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Base address of the DLL to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Module} object with the given base address.
        """
        return lpBaseOfDll in self.__moduleDict

    def get_module(self, lpBaseOfDll):
        """
        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Base address of the DLL to look for.

        @rtype:  L{Module}
        @return: Module object with the given base address.
        """
        if lpBaseOfDll not in self.__moduleDict:
            msg = "Unknown DLL base address %s"
            msg = msg % HexDump.address(lpBaseOfDll)
            raise KeyError, msg
        return self.__moduleDict[lpBaseOfDll]

    def iter_module_addresses(self):
        """
        @see:    L{iter_modules}
        @rtype:  dictionary-keyiterator
        @return: Iterator of DLL base addresses in this snapshot.
        """
        return self.__moduleDict.iterkeys()

    def iter_modules(self):
        """
        @see:    L{iter_module_addresses}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Module} objects in this snapshot.
        """
        return self.__moduleDict.itervalues()

    def get_module_bases(self):
        """
        @see:    L{iter_module_addresses}
        @rtype:  list( int... )
        @return: List of DLL base addresses in this snapshot.
        """
        return self.__moduleDict.keys()

    def get_module_count(self):
        """
        @rtype:  int
        @return: Count of L{Module} objects in this snapshot.
        """
        return len(self.__moduleDict)

#------------------------------------------------------------------------------

    def get_module_by_name(self, modName):
        """
        @type  modName: int
        @param modName:
            Name of the module to look for, as returned by L{Module.get_name}.
            If two or more modules with the same name are loaded, only one
            of the matching modules is returned.

            You can also pass a full pathname to the DLL file.
            This works correctly even if two modules with the same name
            are loaded from different paths.

        @rtype:  L{Module}
        @return: C{Module} object that best matches the given name.
            Returns C{None} if no C{Module} can be found.
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
        if filepart and extpart and extpart.lower() == ".dll":
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
        @type  address: int
        @param address: Memory address to query.

        @rtype:  L{Module}
        @return: C{Module} object that best matches the given address.
            Returns C{None} if no C{Module} can be found.
        """
        bases = self.get_module_bases()
        bases.sort()
        bases.append(0x100000000)   # invalid, > 4 gb. address space
        if address >= bases[0]:
            for i in xrange(len(bases)-1):  # -1 because last base is fake
                begin, end = bases[i:i+2]
                if begin <= address <= end:
                    module = self.get_module(begin)
                    here   = module.is_address_here(address)
                    if here is False:
                        break
                    else:   # True or None
                        return module
        return None

    def scan_modules(self):
        """
        Populates the snapshot with loaded modules.
        """
        # It would seem easier to clear the snapshot first.
        # But then all open handles would be closed.
        found_bases = set()
        hSnapshot   = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPMODULE, \
                                                                self.get_pid())
        try:
            me = win32.Module32First(hSnapshot)
            while me is not None:
                lpBaseAddress = me.modBaseAddr
                fileName      = me.szExePath
                if not fileName:
                    fileName  = me.szModule
                    if not fileName:
                        fileName = None
                found_bases.add(lpBaseAddress)
                if not self.has_module(lpBaseAddress):
                    aModule = Module(lpBaseAddress, fileName = fileName,
                                           SizeOfImage = me.modBaseSize,
                                           process = self)
                    self.__add_module(aModule)
                else:
                    aModule = self.get_module(lpBaseAddress)
                    if not aModule.fileName:
                        aModule.fileName    = fileName
                    if not aModule.SizeOfImage:
                        aModule.SizeOfImage = me.modBaseSize
                    if not aModule.process:
                        aModule.process     = self
                me = win32.Module32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        for base in self.get_module_bases():
            if base not in found_bases:
                self.__del_module(base)

    def clear_modules(self):
        """
        Clears the modules snapshot.
        """
        self.__moduleDict = dict()

#------------------------------------------------------------------------------

    def __add_module(self, aModule):
##        if not isinstance(aModule, Module):
##            if hasattr(aModule, '__class__'):
##                typename = aModule.__class__.__name__
##            else:
##                typename = str(type(aModule))
##            msg = "Expected Module, got %s instead" % typename
##            raise TypeError, msg
        lpBaseOfDll = aModule.get_base()
##        if lpBaseOfDll in self.__moduleDict:
##            msg = "Module already exists: %d" % lpBaseOfDll
##            raise KeyError, msg
        self.__moduleDict[lpBaseOfDll] = aModule

    def __del_module(self, lpBaseOfDll):
##        if lpBaseOfDll not in self.__moduleDict:
##            msg = "Unknown base address %d" % lpBaseOfDll
##            raise KeyError, msg
        del self.__moduleDict[lpBaseOfDll]

    def __add_loaded_module(self, event):
        lpBaseOfDll = event.get_module_base()
        hFile       = event.get_file_handle()
        if not self.has_module(lpBaseOfDll):
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
            self.__add_module(aModule)
        else:
            aModule = self.get_module(lpBaseOfDll)
            if hFile != win32.INVALID_HANDLE_VALUE:
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

    def notify_create_process(self, event):
        """
        Notify the load of the main module.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.
        """
        self.__add_loaded_module(event)
        return True

    def notify_load_dll(self, event):
        """
        Notify the load of a new module.

        @type  event: L{LoadDLLEvent}
        @param event: Load DLL event.
        """
        self.__add_loaded_module(event)
        return True

    def notify_unload_dll(self, event):
        """
        Notify the release of a loaded module.

        @type  event: L{UnloadDLLEvent}
        @param event: Unload DLL event.
        """
        lpBaseOfDll = event.get_module_base()
        if self.has_module(lpBaseOfDll):
            self.__del_module(lpBaseOfDll)
        return True

#==============================================================================

class ThreadContainer (object):
    """
    Encapsulates the capability to contain Thread objects.

    @group Instrumentation:
        start_thread

    @group Threads snapshot:
        scan_threads,
        get_thread, get_thread_count, get_thread_ids,
        has_thread, iter_threads, iter_thread_ids,
        find_threads_by_name,
        clear_threads, clear_dead_threads, close_thread_handles

    @group Event notifications (private):
        notify_create_process,
        notify_create_thread,
        notify_exit_thread
    """

    def __init__(self):
        super(ThreadContainer, self).__init__()
        self.__threadDict = dict()

    def __contains__(self, anObject):
        """
        @type  anObject: L{Thread}, int
        @param anObject:
             - C{int}: Global ID of the thread to look for.
             - C{Thread}: Thread object to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains
            a L{Thread} object with the same ID.
        """
        if isinstance(anObject, Thread):
            anObject = anObject.dwThreadId
        return self.has_thread(anObject)

    def __iter__(self):
        """
        @see:    L{iter_threads}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Thread} objects in this snapshot.
        """
        return self.iter_threads()

    def __len__(self):
        """
        @see:    L{get_thread_count}
        @rtype:  int
        @return: Count of L{Thread} objects in this snapshot.
        """
        return self.get_thread_count()

    def __add_thread(self, aThread):
##        if not isinstance(aThread, Thread):
##            if hasattr(aThread, '__class__'):
##                typename = aThread.__class__.__name__
##            else:
##                typename = str(type(aThread))
##            msg = "Expected Thread, got %s instead" % typename
##            raise TypeError, msg
        dwThreadId = aThread.dwThreadId
##        if dwThreadId in self.__threadDict:
##            msg = "Already have a Thread object with ID %d" % dwThreadId
##            raise KeyError, msg
        aThread.dwProcessId = self.get_pid()
        self.__threadDict[dwThreadId] = aThread

    def __del_thread(self, dwThreadId):
##        if dwThreadId not in self.__threadDict:
##            msg = "Unknown thread ID: %d" % dwThreadId
##            raise KeyError, msg
        del self.__threadDict[dwThreadId]

    def has_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Thread} object with the given global ID.
        """
        return dwThreadId in self.__threadDict

    def get_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.

        @rtype:  L{Thread}
        @return: Thread object with the given global ID.
        """
        if dwThreadId not in self.__threadDict:
            msg = "Unknown thread ID: %d" % dwThreadId
            raise KeyError, msg
        return self.__threadDict[dwThreadId]

    def iter_thread_ids(self):
        """
        @see:    L{iter_threads}
        @rtype:  dictionary-keyiterator
        @return: Iterator of global thread IDs in this snapshot.
        """
        return self.__threadDict.iterkeys()

    def iter_threads(self):
        """
        @see:    L{iter_thread_ids}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Thread} objects in this snapshot.
        """
        return self.__threadDict.itervalues()

    def get_thread_ids(self):
        """
        @rtype:  list( int )
        @return: List of global thread IDs in this snapshot.
        """
        return self.__threadDict.keys()

    def get_thread_count(self):
        """
        @rtype:  int
        @return: Count of L{Thread} objects in this snapshot.
        """
        return len(self.__threadDict)

#------------------------------------------------------------------------------

    def find_threads_by_name(self, name, bExactMatch = True):
        """
        Find threads by name, using different search methods.

        @type  name: str, None
        @param name: Name to look for. Use C{None} to find nameless threads.

        @type  bExactMatch: bool
        @param bExactMatch: C{True} if the name must be
            B{exactly} as given, C{False} if the name can be
            loosely matched.

            This parameter is ignored when C{name} is C{None}.

        @rtype:  list( L{Thread} )
        @return: All threads matching the given name.
        """
        found_threads = list()

        # Find threads with no name.
        if name is None:
            for aThread in self.iter_threads():
                if aThread.get_name() is None:
                    found_threads.append(aThread)

        # Find threads matching the given name exactly.
        elif bExactMatch:
            for aThread in self.iter_threads():
                if aThread.get_name() == name:
                    found_threads.append(aThread)

        # Find threads whose names match the given substring.
        else:
            for aThread in self.iter_threads():
                t_name = aThread.get_name()
                if t_name is not None and name in t_name:
                    found_threads.append(aThread)

        return found_threads

#------------------------------------------------------------------------------

    def start_thread(self, lpStartAddress, lpParameter=0,  bSuspended = False):
        """
        Remotely creates a new thread in the process.

        @type  lpStartAddress: int
        @param lpStartAddress: Start address for the new thread.

        @type  lpParameter: int
        @param lpParameter: Optional argument for the new thread.

        @type  bSuspended: bool
        @param bSuspended: C{True} if the new thread should be suspended.
            In that case use L{Thread.resume} to start execution.
        """
        if bSuspended:
            dwCreationFlags = win32.CREATE_SUSPENDED
        else:
            dwCreationFlags = 0
        hThread, dwThreadId = win32.CreateRemoteThread(self.get_handle(), 0, 0,
                                lpStartAddress, lpParameter, dwCreationFlags)
        aThread = Thread(dwThreadId, hThread, self)
        self.__add_thread(aThread)
        return aThread

#------------------------------------------------------------------------------

    # TODO
    # maybe put all the toolhelp code into their own set of classes?
    def scan_threads(self):
        """
        Populates the snapshot with running threads.
        """
        dead_tids   = set( self.get_thread_ids() )
        dwProcessId = self.get_pid()
        hSnapshot   = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPTHREAD,
                                                                 dwProcessId)
        try:
            te = win32.Thread32First(hSnapshot)
            while te is not None:
                if te.th32OwnerProcessID == dwProcessId:
                    dwThreadId = te.th32ThreadID
                    if dwThreadId in dead_tids:
                        dead_tids.remove(dwThreadId)
                    if not self.has_thread(dwThreadId):
                        aThread = Thread(dwThreadId, process = self)
                        self.__add_thread(aThread)
                te = win32.Thread32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        for tid in dead_tids:
            self.__del_thread(tid)

    def clear_dead_threads(self):
        """
        Remove Thread objects from the snapshot
        referring to threads no longer running.
        """
        for tid in self.get_thread_ids():
            aThread = self.get_thread(tid)
            if not aThread.is_alive():
                self.__del_thread(aThread)

    def clear_threads(self):
        """
        Clears the threads snapshot.
        """
        self.__threadDict = dict()

    def close_thread_handles(self):
        """
        Closes all open handles to threads in the snapshot.
        """
        for aThread in self.iter_threads():
            try:
                aThread.close_handle()
            except Exception, e:
                pass

#------------------------------------------------------------------------------

    def __add_created_thread(self, event):
        dwThreadId  = event.get_tid()
        hThread     = event.get_thread_handle()
        if self.has_thread(dwThreadId):
            aThread = self.get_thread(dwThreadId)
            if hThread != win32.INVALID_HANDLE_VALUE:
                aThread.hThread = hThread   # may have more privileges
        else:
            aThread = Thread(dwThreadId, hThread, self)
            self.__add_thread(aThread)

    def notify_create_process(self, event):
        """
        Notify the creation of the main thread of this process.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.
        """
        self.__add_created_thread(event)
        return True

    def notify_create_thread(self, event):
        """
        Notify the creation of a new thread in this process.

        @type  event: L{CreateThreadEvent}
        @param event: Create thread event.
        """
        self.__add_created_thread(event)
        return True

    def notify_exit_thread(self, event):
        """
        Notify the termination of a thread.

        @type  event: L{ExitThreadEvent}
        @param event: Exit thread event.
        """
        dwThreadId = event.get_tid()
        if self.has_thread(dwThreadId):
            self.__del_thread(dwThreadId)
        return True

#==============================================================================

class MemoryAddresses (object):
    """
    Class to manipulate memory addresses.
    """

    @staticmethod
    def align_address_to_page_start(address):
        """
        Align the given address to the start of the page it occupies.

        @type  address: int
        @param address: Memory address.

        @rtype:  int
        @return: Aligned memory address.
        """
        return address - ( address % System.pageSize )

    @staticmethod
    def align_address_to_page_end(address):
        """
        Align the given address to the end of the page it occupies.

        @type  address: int
        @param address: Memory address.

        @rtype:  int
        @return: Aligned memory address.
        """
        return address + System.pageSize - ( address % System.pageSize )

    @classmethod
    def align_address_range(cls, begin, end):
        """
        Align the given address range to the start and end of the page(s) it occupies.

        @type  begin: int
        @param begin: Memory address of the beginning of the buffer.

        @type  end: int
        @param end: Memory address of the end of the buffer.

        @rtype:  tuple( int, int )
        @return: Aligned memory addresses.
        """
        if end > begin:
            begin, end = end, begin
        return (
            cls.align_address_to_page_start(begin),
            cls.align_address_to_page_end(end)
            )

    @classmethod
    def get_buffer_size_in_pages(cls, address, size):
        """
        Get the number of pages in use by the given buffer.

        @type  address: int
        @param address: Aligned memory address.

        @type  size: int
        @param size: Buffer size.

        @rtype:  int
        @return: Buffer size in number of pages.
        """
        if size < 0:
            size    = -size
            address = address - size
        begin, end = cls.align_address_range(address, address + size)
        return int(float(end - begin) / float(System.pageSize))

    @staticmethod
    def do_ranges_intersect(begin, end, old_begin, old_end):
        return  (old_begin <= begin < old_end) or \
                (old_begin < end <= old_end)   or \
                (begin <= old_begin < end)     or \
                (begin < old_end <= end)

#==============================================================================

# TODO
# * This methods do not take into account that code breakpoints change the
#   memory. This object should talk to BreakpointContainer to retrieve the
#   original memory contents where code breakpoints are enabled.
# * A memory cache could be implemented here.
class MemoryOperations (object):
    """
    Encapsulates the capabilities to manipulate the memory of a process.

    @group Memory mapping:
        get_memory_map, malloc, free, mprotect, mquery,
        is_address_valid, is_address_free, is_address_reserved,
        is_address_commited, is_address_readable, is_address_writeable,
        is_address_executable, is_address_executable_and_writeable

    @group Memory read:
        read, read_char, read_uint, read_structure,
        peek, peek_char, peek_uint, peek_string

    @group Memory write:
        write, write_char, write_uint,
        poke, poke_char, poke_uint
    """

    # FIXME
    # * under Wine reading from an unmapped address returns nulls
    #   this is wrong, the call to ReadProcessMemory should fail instead
    # * under ReactOS it doesn't seem to work at all (more testing needed)
    def read(self, lpBaseAddress, nSize):
        """
        Reads from the memory of the process.

        @see: L{peek}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @type  nSize: int
        @param nSize: Number of bytes to read.

        @rtype:  str
        @return: Bytes read from the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        data = win32.ReadProcessMemory(self.get_handle(), lpBaseAddress, nSize)
        if len(data) != nSize:
            raise ctypes.WinError()
        return data

    # FIXME
    # * under ReactOS it doesn't seem to work at all (more testing needed)
    def write(self, lpBaseAddress, lpBuffer):
        """
        Writes to the memory of the process.

        @see: L{poke}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  lpBuffer: int
        @param lpBuffer: Bytes to write.

        @raise WindowsError: On error an exception is raised.
        """
        r = win32.WriteProcessMemory(self.get_handle(), lpBaseAddress, lpBuffer)
        if r != len(lpBuffer):
            raise ctypes.WinError()

    def read_uint(self, lpBaseAddress):
        """
        Reads a single uint from the memory of the process.

        @see: L{peek}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Integer value read from the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        packedDword     = self.read(lpBaseAddress, 4)
        if len(packedDword) != 4:
            raise ctypes.WinError()
        unpackedDword   = struct.unpack('<L', packedDword)[0]
        return unpackedDword

    def write_uint(self, lpBaseAddress, unpackedDword):
        """
        Writes a single uint to the memory of the process.

        @see: L{poke_uint}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  unpackedDword: int, long
        @param unpackedDword: Value to write.

        @raise WindowsError: On error an exception is raised.
        """
        packedDword = struct.pack('<L', unpackedDword)
        self.write(lpBaseAddress, packedDword)

    def read_char(self, lpBaseAddress):
        """
        Reads a single character to the memory of the process.

        @see: L{write_char}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @rtype:  int
        @return: Character value read from the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        return ord( self.read(lpBaseAddress, 1) )

    def write_char(self, lpBaseAddress, char):
        """
        Writes a single character to the memory of the process.

        @see: L{write_char}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  char: int
        @param char: Character to write.

        @raise WindowsError: On error an exception is raised.
        """
        self.write(lpBaseAddress, chr(char))

    def read_structure(self, lpBaseAddress, stype):
        """
        Reads a ctypes structure from the memory of the process.

        @see: L{read}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @type  stype: class ctypes.Structure or a subclass.
        @param stype: Structure definition.

        @rtype:  int
        @return: Structure instance filled in with data
            read from the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        if type(lpBaseAddress) not in (type(0), type(0L)):
            lpBaseAddress = ctypes.cast(lpBaseAddress, ctypes.c_void_p)
        data = self.read(lpBaseAddress, ctypes.sizeof(stype))
        buff = ctypes.create_string_buffer(data)
        ptr  = ctypes.cast(ctypes.pointer(buff), ctypes.POINTER(stype))
        return ptr.contents

# TODO
##    def write_structure(self, lpBaseAddress, sStructure):
##        """
##        Writes a ctypes structure into the memory of the process.
##
##        @see: L{write}
##
##        @type  lpBaseAddress: int
##        @param lpBaseAddress: Memory address to begin writing.
##
##        @type  sStructure: ctypes.Structure or a subclass' instance.
##        @param sStructure: Structure definition.
##
##        @rtype:  int
##        @return: Structure instance filled in with data
##            read from the process memory.
##
##        @raise WindowsError: On error an exception is raised.
##        """
##        size = ctypes.sizeof(sStructure)
##        data = ctypes.create_string_buffer("", size = size)
##        win32.CopyMemory(ctypes.byref(data), ctypes.byref(sStructure), size)
##        self.write(lpBaseAddress, data.raw)

    def read_string(self, lpBaseAddress, nChars, fUnicode = False):
        """
        Reads an ASCII or Unicode string
        from the address space of the process.

        @see: L{read}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @type  nChars: int
        @param nChars: String length to read, in characters.
            Remember that Unicode strings have two byte characters.

        @type  fUnicode: bool
        @param fUnicode: C{True} is the string is expected to be Unicode,
            C{False} if it's expected to be ANSI.

        @rtype:  str, unicode
        @return: String read from the process memory space.

        @raise WindowsError: On error an exception is raised.
        """
        if fUnicode:
            nChars = nChars * 2
        szString = self.read(lpBaseAddress, nChars)
        if fUnicode:
            szString = unicode(szString, 'U16', 'ignore')
        return szString

#------------------------------------------------------------------------------

    def peek(self, lpBaseAddress, nSize):
        """
        Reads the memory of the process.

        @see: L{read}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @type  nSize: int
        @param nSize: Number of bytes to read.

        @rtype:  str
        @return: Bytes read from the process memory.
            Returns an empty string on error.
        """
        data = ''
        if nSize > 0:
            try:
                data = win32.ReadProcessMemory(self.get_handle(),
                                                          lpBaseAddress, nSize)
            except WindowsError:
                pass
        return data

    def poke(self, lpBaseAddress, lpBuffer):
        """
        Writes to the memory of the process.

        @see: L{write}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  lpBuffer: str
        @param lpBuffer: Bytes to write.

        @rtype:  int
        @return: Number of bytes written.
            May be less than the number of bytes to write.
        """
        try:
            bytesWritten = win32.WriteProcessMemory(self.get_handle(),
                                                       lpBaseAddress, lpBuffer)
        except WindowsError:
            bytesWritten = 0
        return bytesWritten

    def peek_uint(self, lpBaseAddress):
        """
        Reads a single uint from the memory of the process.

        @see: L{read_uint}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Integer value read from the process memory.
            Returns zero on error.
        """
        packedDword = self.peek(lpBaseAddress, 4)
        if len(packedDword) < 4:
            packedDword += '\x00' * (4 - len(packedDword))
        unpackedDword = struct.unpack('<L', packedDword)[0]
        return unpackedDword

    def poke_uint(self, lpBaseAddress, unpackedDword):
        """
        Writes a single uint to the memory of the process.

        @see: L{write_uint}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  unpackedDword: int, long
        @param unpackedDword: Value to write.

        @rtype:  int
        @return: Number of bytes written.
            May be less than the number of bytes to write.
        """
        packedDword     = struct.pack('<L', unpackedDword)
        dwBytesWritten  = self.poke(lpBaseAddress, packedDword)
        return dwBytesWritten

    def peek_char(self, lpBaseAddress):
        """
        Reads a single character from the memory of the process.

        @see: L{read_char}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Character read from the process memory.
            Returns zero on error.
        """
        char = self.peek(lpBaseAddress, 1)
        if char:
            return ord(char)
        return 0

    def poke_char(self, lpBaseAddress, char):
        """
        Writes a single character to the memory of the process.

        @see: L{write_char}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  char: str
        @param char: Character to write.

        @rtype:  int
        @return: Number of bytes written.
            May be less than the number of bytes to write.
        """
        return self.poke(lpBaseAddress, chr(char))

    def peek_string(self, lpBaseAddress, fUnicode = False, dwMaxSize = 0x1000):
        """
        Tries to read an ASCII or Unicode string
        from the address space of the process.

        @see: L{peek}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @type  fUnicode: bool
        @param fUnicode: C{True} is the string is expected to be Unicode,
            C{False} if it's expected to be ANSI.

        @type  dwMaxSize: int
        @param dwMaxSize: Maximum allowed string length to read, in bytes.

        @rtype:  str, unicode
        @return: String read from the process memory space.
            It doesn't include the terminating null character.
            Returns an empty string on failure.
        """
        szString = self.peek(lpBaseAddress, dwMaxSize)
        if fUnicode:
            szString = unicode(szString, 'U16', 'ignore')
            szString = ctypes.create_unicode_buffer(szString).value
        else:
            szString = ctypes.create_string_buffer(szString).value
        return szString

#------------------------------------------------------------------------------

    def malloc(self, dwSize, lpAddress = win32.NULL):
        """
        Allocates memory into the address space of the process.

        @see: L{free}

        @type  dwSize: int
        @param dwSize: Number of bytes to allocate.

        @type  lpAddress: int
        @param lpAddress: (Optional)
            Desired address for the newly allocated memory.
            This is only a hint, the memory could still be allocated somewhere
            else.

        @rtype:  int
        @return: Address of the newly allocated memory.

        @raise WindowsError: On error an exception is raised.
        """
        return win32.VirtualAllocEx(self.get_handle(), lpAddress, dwSize)

    def mprotect(self, lpAddress, dwSize, flNewProtect):
        """
        Set memory protection in the address space of the process.

        @see: U{http://msdn.microsoft.com/en-us/library/aa366899.aspx}

        @type  lpAddress: int
        @param lpAddress: Address of memory to protect.

        @type  dwSize: int
        @param dwSize: Number of bytes to protect.

        @type  flNewProtect: int
        @param flNewProtect: New protect flags.

        @rtype:  int
        @return: Old protect flags.

        @raise WindowsError: On error an exception is raised.
        """
        return win32.VirtualProtectEx(self.get_handle(), lpAddress, dwSize,
                                                                  flNewProtect)

    def mquery(self, lpAddress):
        """
        Query memory information from the address space of the process.
        Returns a L{MEMORY_BASIC_INFORMATION} structure.

        @see: U{http://msdn.microsoft.com/en-us/library/aa366907(VS.85).aspx}

        @type  lpAddress: int
        @param lpAddress: Address of memory to query.

        @rtype:  L{MEMORY_BASIC_INFORMATION}
        @return: Memory region information.

        @raise WindowsError: On error an exception is raised.
        """
        return win32.VirtualQueryEx(self.get_handle(), lpAddress)

    def free(self, lpAddress, dwSize = 0):
        """
        Frees memory from the address space of the process.

        @see: L{malloc}

        @type  lpAddress: int
        @param lpAddress: Address of memory to free.

        @type  dwSize: int
        @param dwSize: (Optional) Number of bytes to free.

        @rtype:  bool
        @return: C{True} on success, C{False} on error.
        """
        success = win32.VirtualFreeEx(self.get_handle(), lpAddress, dwSize)
        return bool(success)

#------------------------------------------------------------------------------

    def is_address_valid(self, address):
        """
        Determines if an address is a valid user mode address.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address is a valid user mode address.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return True

    def is_address_free(self, address):
        """
        Determines if an address belongs to a free page.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address belongs to a free page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.State == win32.MEM_FREE

    def is_address_reserved(self, address):
        """
        Determines if an address belongs to a reserved page.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address belongs to a reserved page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.State == win32.MEM_RESERVE

    def is_address_commited(self, address):
        """
        Determines if an address belongs to a commited page.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address belongs to a commited page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.State == win32.MEM_COMMIT

    def is_address_readable(self, address):
        """
        Determines if an address belongs to a commited and readable page.
        The page may or may not have additional permissions.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return:
            C{True} if the address belongs to a commited and readable page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        Protect = mbi.Protect
        return mbi.State == win32.MEM_COMMIT and \
            (
                Protect & win32.PAGE_EXECUTE_READ       or \
                Protect & win32.PAGE_EXECUTE_READWRITE  or \
                Protect & win32.PAGE_EXECUTE_WRITECOPY  or \
                Protect & win32.PAGE_READONLY           or \
                Protect & win32.PAGE_READWRITE          or \
                Protect & win32.PAGE_WRITECOPY
            )

    def is_address_writeable(self, address):
        """
        Determines if an address belongs to a commited and writeable page.
        The page may or may not have additional permissions.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return:
            C{True} if the address belongs to a commited and writeable page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        Protect = mbi.Protect
        return mbi.State == win32.MEM_COMMIT and \
            (
                Protect & win32.PAGE_EXECUTE_READWRITE  or \
                Protect & win32.PAGE_EXECUTE_WRITECOPY  or \
                Protect & win32.PAGE_READWRITE          or \
                Protect & win32.PAGE_WRITECOPY
            )

    def is_address_executable(self, address):
        """
        Determines if an address belongs to a commited and executable page.
        The page may or may not have additional permissions.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return:
            C{True} if the address belongs to a commited and executable page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        Protect = mbi.Protect
        return mbi.State == win32.MEM_COMMIT and \
            (
                Protect & win32.PAGE_EXECUTE            or \
                Protect & win32.PAGE_EXECUTE_READ       or \
                Protect & win32.PAGE_EXECUTE_READWRITE  or \
                Protect & win32.PAGE_EXECUTE_WRITECOPY
            )

    def is_address_executable_and_writeable(self, address):
        """
        Determines if an address belongs to a commited, writeable and
        executable page. The page may or may not have additional permissions.

        Looking for writeable and executable pages is important when
        exploiting a software vulnerability.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return:
            C{True} if the address belongs to a commited, writeable and
            executable page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if e.winerror == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        Protect = mbi.Protect
        return mbi.State == win32.MEM_COMMIT and \
            (
                Protect & win32.PAGE_EXECUTE_READWRITE  or \
                Protect & win32.PAGE_EXECUTE_WRITECOPY
            )

    def get_memory_map(self, minAddr = 0, maxAddr = 0x100000000):
        """
        Produces a memory map to the process address space.
        Optionally restrict the map to the given address range.

        @see: L{mquery}

        @type  minAddr: int
        @param minAddr: (Optional) Starting address in address range to query.

        @type  maxAddr: int
        @param maxAddr: (Optional) Ending address in address range to query.

        @rtype:  list( L{MEMORY_BASIC_INFORMATION} )
        @return: List of MEMORY_BASIC_INFORMATION structures.
        """
        if minAddr > maxAddr:
            minAddr, maxAddr = maxAddr, minAddr
        minAddr     = MemoryAddresses.align_address_to_page_start(minAddr)
        maxAddr     = MemoryAddresses.align_address_to_page_end(maxAddr)
        currentAddr = minAddr
        memoryMap   = list()
        while currentAddr <= maxAddr:
            try:
                mbi = self.mquery(currentAddr)
            except WindowsError, e:
                if e.winerror == win32.ERROR_INVALID_PARAMETER:
                    break
                raise
            memoryMap.append(mbi)
            currentAddr = mbi.BaseAddress + mbi.RegionSize
        return memoryMap

    def get_mapped_filenames(self, memoryMap = None):
        """
        Retrieves the filenames for memory mapped files in the debugee.

        @type  memoryMap: list( L{MEMORY_BASIC_INFORMATION} )
        @param memoryMap: (Optional) Memory map returned by L{get_memory_map}.
            If not given, the current memory map is used.

        @rtype:  dict( int S{->} str )
        @return: Dictionary mapping memory addresses to file names.
            Native filenames are converted to Win32 filenames when possible.
        """
        hProcess = self.get_handle()
        if not memoryMap:
            memoryMap = self.get_memory_map()
        mappedFilenames = dict()
        for mbi in memoryMap:

            # this check is redundant, but it saves an API call
            # just comment it out if it gives problems
            if mbi.Type not in (win32.MEM_IMAGE, win32.MEM_MAPPED):
                continue

            baseAddress = mbi.BaseAddress
            fileName    = ""
            try:
                fileName = win32.GetMappedFileName(hProcess, baseAddress)
                fileName = PathOperations.native_to_win32_pathname(fileName)
            except WindowsError, e:
##                    print str(e)    # XXX DEBUG
                pass
            mappedFilenames[baseAddress] = fileName
        return mappedFilenames

#==============================================================================

class SymbolEnumerator (object):
    """
    Internally used by L{SymbolContainer} to enumerate symbols in a module.
    """

    def __init__(self):
        self.symbols = list()

    def __call__(self, SymbolName, SymbolAddress, SymbolSize, UserContext):
        """
        Callback that receives symbols and stores them in a Python list.
        """
        self.symbols.append( (SymbolName, SymbolAddress, SymbolSize) )
        return win32.TRUE

class SymbolContainer (object):
    """
    Capability to contain symbols. Used by L{Module}.

    @group Symbols:
        load_symbols, unload_symbols, get_symbols, iter_symbols,
        resolve_symbol, get_symbol_at_address
    """

    def __init__(self):
        self.__symbols = list()

    # XXX FIXME
    # I've been told sometimes the debugging symbols APIs don't correctly
    # handle redirected exports (for example ws2_32!recv).
    # I haven't been able to reproduce the bug yet.
    def load_symbols(self):
        """
        Loads the debugging symbols for a module.
        Automatically called by L{get_symbols}.
        """
        hProcess    = self.get_process().get_handle()
        hFile       = self.hFile
        BaseOfDll   = self.get_base()
        SizeOfDll   = self.get_size()
        Enumerator  = SymbolEnumerator()
        try:
            win32.SymInitialize(hProcess)
            try:
                try:
                    win32.SymLoadModule(hProcess, hFile, None, None, BaseOfDll, SizeOfDll)
                except WindowsError:
                    ImageName = self.get_filename()
                    win32.SymLoadModule(hProcess, None, ImageName, None, BaseOfDll, SizeOfDll)
                try:
                    win32.SymEnumerateSymbols(hProcess, BaseOfDll, Enumerator)
                finally:
                    win32.SymUnloadModule(hProcess, BaseOfDll)
            finally:
                win32.SymCleanup(hProcess)
        except WindowsError, e:
##            import traceback        # XXX DEBUG
##            traceback.print_exc()
            pass
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

        @rtype:  list of tuple( str, int, int )
        @return: List of symbols.
            Each symbol is represented by a tuple that contains:
                - Symbol name
                - Symbol memory address
                - Symbol size in bytes
        """
        if not self.__symbols:
            self.load_symbols()
        return list(self.__symbols)

    def iter_symbols(self):
        """
        Returns an iterator for the debugging symbols in a module,
        in no particular order.
        The symbols are automatically loaded when needed.

        @rtype:  iterator of tuple( str, int, int )
        @return: Iterator of symbols.
            Each symbol is represented by a tuple that contains:
                - Symbol name
                - Symbol memory address
                - Symbol size in bytes
        """
        if not self.__symbols:
            self.load_symbols()
        return self.__symbols.__iter__()

    def resolve_symbol(self, symbol, bCaseSensitive = False):
        """
        Resolves a debugging symbol's address.

        @type  symbol: str
        @param symbol: Name of the symbol to resolve.

        @type  bCaseSensitive: bool
        @param bCaseSensitive: C{True} for case sensitive matches,
            C{False} for case insensitive.

        @rtype:  int or None
        @return: Memory address of symbol. C{None} if not found.
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
        found = None
        for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
            if SymbolAddress > address:
                continue
            if SymbolAddress + SymbolSize > address:
                if not found or found[1] < SymbolAddress:
                    found = (SymbolName, SymbolAddress, SymbolSize)
        return found

#==============================================================================

class SymbolOperations (object):
    """
    Encapsulates symbol operations capabilities.

    Requires a L{ModuleContainer}.

    @note: Labels are an approximated way of referencing memory locations
        across different executions of the same process, or different processes
        with common modules. They are not meant to be perfectly unique, and
        some errors may occur when multiple modules with the same name are
        loaded, or when module filenames can't be retrieved.

        Read more on labels here:
        U{http://apps.sourceforge.net/trac/winappdbg/wiki/HowLabelsWork}

    @group Labels:
        parse_label,
        split_label,
        sanitize_label,
        resolve_label,
        get_label_at_address,
        split_label_strict,
        split_label_fuzzy

    @group Symbols:
        load_symbols, unload_symbols, get_symbols, iter_symbols,
        resolve_symbol, get_symbol_at_address

    @group Debugging:
        get_system_breakpoint, get_user_breakpoint, get_breakin_breakpoint,
        is_system_defined_breakpoint
    """

    def __init__(self):
        super(SymbolOperations, self).__init__()

        # Replace split_label with the fuzzy version on object instances.
        self.split_label = self.__use_fuzzy_mode

    @staticmethod
    def parse_label(module = None, function = None, offset = None):
        """
        Creates a label from a module and a function name, plus an offset.

        @warning: This method only parses the label, it doesn't make sure the
            label actually points to a valid memory location.

        @type  module: None or str
        @param module: (Optional) Module name.

        @type  function: None, str or int
        @param function: (Optional) Function name or ordinal.

        @type  offset: None or int
        @param offset: (Optional) Offset value.

            If C{function} is specified, offset from the function.

            If C{function} is C{None}, offset from the module.

        @rtype:  str
        @return:
            Label representing the given function in the given module.

        @raise ValueError:
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
            raise ValueError, "Invalid module name: %s" % module
        if function is not None and ('!' in function or '+' in function):
            raise ValueError, "Invalid function name: %s" % function

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
        Splits a label created with L{parse_label}.

        To parse labels with a less strict syntax, use the L{split_label_fuzzy}
        method instead.

        @warning: This method only parses the label, it doesn't make sure the
            label actually points to a valid memory location.

        @type  label: str
        @param label: Label to split.

        @rtype:  tuple( str or None, str or int or None, int or None )
        @return: Tuple containing the C{module} name,
            the C{function} name or ordinal, and the C{offset} value.

            If the label doesn't specify a module,
            then C{module} is C{None}.

            If the label doesn't specify a function,
            then C{function} is C{None}.

            If the label doesn't specify an offset,
            then C{offset} is C{0}.

        @raise ValueError: The label is malformed.
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
                raise ValueError, "Malformed label: %s" % label

            # module ! function
            if function:
                if '+' in module:
                    raise ValueError, "Malformed label: %s" % label

                # module ! function + offset
                if '+' in function:
                    try:
                        function, offset = function.split('+')
                    except ValueError:
                        raise ValueError, "Malformed label: %s" % label
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError, "Malformed label: %s" % label
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
                        raise ValueError, "Malformed label: %s" % label
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError, "Malformed label: %s" % label

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
                        raise ValueError, "Ambiguous label: %s" % label

                # module?
                # function?
                else:
                    raise ValueError, "Ambiguous label: %s" % label

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

        It's more flexible in it's syntax parsing than the L{split_label_strict}
        method, as it allows the exclamation mark (B{C{!}}) to be omitted. The
        ambiguity is resolved by searching the modules in the snapshot to guess
        if a label refers to a module or a function. It also tries to rebuild
        labels when they contain hardcoded addresses.

        @warning: This method only parses the label, it doesn't make sure the
            label actually points to a valid memory location.

        @type  label: str
        @param label: Label to split.

        @rtype:  tuple( str or None, str or int or None, int or None )
        @return: Tuple containing the C{module} name,
            the C{function} name or ordinal, and the C{offset} value.

            If the label doesn't specify a module,
            then C{module} is C{None}.

            If the label doesn't specify a function,
            then C{function} is C{None}.

            If the label doesn't specify an offset,
            then C{offset} is C{0}.

        @raise ValueError: The label is malformed.
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
                raise ValueError, "Malformed label: %s" % label
            try:
                offset = HexInput.integer(offset)
            except ValueError:
                raise ValueError, "Malformed label: %s" % label
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
Splits a label into it's C{module}, C{function} and C{offset}
components, as used in L{parse_label}.

When called as a static method, the strict syntax mode is used::

    winappdbg.Process.split_label( "kernel32!CreateFileA" )

When called as an instance method, the fuzzy syntax mode is used::

    aProcessInstance.split_label( "CreateFileA" )

@see: L{split_label_strict}, L{split_label_fuzzy}

@type  label: str
@param label: Label to split.

@rtype:  tuple( str or None, str or int or None, int or None )
@return:
    Tuple containing the C{module} name,
    the C{function} name or ordinal, and the C{offset} value.

    If the label doesn't specify a module,
    then C{module} is C{None}.

    If the label doesn't specify a function,
    then C{function} is C{None}.

    If the label doesn't specify an offset,
    then C{offset} is C{0}.

@raise ValueError: The label is malformed.
        """

        # XXX
        # Docstring indentation was removed so epydoc doesn't complain
        # when parsing the docs for __use_fuzzy_mode().

        # This function is overwritten by __init__
        # so here is the static implementation only.
        return cls.split_label_strict(label)

    # The split_label method is replaced with this function by __init__.
    def __use_fuzzy_mode(self, label):
        "@see: L{split_label}"
        return self.split_label_fuzzy(label)
##    __use_fuzzy_mode.__doc__ = split_label.__doc__

    def sanitize_label(self, label):
        """
        Converts a label taken from user input into a well-formed label.

        @type  label: str
        @param label: Label taken from user input.

        @rtype:  str
        @return: Sanitized label.
        """
        (module, function, offset) = self.split_label_fuzzy(label)
        label = self.parse_label(module, function, offset)
        return label

    def resolve_label(self, label):
        """
        Resolve the memory address of the given label.

        @note:
            If multiple modules with the same name are loaded,
            the label may be resolved at any of them. For a more precise
            way to resolve functions use the base address to get the L{Module}
            object (see L{Process.get_module}) and then call L{Module.resolve}.

            If no module name is specified in the label, the function may be
            resolved in any loaded module. If you want to resolve all functions
            with that name in all processes, call L{Process.iter_modules} to
            iterate through all loaded modules, and then try to resolve the
            function in each one of them using L{Module.resolve}.

        @type  label: str
        @param label: Label to resolve.

        @rtype:  int
        @return: Memory address pointed to by the label.

        @raise ValueError: The label is malformed or impossible to resolve.
        @raise RuntimeError: Cannot resolve the module or function.
        """
        # Default address if no module or function are given.
        # An offset may be added later.
        address = 0

        # Split the label into module, function and offset components.
        module, function, offset = self.split_label_fuzzy(label)

        # Resolve the module.
        if module:
            modobj = self.get_module_by_name(module)
            if not modobj:
                msg = "Module %r not found" % module
                raise RuntimeError, msg

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
                            msg = msg % (function, module)
                            raise RuntimeError, msg

            # No function, use the base address.
            else:
                address = modobj.get_base()

        # Resolve the function in any module.
        elif function:
            for modobj in self.iter_modules():
                address = modobj.resolve(function)
                if address is not None:
                    break
            if address is None:
                msg = "Function %r not found in any module" % function
                raise RuntimeError, msg

        # Return the address plus the offset.
        if offset:
            address = address + offset
        return address

    def get_label_at_address(self, address, offset = None):
        """
        Creates a label from the given memory address.

        @warning: This method uses the name of the nearest currently loaded
            module. If that module is unloaded later, the label becomes
            impossible to resolve.

        @type  address: int
        @param address: Memory address.

        @type  offset: None or int
        @param offset: (Optional) Offset value.

        @rtype:  str
        @return: Label pointing to the given address.
        """
        if offset:
            address = address + offset
        modobj = self.get_module_at_address(address)
        if modobj:
            label = modobj.get_label_at_address(address)
        else:
            label = self.parse_label(None, None, address)
        return label

    def is_system_defined_breakpoint(self, address):
        """
        @type  address: int
        @param address: Memory address.

        @rtype:  bool
        @return: C{True} if the given address points to a system defined
            breakpoint. System defined breakpoints are hardcoded into
            system libraries.
        """
        return (
            address == self.get_system_breakpoint() or \
            address == self.get_user_breakpoint()   or \
            address == self.get_breakin_breakpoint()
        )

    # FIXME
    # In Wine, the system breakpoint seems to be somewhere in kernel32.
    # In Windows 2000 I've been told it's in ntdll!NtDebugBreak (not sure yet).
    def get_system_breakpoint(self):
        """
        @rtype:  int
        @return: Memory address of the system breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        return self.resolve_label("ntdll!DbgBreakPoint")

    # I don't know when this breakpoint is actually used...
    def get_user_breakpoint(self):
        """
        @rtype:  int
        @return: Memory address of the user breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        return self.resolve_label("ntdll!DbgUserBreakPoint")

    # This breakpoint can only be resolved when the
    # debugging symbols for ntdll.dll are loaded.
    def get_breakin_breakpoint(self):
        """
        @rtype:  int
        @return: Memory address of the remote breakin breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        return self.resolve_label("ntdll!DbgUiRemoteBreakin")

    def load_symbols(self):
        for aModule in self.iter_modules():
            aModule.load_symbols()

    def unload_symbols(self):
        for aModule in self.iter_modules():
            aModule.unload_symbols()

    def get_symbols(self):
        symbols = list()
        for aModule in self.iter_modules():
            for symbol in aModule.iter_symbols():
                symbols.append(symbol)
        return symbols

    def iter_symbols(self):
        for aModule in self.iter_modules():
            for symbol in aModule.iter_symbols():
                yield symbol

    def resolve_symbol(self, symbol):
        symbol = symbol.lower()
        for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
            if symbol == SymbolName.lower():
                return SymbolAddress

    def get_symbol_at_address(self, address):
        found = None
        for (SymbolName, SymbolAddress, SymbolSize) in self.iter_symbols():
            if SymbolAddress <= address:
                if SymbolAddress + SymbolSize > address:
                    if not found or found[1] < SymbolAddress:
                        found = (SymbolName, SymbolAddress, SymbolSize)
        return found

#==============================================================================

# TODO
# + fetch special registers (MMX, XMM, 3DNow!, etc)

class ThreadDebugOperations (object):
    """
    Encapsulates several useful debugging routines for threads.

    @group Properties:
        get_teb

    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string

    @group Stack:
        get_stack_frame, get_stack_frame_range, get_stack_range,
        get_stack_trace, get_stack_trace_with_labels,
        read_stack_data, read_stack_dwords,
        peek_stack_data, peek_stack_dwords

    @group Miscellaneous:
        read_code_bytes, peek_code_bytes,
        peek_pointers_in_data, peek_pointers_in_registers,
        get_linear_address
    """

    # TODO
    # Maybe it'd be a good idea to cache the TEB, or at least it's pointer.
    # The pointers may be obtained when debugging at create_thread_event.
    def get_teb(self):
        """
        Returns a copy of the TEB.
        To dereference pointers in it call L{Process.read_structure}.

        @rtype:  L{TEB}
        @return: TEB structure.
        """
        tbi = win32.NtQueryInformationThread(self.get_handle(),
                                                  win32.ThreadBasicInformation)
        aProcess = self.get_process()
        return aProcess.read_structure(tbi.TebBaseAddress, win32.TEB)

    def get_linear_address(self, segment, address):
        """
        Translates segment-relative addresses to linear addresses.

        Linear addresses can be used to access a process memory,
        calling L{Process.read} and L{Process.write}.

        @type  segment: str
        @param segment: Segment register name.

        @type  address: int
        @param address: Segment relative memory address.

        @rtype:  int
        @return: Linear memory address.
        """
        selector = self.get_register(segment)
        ldt      = win32.GetThreadSelectorEntry(self.get_handle(), selector)
        BaseLow  = ldt.BaseLow
        BaseMid  = ldt.HighWord.Bytes.BaseMid << 16
        BaseHi   = ldt.HighWord.Bytes.BaseHi  << 24
        Base     = BaseLow | BaseMid | BaseHi
        LimitLow = ldt.LimitLow
        LimitHi  = ldt.HighWord.Bits.LimitHi  << 16
        Limit    = LimitLow | LimitHi
        if address > Limit:
            raise ValueError, "Address too large for selector: %r" % address
        return Base + address

    def get_seh_chain(self):
        """
        @rtype:  list of tuple( int, int )
        @return: List of structured exception handlers.
            Each SEH is represented as a tuple of two addresses:
                - Address of the SEH block
                - Address of the SEH callback function
        """
        process   = self.get_process()
        seh_chain = list()
        try:
            seh = process.read_uint( self.get_linear_address('SegFs', 0) )
            while seh != 0xFFFFFFFF:
                seh_func = process.read_uint( seh + 4 )
                seh_chain.append( (seh, seh_func) )
                seh = process.read_uint( seh )
        except WindowsError, e:
            print str(e)
            pass
        return seh_chain

    def get_stack_range(self):
        """
        @rtype:  tuple( int, int )
        @return: Stack beginning and end pointers, in memory addresses order.
        """
        process = self.get_process()
        begin   = process.read_uint( self.get_linear_address('SegFs', 8) )
        end     = process.read_uint( self.get_linear_address('SegFs', 4) )
        return (begin, end)

    def __get_stack_trace(self, depth = 16, bUseLabels = True,
                                                           bMakePretty = True):
        """
        Tries to get a stack trace for the current function.
        Only works for functions with standard prologue and epilogue.

        @type  depth: int
        @param depth: Maximum depth of stack trace.

        @type  bUseLabels: bool
        @param bUseLabels: C{True} to use labels, C{False} to use addresses.

        @rtype:  tuple of tuple( int, int, str )
        @return: Stack trace of the thread as a tuple of
            ( return address, frame pointer address, module filename )
            when C{bUseLabels} is C{True}, or a tuple of
            ( return address, frame pointer label )
            when C{bUseLabels} is C{False}.
        """
        aProcess = self.get_process()
        sb, sl   = self.get_stack_range()
        fp       = self.get_fp()
        trace    = list()
        if aProcess.get_module_count() == 0:
            aProcess.scan_modules()
        while depth > 0:
            if fp == 0:
                break
            if not sb <= fp < sl:
                break
            ra  = aProcess.peek_uint(fp + 4)
            if ra == 0:
                break
            lib = aProcess.get_module_at_address(ra)
            if lib is None:
                lib = ""
            else:
                if lib.fileName:
                    lib = lib.fileName
                else:
                    lib = "%s" % HexDump.address(lib.lpBaseOfDll)
            if bUseLabels:
                label = aProcess.get_label_at_address(ra)
                if bMakePretty:
                    label = '%s (%s)' % (HexDump.address(ra), label)
                trace.append( (fp, label) )
            else:
                trace.append( (fp, ra, lib) )
            fp = aProcess.peek_uint(fp)
        return tuple(trace)

    def get_stack_trace(self, depth = 16):
        """
        Tries to get a stack trace for the current function.
        Only works for functions with standard prologue and epilogue.

        @type  depth: int
        @param depth: Maximum depth of stack trace.

        @rtype:  tuple of tuple( int, int, str )
        @return: Stack trace of the thread as a tuple of
            ( return address, frame pointer address, module filename ).
        """
        return self.__get_stack_trace(depth, False)

    def get_stack_trace_with_labels(self, depth = 16, bMakePretty = True):
        """
        Tries to get a stack trace for the current function.
        Only works for functions with standard prologue and epilogue.

        @type  depth: int
        @param depth: Maximum depth of stack trace.

        @type  bMakePretty: bool
        @param bMakePretty:
            C{True} for user readable labels,
            C{False} for labels that can be passed to L{Process.resolve_label}.

            "Pretty" labels look better when producing output for the user to
            read, while pure labels are more useful programatically.

        @rtype:  tuple of tuple( int, int, str )
        @return: Stack trace of the thread as a tuple of
            ( return address, frame pointer label ).
        """
        return self.__get_stack_trace(depth, True)

    def get_stack_frame_range(self):
        """
        Returns the starting and ending addresses of the stack frame.
        Only works for functions with standard prologue and epilogue.

        @rtype:  tuple( int, int )
        @return: Stack frame range.
            May not be accurate, depending on the compiler used.

        @raise RuntimeError: The stack frame is invalid,
            or the function doesn't have a standard prologue
            and epilogue.

        @raise WindowsError: An error occured when getting the thread context.
        """
        sb, sl   = self.get_stack_range()
        sp       = self.get_sp()
        fp       = self.get_fp()
        size     = fp - sp
        if not sb <= sp < sl:
            raise RuntimeError, 'Stack pointer lies outside the stack'
        if not sb <= fp < sl:
            raise RuntimeError, 'Frame pointer lies outside the stack'
        if sp > fp:
            raise RuntimeError, 'No valid stack frame found'
        return (sp, fp)

    def get_stack_frame(self, max_size = None):
        """
        Reads the contents of the current stack frame.
        Only works for functions with standard prologue and epilogue.

        @type  max_size: int
        @param max_size: (Optional) Maximum amount of bytes to read.

        @rtype:  str
        @return: Stack frame data.
            May not be accurate, depending on the compiler used.
            May return an empty string.

        @raise RuntimeError: The stack frame is invalid,
            or the function doesn't have a standard prologue
            and epilogue.

        @raise WindowsError: An error occured when getting the thread context
            or reading data from the process memory.
        """
        sp, fp   = self.get_stack_frame_range()
        size     = fp - sp
        if max_size and size > max_size:
            size = max_size
        return self.get_process().peek(sp, size)

    def read_stack_data(self, size = 128, offset = 0):
        """
        Reads the contents of the top of the stack.

        @type  size: int
        @param size: Number of bytes to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  str
        @return: Stack data.

        @raise WindowsError: Could not read the requested data.
        """
        aProcess = self.get_process()
        return aProcess.read(self.get_sp() + offset, size)

    def peek_stack_data(self, size = 128, offset = 0):
        """
        Tries to read the contents of the top of the stack.

        @type  size: int
        @param size: Number of bytes to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  str
        @return: Stack data.
            Returned data may be less than the requested size.
        """
        aProcess = self.get_process()
        return aProcess.peek(self.get_sp() + offset, size)

    def read_stack_dwords(self, count, offset = 0):
        """
        Reads DWORDs from the top of the stack.

        @type  count: int
        @param count: Number of DWORDs to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  tuple( int... )
        @return: Tuple of integers read from the stack.

        @raise WindowsError: Could not read the requested data.
        """
        stackData = self.read_stack_data(count * 4, offset)
        return struct.unpack('<'+('L'*count), stackData)

    def peek_stack_dwords(self, count, offset = 0):
        """
        Tries to read DWORDs from the top of the stack.

        @type  count: int
        @param count: Number of DWORDs to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  tuple( int... )
        @return: Tuple of integers read from the stack.
            May be less than the requested number of DWORDs.
        """
        stackData = self.peek_stack_data(count * 4, offset)
        if len(stackData) & 3:
            stackData = stackData[:-len(stackData) & 3]
        if not stackData:
            return ()
        return struct.unpack('<'+('L'*count), stackData)

    def read_code_bytes(self, size = 128, offset = 0):
        """
        Tries to read some bytes of the code currently being executed.

        @type  size: int
        @param size: Number of bytes to read.

        @type  offset: int
        @param offset: Offset from the program counter to begin reading.

        @rtype:  str
        @return: Bytes read from the process memory.

        @raise WindowsError: Could not read the requested data.
        """
        return self.get_process().read(self.get_pc() + offset, size)

    def peek_code_bytes(self, size = 128, offset = 0):
        """
        Tries to read some bytes of the code currently being executed.

        @type  size: int
        @param size: Number of bytes to read.

        @type  offset: int
        @param offset: Offset from the program counter to begin reading.

        @rtype:  str
        @return: Bytes read from the process memory.
            May be less than the requested number of bytes.
        """
        return self.get_process().peek(self.get_pc() + offset, size)

    def peek_pointers_in_registers(self, peekSize = 16, context = None):
        """
        Tries to guess which values in the registers are valid pointers,
        and reads some data from them.

        @type  peekSize: int
        @param peekSize: Number of bytes to read from each pointer found.

        @type  context: dict( str S{->} int )
        @param context: (Optional)
            Dictionary mapping register names to their values.
            If not given, the current thread context will be used.

        @rtype:  dict( str S{->} str )
        @return: Dictionary mapping register names to the data they point to.
        """
        peekable_registers = (
            'Eax', 'Ebx', 'Ecx', 'Edx', 'Esi', 'Edi', 'Ebp'
        )
        if not context:
            context = self.get_context(win32.CONTEXT_CONTROL | \
                                       win32.CONTEXT_INTEGER)
        aProcess    = self.get_process()
        data        = dict()
        for (reg_name, reg_value) in context.iteritems():
            if reg_name not in peekable_registers:
                continue
##            if reg_name == 'Ebp':
##                stack_begin, stack_end = self.get_stack_range()
##                print hex(stack_end), hex(reg_value), hex(stack_begin)
##                if stack_begin and stack_end and stack_end < stack_begin and \
##                   stack_begin <= reg_value <= stack_end:
##                      continue
            reg_data = aProcess.peek(reg_value, peekSize)
            if reg_data:
                data[reg_name] = reg_data
        return data

    # TODO
    # try to avoid reading the same page twice by caching it
    def peek_pointers_in_data(self, data, peekSize = 16, peekStep = 1):
        """
        Tries to guess which values in the given data are valid pointers,
        and reads some data from them.

        @type  data: str
        @param data: Binary data to find pointers in.

        @type  peekSize: int
        @param peekSize: Number of bytes to read from each pointer found.

        @type  peekStep: int
        @param peekStep: Expected data alignment.
            Tipically you specify 1 when data alignment is unknown,
            or 4 when you expect data to be DWORD aligned.
            Any other value may be specified.

        @rtype:  dict( str S{->} str )
        @return: Dictionary mapping stack offsets to the data they point to.
        """
        aProcess = self.get_process()
        return aProcess.peek_pointers_in_data(data, peekSize, peekStep)

#------------------------------------------------------------------------------

    # TODO
    # The disassemble_around and disassemble_around_pc methods
    # should take as parameter instruction counts rather than sizes

    @staticmethod
    def disassemble_string(lpAddress, code):
        """
        Disassemble instructions from a block of binary code.

        @type  lpAddress: int
        @param lpAddress: Memory address where the code was read from.

        @type  code: str
        @param code: Binary code to disassemble.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        return ProcessDebugOperations.disassemble_string(lpAddress, code)

    def disassemble(self, lpAddress, dwSize):
        """
        Disassemble instructions from the address space of the process.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @type  dwSize: int
        @param dwSize: Size of binary code to disassemble.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aProcess = self.get_process()
        return aProcess.disassemble(lpAddress, dwSize)

    def disassemble_around(self, lpAddress, dwSize = 64):
        """
        Disassemble around the given address.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @type  dwSize: int
        @param dwSize: Delta offset.
            Code will be read from lpAddress - dwSize to lpAddress + dwSize.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aProcess = self.get_process()
        return aProcess.disassemble_around(lpAddress, dwSize)

    def disassemble_around_pc(self, dwSize = 64):
        """
        Disassemble around the program counter of the given thread.

        @type  dwSize: int
        @param dwSize: Delta offset.
            Code will be read from pc - dwSize to pc + dwSize.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aProcess = self.get_process()
        return aProcess.disassemble_around(self.get_pc(), dwSize)

#==============================================================================

# TODO
# + remote GetLastError

class ProcessDebugOperations (object):
    """
    Encapsulates several useful debugging routines for processes.

    @group Properties:
        get_peb, get_main_module, get_image_base, get_image_name

    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string

    @group Debugging:
        flush_instruction_cache, debug_break, peek_pointers_in_data
    """

    __hexa_parameter = re.compile('0x[0-9A-Za-z]+')

    def __fixup_labels(self, disasm):
        for index in xrange(len(disasm)):
            (address, size, text, dump) = disasm[index]
            m = self.__hexa_parameter.search(text)
            while m:
                s, e = m.span()
                value = text[s:e]
                try:
                    label = self.get_label_at_address( int(value, 0x10) )
                except Exception, e:
                    label = None
                if label:
                    text = text[:s] + label + text[e:]
                    e = s + len(value)
                m = self.__hexa_parameter.search(text, e)
            disasm[index] = (address, size, text, dump)

    @staticmethod
    def disassemble_string(lpAddress, code):
        """
        Disassemble instructions from a block of binary code.

        @type  lpAddress: int
        @param lpAddress: Memory address where the code was read from.

        @type  code: str
        @param code: Binary code to disassemble.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        return Decode(lpAddress, code)

    def disassemble(self, lpAddress, dwSize):
        """
        Disassemble instructions from the address space of the process.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @type  dwSize: int
        @param dwSize: Size of binary code to disassemble.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        data   = self.read(lpAddress, dwSize)
        disasm = self.disassemble_string(lpAddress, data)
        self.__fixup_labels(disasm)
        return disasm

    # FIXME
    # This algorithm really sucks, I've got to write a better one :P
    def disassemble_around(self, lpAddress, dwSize = 64):
        """
        Disassemble around the given address.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @type  dwSize: int
        @param dwSize: Delta offset.
            Code will be read from lpAddress - dwSize to lpAddress + dwSize.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        dwDelta  = int(float(dwSize) / 2.0)
        addr_1   = lpAddress - dwDelta
        addr_2   = lpAddress
        size_1   = dwDelta
        size_2   = dwSize - dwDelta
        data     = self.read(addr_1, dwSize)
        data_1   = data[:size_1]
        data_2   = data[size_1:]
        disasm_1 = self.disassemble_string(addr_1, data_1)
        disasm_2 = self.disassemble_string(addr_2, data_2)
        disasm   = disasm_1 + disasm_2
        self.__fixup_labels(disasm)
        return disasm

    def disassemble_around_pc(self, dwThreadId, dwSize = 64):
        """
        Disassemble around the program counter of the given thread.

        @type  dwThreadId: int
        @param dwThreadId: Global thread ID.
            The program counter for this thread will be used as the disassembly
            address.

        @type  dwSize: int
        @param dwSize: Delta offset.
            Code will be read from pc - dwSize to pc + dwSize.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aThread = self.get_thread(dwThreadId)
        return self.disassemble_around(aThread.get_pc(), dwSize)

#------------------------------------------------------------------------------

    def flush_instruction_cache(self):
        """
        Flush the instruction cache. This is required if the process memory is
        modified and one or more threads are executing nearby the modified
        memory region.

        @see: U{http://blogs.msdn.com/oldnewthing/archive/2003/12/08/55954.aspx#55958}

        @raise WindowsError: Raises exception on error.
        """
        win32.FlushInstructionCache(self.get_handle())

    def debug_break(self):
        """
        Triggers the system breakpoint in the process.

        @raise WindowsError: On error an exception is raised.
        """
        # The exception is raised by a new thread.
        # When continuing the exception, the thread dies by itself.
        # This thread is hidden from the debugger.
        win32.DebugBreakProcess(self.get_handle())

#------------------------------------------------------------------------------

    def get_peb(self):
        """
        Returns a copy of the PEB.
        To dereference pointers in it call L{Process.read_structure}.

        @rtype:  L{PEB}
        @return: PEB structure.
        """
        pbi = win32.NtQueryInformationProcess(self.get_handle(),
                                                 win32.ProcessBasicInformation)
        return self.read_structure(pbi.PebBaseAddress, win32.PEB)

    def get_main_module(self):
        """
        @rtype:  L{Module}
        @return: Module object for the process main module.
        """
        return self.get_module(self.get_image_base())

    def get_image_base(self):
        """
        @rtype:  int
        @return: Image base address for the process main module.
        """
        return self.get_peb().ImageBaseAddress

    # TODO
    # Still not working sometimes, I need more implementations.
    # Example: PIFSvc.exe from Symantec, under Windows XP.
    # Note that using the toolhelp api won't help, it also fails.
    # My guess is tasklist.exe uses undocumented apis (at ntdll?).
    def get_image_name(self):
        """
        @rtype:  int
        @return: Filename of the process main module.

            This method does it's best to retrieve the filename.
            However sometimes this is not possible, so C{None} may
            be returned instead.
        """

        name = None

        # method 1: Module.get_filename()
        # only works if the filename was already found by the other methods,
        # or it came with the corresponding debug event.
        if not name:
            try:
                aModule = self.get_main_module()
                name    = aModule.get_filename()
            except (KeyError, AttributeError, WindowsError):
                name = None

        # method 2: QueryFullProcessImageName()
        # not implemented until Windows Vista.
        if not name:
            try:
                name = win32.QueryFullProcessImageName(self.get_handle())
            except (AttributeError, WindowsError):
                name = None

        # method 3: GetProcessImageFileName()
        # not implemented until Windows XP.
        # for more info see http://blog.voidnish.com/?p=72
        if not name:
            try:
                name = win32.GetProcessImageFileName(self.get_handle())
                if name:
                    name = PathOperations.native_to_win32_pathname(name)
                else:
                    name = None
            except (AttributeError, WindowsError):
                if not name:
                    name = None

        # method 4: GetModuleFileNameEx()
        # not implemented until Windows 2000.
        if not name:
            try:
                # XXX: sometimes gives odd pathnames like:
                #   \SystemRoot\System32\smss.exe
                #   \??\C:\WINDOWS\system32\csrss.exe
                #   \??\C:\WINDOWS\system32\winlogon.exe
                name = win32.GetModuleFileNameEx(self.get_handle(), win32.NULL)
                if name:
                    name = PathOperations.native_to_win32_pathname(name)
                else:
                    name = None
            except (AttributeError, WindowsError):
                if not name:
                    name = None

##        # method 5: NtQueryInformationProcess(ProcessImageFileName)
##        # not implemented in W2K.
##        # may fail since it's not officially part of the Win32 API.
##        # FIXME not working on XP either :( returns STATUS_INVALID_INFO_CLASS
##        if not name:
##            try:
##                name = win32.NtQueryInformationProcess(self.get_handle(),
##                                                win32.ProcessImageFileName)
##            except (AttributeError, WindowsError):
##                name = None

        # method 6: PEB.ProcessParameters->ImagePathName
        # may fail since it's using an undocumented internal structure.
        if not name:
            try:
                peb = self.get_peb()
                pp = self.read_structure(peb.ProcessParameters,
                                             win32.RTL_USER_PROCESS_PARAMETERS)
                s = pp.ImagePathName
##                name = self.read_string(s.Buffer, s.Length, fUnicode=True)
                name = self.peek_string(s.Buffer, dwMaxSize=s.MaximumLength, fUnicode=True)
            except (AttributeError, WindowsError):
                name = None

        # return the image filename, or None on error.
        return name

    def get_command_line(self):
        """
        Retrieves the command line with wich the program was started.

        @rtype:  str
        @return: Command line string.

        @raise WindowsError: On error an exception is raised.
        """
        peb = self.get_peb()
        pp = self.read_structure(peb.ProcessParameters,
                                             win32.RTL_USER_PROCESS_PARAMETERS)
        s = pp.CommandLine
##        return self.read_string(s.Buffer, s.Length, fUnicode=True)
        return self.peek_string(s.Buffer, dwMaxSize=s.MaximumLength, fUnicode=True)

#------------------------------------------------------------------------------

    # TODO
    # try to avoid reading the same page twice by caching it
    def peek_pointers_in_data(self, data, peekSize = 16, peekStep = 1):
        """
        Tries to guess which values in the given data are valid pointers,
        and reads some data from them.

        @type  data: str
        @param data: Binary data to find pointers in.

        @type  peekSize: int
        @param peekSize: Number of bytes to read from each pointer found.

        @type  peekStep: int
        @param peekStep: Expected data alignment.
            Tipically you specify 1 when data alignment is unknown,
            or 4 when you expect data to be DWORD aligned.
            Any other value may be specified.

        @rtype:  dict( str S{->} str )
        @return: Dictionary mapping stack offsets to the data they point to.
        """
        result = dict()
        if len(data) > 0:
            for i in xrange(0, len(data), peekStep):
                packed          = data[i:i+4]
                if len(packed) == 4:
                    address     = struct.unpack('<L', packed)[0]
                    if address & 0xFFFF0000:
                        peek_data   = self.peek(address, peekSize)
                        if peek_data:
                            result[i] = peek_data
        return result

#==============================================================================

class ProcessContainer (object):
    """
    Encapsulates the capability to contain Process objects.

    @group Instrumentation:
        start_process, argv_to_cmdline, cmdline_to_argv

    @group Processes snapshot:
        scan, scan_processes, scan_processes_fast,
        get_process, get_process_count, get_process_ids,
        has_process, iter_processes, iter_process_ids,
        find_processes_by_filename,
        clear, clear_processes, clear_dead_processes,
        clear_unattached_processes,
        close_process_handles,
        close_process_and_thread_handles

    @group Threads snapshots:
        scan_processes_and_threads,
        get_thread, get_thread_count, get_thread_ids,
        has_thread

    @group Modules snapshots:
        scan_modules, find_modules_by_address,
        find_modules_by_base, find_modules_by_name,
        get_module_count

    @group Event notifications (private):
        notify_create_process,
        notify_exit_process
    """

    def __init__(self):
        super(ProcessContainer, self).__init__()
        self.__processDict = dict()

    def __contains__(self, anObject):
        """
        @type  anObject: L{Process}, L{Thread}, int
        @param anObject:
             - C{int}: Global ID of the process to look for.
             - C{int}: Global ID of the thread to look for.
             - C{Process}: Process object to look for.
             - C{Thread}: Thread object to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains
            a L{Process} or L{Thread} object with the same ID.
        """
        if isinstance(anObject, Process):
            anObject = anObject.dwProcessId
        if self.has_process(anObject):
            return True
        for aProcess in self.iter_processes():
            if anObject in aProcess:
                return True
        return False

    def __iter__(self):
        """
        @see:    L{iter_processes}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Process} objects in this snapshot.
        """
        return self.iter_processes()

    def __len__(self):
        """
        @see:    L{get_process_count}
        @rtype:  int
        @return: Count of L{Process} objects in this snapshot.
        """
        return self.get_process_count()

    def __add_process(self, aProcess):
##        if not isinstance(aProcess, Process):
##            if hasattr(aProcess, '__class__'):
##                typename = aProcess.__class__.__name__
##            else:
##                typename = str(type(aProcess))
##            msg = "Expected Process, got %s instead" % typename
##            raise TypeError, msg
        dwProcessId = aProcess.dwProcessId
##        if dwProcessId in self.__processDict:
##            msg = "Process already exists: %d" % dwProcessId
##            raise KeyError, msg
        self.__processDict[dwProcessId] = aProcess

    def __del_process(self, dwProcessId):
##        if dwProcessId not in self.__processDict:
##            msg = "Unknown process ID %d" % dwProcessId
##            raise KeyError, msg
        del self.__processDict[dwProcessId]

    def has_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Process} object with the given global ID.
        """
        return dwProcessId in self.__processDict

    def get_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.

        @rtype:  L{Process}
        @return: Process object with the given global ID.
        """
        if dwProcessId not in self.__processDict:
            msg = "Unknown process ID %d" % dwProcessId
            raise KeyError, msg
        return self.__processDict[dwProcessId]

    def iter_process_ids(self):
        """
        @see:    L{iter_processes}
        @rtype:  dictionary-keyiterator
        @return: Iterator of global process IDs in this snapshot.
        """
        return self.__processDict.iterkeys()

    def iter_processes(self):
        """
        @see:    L{iter_process_ids}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Process} objects in this snapshot.
        """
        return self.__processDict.itervalues()

    def get_process_ids(self):
        """
        @see:    L{iter_process_ids}
        @rtype:  list( int )
        @return: List of global process IDs in this snapshot.
        """
        return self.__processDict.keys()

    def get_process_count(self):
        """
        @rtype:  int
        @return: Count of L{Process} objects in this snapshot.
        """
        return len(self.__processDict)

#------------------------------------------------------------------------------

    def get_windows(self):
        window_list = list()
        for process in self.iter_processes():
            window_list.extend( process.get_windows() )
        return window_list

#------------------------------------------------------------------------------

    def argv_to_cmdline(self, argv):
        """
        Convert a list of arguments to a single command line string.

        @type  argv: list( str )
        @param argv: List of argument strings.
            The first element is the program to execute.

        @rtype:  str
        @return: Command line string.
        """
        cmdline = list()
        for token in argv:
            if '"' in token:
                token = token.replace('"', '\\"')
            if ' ' in token or '\t' in token or '\n' in token or '\r' in token:
                token = '"%s"' % token
            cmdline.append(token)
        return ' '.join(cmdline)

    def cmdline_to_argv(self, lpCmdLine):
        """
        Convert a single command line string to a list of arguments.

        @type  lpCmdLine: str
        @param lpCmdLine: Command line string.
            The first token is the program to execute.

        @rtype:  list( str )
        @return: List of argument strings.
        """
        if not lpCmdLine:
            return []
        return win32.CommandLineToArgv(lpCmdLine)

    def start_process(self, lpCmdLine,
            bConsole    = False,
            bDebug      = False,
            bFollow     = False,
            bSuspended  = False
        ):
        """
        Starts a new process for debugging.

        @type  lpCmdLine: str
        @param lpCmdLine: Command line to execute. Can't be an empty string.

        @type  bConsole: bool
        @param bConsole: C{True} if the new process should inherit the console.

        @type  bDebug: bool
        @param bDebug: C{True} to attach to the new process.
            To debug a process it's best to use the L{Debug} class instead.

        @type  bFollow: bool
        @param bFollow: C{True} to automatically attach to the child processes
            of the newly created process. Ignored unless C{bDebug} is C{True}.

        @type  bSuspended: bool
        @param bSuspended: C{True} if the new process should be suspended.

        @rtype:  L{Process}
        @return: Process object.
        """
        if not lpCmdLine:
            raise ValueError, "Missing command line to execute!"
        dwCreationFlags  = 0
        dwCreationFlags |= win32.CREATE_DEFAULT_ERROR_MODE
        dwCreationFlags |= win32.CREATE_BREAKAWAY_FROM_JOB
        if not bConsole:
            dwCreationFlags |= win32.DETACHED_PROCESS
        if bSuspended:
            dwCreationFlags |= win32.CREATE_SUSPENDED
        if bDebug:
            dwCreationFlags |= win32.DEBUG_PROCESS
        if bDebug and not bFollow:
            dwCreationFlags |= win32.DEBUG_ONLY_THIS_PROCESS
        pi = win32.CreateProcess(win32.NULL, lpCmdLine,
                                             dwCreationFlags = dwCreationFlags)
        aProcess = Process(pi.dwProcessId, pi.hProcess)
        aThread  = Thread (pi.dwThreadId,  pi.hThread)
        aProcess._ThreadContainer__add_thread(aThread)
        self.__add_process(aProcess)
        return aProcess

#------------------------------------------------------------------------------

    def scan(self):
        """
        Populates the snapshot with running processes and threads,
        and loaded modules.
        """
        self.scan_processes_and_threads()
        self.scan_modules()

    def scan_processes_and_threads(self):
        """
        Populates the snapshot with running processes and threads.
        """
        our_pid    = win32.GetProcessId( win32.GetCurrentProcess() )
        dead_pids  = set( self.get_process_ids() )
        found_tids = set()

        # Ignore our own process if it's in the snapshot for some reason
        if our_pid in dead_pids:
            dead_pids.remove(our_pid)

        # Take a snapshot of all processes and threads
        # (excluding our own)
        dwFlags   = win32.TH32CS_SNAPPROCESS | win32.TH32CS_SNAPTHREAD
        hSnapshot = win32.CreateToolhelp32Snapshot(dwFlags)
        try:

            # Add all the processes
            pe = win32.Process32First(hSnapshot)
            while pe is not None:
                dwProcessId = pe.th32ProcessID
                if dwProcessId != our_pid:
                    if dwProcessId in dead_pids:
                        dead_pids.remove(dwProcessId)
                    if not self.has_process(dwProcessId):
                        aProcess = Process(dwProcessId)
                        self.__add_process(aProcess)
                    elif pe.szExeFile:
                        aProcess = self.get_process(dwProcessId)
                        if not aProcess.fileName:
                            aProcess.fileName = pe.szExeFile
                pe = win32.Process32Next(hSnapshot)

            # Add all the threads
            te = win32.Thread32First(hSnapshot)
            while te is not None:
                dwProcessId = te.th32OwnerProcessID
                if dwProcessId != our_pid:
                    if dwProcessId in dead_pids:
                        dead_pids.remove(dwProcessId)
                    if self.has_process(dwProcessId):
                        aProcess = self.get_process(dwProcessId)
                    else:
                        aProcess = Process(dwProcessId)
                        self.__add_process(aProcess)
                    dwThreadId = te.th32ThreadID
                    found_tids.add(dwThreadId)
                    if not aProcess.has_thread(dwThreadId):
                        aThread = Thread(dwThreadId, process = aProcess)
                        aProcess._ThreadContainer__add_thread(aThread)
                te = win32.Thread32Next(hSnapshot)

        # Always close the snapshot handle before returning
        finally:
            win32.CloseHandle(hSnapshot)

        # Remove dead processes
        for pid in dead_pids:
            self.__del_process(pid)

        # Remove dead threads
        for aProcess in self.iter_processes():
            dead_tids = set( aProcess.get_thread_ids() )
            dead_tids.difference_update(found_tids)
            for tid in dead_tids:
                aProcess._ThreadContainer__del_thread(tid)

    def scan_modules(self):
        """
        Populates the snapshot with loaded modules.
        """
        for aProcess in self.iter_processes():
            try:
                aProcess.scan_modules()
            except WindowsError, e:
                # For some reason, scanning the modules of PID 4 always fails.
                dwProcessId = aProcess.get_pid()
                if dwProcessId == 4 and e.winerror == 8:
                    continue

    def scan_processes(self):
        """
        Populates the snapshot with running processes.
        """
        our_pid   = win32.GetProcessId( win32.GetCurrentProcess() )
        dead_pids = set( self.get_process_ids() )
        if our_pid in dead_pids:
            dead_pids.remove(our_pid)
        hSnapshot = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPPROCESS)
        try:
            pe = win32.Process32First(hSnapshot)
            while pe is not None:
                dwProcessId = pe.th32ProcessID
                if dwProcessId != our_pid:
                    if dwProcessId in dead_pids:
                        dead_pids.remove(dwProcessId)
                    if not self.has_process(dwProcessId):
                        aProcess = Process(dwProcessId)
                        self.__add_process(aProcess)
                    elif pe.szExeFile:
                        aProcess = self.get_process(dwProcessId)
                        if not aProcess.fileName:
                            aProcess.fileName = pe.szExeFile
                pe = win32.Process32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        for pid in dead_pids:
            self.__del_process(pid)

    def scan_processes_fast(self):
        """
        Populates the snapshot with running processes.
        Only the PID is retrieved for each process.

        Dead processes are removed.
        Threads and modules of living processes are ignored.

        @note: This method may be faster for scanning, but some information
            may be missing, outdated or slower to obtain. This could be a good
            tradeoff under some circumstances.
        """

        # Get the new and old list of pids
        new_pids = set( win32.EnumProcesses() )
        old_pids = set( self.get_process_ids() )

        # Ignore our own pid
        our_pid  = win32.GetProcessId( win32.GetCurrentProcess() )
        if our_pid in new_pids:
            new_pids.remove(our_pid)
        if our_pid in old_pids:
            old_pids.remove(our_pid)

        # Add newly found pids
        for pid in new_pids.difference(old_pids):
            self.__add_process( Process(pid) )

        # Remove missing pids
        for pid in old_pids.difference(new_pids):
            self.__del_process(pid)

    def clear_dead_processes(self):
        """
        Removes Process objects from the snapshot
        referring to processes no longer running.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            if not aProcess.is_alive():
                self.__del_process(aProcess)

    def clear_unattached_processes(self):
        """
        Removes Process objects from the snapshot
        referring to processes not being debugged.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            if not aProcess.is_being_debugged():
                self.__del_process(aProcess)

    def close_process_handles(self):
        """
        Closes all open handles to processes in this snapshot.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            try:
                aProcess.close_handle()
            except Exception, e:
                pass

    def close_process_and_thread_handles(self):
        """
        Closes all open handles to processes and threads in this snapshot.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            aProcess.close_thread_handles()
            try:
                aProcess.close_handle()
            except Exception, e:
                pass

    def clear_processes(self):
        """
        Removes all L{Process}, L{Thread} and L{Module} objects in this snapshot.
        """
        self.__processDict = dict()

    def clear(self):
        """
        Clears this snapshot.

        @see: L{clear_processes}
        """
        self.clear_processes()

#------------------------------------------------------------------------------

    # Docs for these methods are taken from the ThreadContainer class.

    def has_thread(self, dwThreadId):
        for aProcess in self.iter_processes():
            if aProcess.has_thread(dwThreadId):
                return True
        return False

    def get_thread(self, dwThreadId):
        for aProcess in self.iter_processes():
            if aProcess.has_thread(dwThreadId):
                return aProcess.get_thread(dwThreadId)
        msg = "Unknown thread ID %d" % dwThreadId
        raise KeyError, msg

    def get_thread_ids(self):
        ids = list()
        for aProcess in self.iter_processes():
            ids += aProcess.get_thread_ids()
        return ids

    def get_thread_count(self):
        count = 0
        for aProcess in self.iter_processes():
            count += aProcess.get_thread_count()
        return count

    has_thread.__doc__       = ThreadContainer.has_thread.__doc__
    get_thread.__doc__       = ThreadContainer.get_thread.__doc__
    get_thread_ids.__doc__   = ThreadContainer.get_thread_ids.__doc__
    get_thread_count.__doc__ = ThreadContainer.get_thread_count.__doc__

#------------------------------------------------------------------------------

    # Docs for these methods are taken from the ModuleContainer class.

    def get_module_count(self):
        count = 0
        for aProcess in self.iter_processes():
            count += aProcess.get_module_count()
        return count

    get_module_count.__doc__ = ModuleContainer.get_module_count.__doc__

#------------------------------------------------------------------------------

    def find_modules_by_base(self, lpBaseOfDll):
        """
        @rtype:  list( L{Module}... )
        @return: List of Module objects with the given base address.
        """
        found = list()
        for aProcess in self.iter_processes():
            if aProcess.has_module(lpBaseOfDll):
                aModule = aProcess.get_module(lpBaseOfDll)
                found.append( (aProcess, aModule) )
        return found

    def find_modules_by_name(self, fileName):
        """
        @rtype:  list( L{Module}... )
        @return: List of Module objects found.
        """
        found = list()
        for aProcess in self.iter_processes():
            aModule = aProcess.get_module_by_name(fileName)
            if aModule is not None:
                found.append( (aProcess, aModule) )
        return found

    def find_modules_by_address(self, address):
        """
        @rtype:  list( L{Module}... )
        @return: List of Module objects that best match the given address.
        """
        found = list()
        for aProcess in self.iter_processes():
            aModule = aProcess.get_module_at_address(address)
            if aModule is not None:
                found.append( (aProcess, aModule) )
        return found

    def __find_processes_by_filename(self, filename):
        """
        Internally used by L{find_processes_by_filename}.
        """
        found    = list()
        filename = filename.lower()
        if PathOperations.path_is_absolute(filename):
            for aProcess in self.iter_processes():
                imagename = aProcess.get_filename()
                if imagename and imagename.lower() == filename:
                    found.append( (aProcess, imagename) )
        else:
            for aProcess in self.iter_processes():
                imagename = aProcess.get_filename()
                if imagename:
                    imagename = PathOperations.pathname_to_filename(imagename)
                    if imagename.lower() == filename:
                        found.append( (aProcess, imagename) )
        return found

    def find_processes_by_filename(self, fileName):
        """
        @type  fileName: str
        @param fileName: Filename to search for.
            If it's a full pathname, the match must be exact.
            If it's a base filename only, the file part is matched,
            regardless of the directory where it's located.

        @note: If the process is not found and the file extension is not
            given, this method will search again assuming a default
            extension (.exe).

        @rtype:  list of tuple( L{Process}, str )
        @return: List of processes matching the given main module filename.
            Each tuple contains a Process object and it's filename.
        """
        found = self.__find_processes_by_filename(fileName)
        if not found:
            fn, ext = PathOperations.split_extension(fileName)
            if not ext:
                fileName = '%s.exe' % fn
                found    = self.__find_processes_by_filename(fileName)
        return found

#------------------------------------------------------------------------------

    # Notify the creation of a new process.
    def notify_create_process(self, event):
        """
        Notify the creation of a new process.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.
        """
        dwProcessId = event.get_pid()
        dwThreadId  = event.get_tid()
        hProcess    = event.get_process_handle()
        if self.has_process(dwProcessId):
            aProcess = self.get_process(dwProcessId)
            if hProcess != win32.INVALID_HANDLE_VALUE:
                aProcess.hProcess = hProcess    # may have more privileges
            if not aProcess.fileName:
                fileName = event.get_filename()
                if fileName:
                    aProcess.fileName = fileName
        else:
            aProcess = Process(dwProcessId, hProcess)
            self.__add_process(aProcess)
            aProcess.fileName = event.get_filename()
        return aProcess.notify_create_process(event)   # pass it to the process

    def notify_exit_process(self, event):
        """
        Notify the termination of a process.

        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.
        """
        dwProcessId = event.get_pid()
        if self.has_process(dwProcessId):
            self.__del_process(dwProcessId)
        return True

#==============================================================================

class Window (object):

    def __init__(self, hWnd = None, process = None, thread = None):
        self.hWnd        = hWnd
        self.process     = process
        self.thread      = thread
        self.dwProcessId = None
        self.dwThreadId  = None

    def get_handle(self):
        if self.hWnd is None:
            raise ValueError, "No window handle set!"
        return self.hWnd

    def get_pid(self):
        if self.process:
            return process.get_pid()
        if not self.dwProcessId:
            self.__get_pid_and_tid()
        return self.dwProcessId

    def get_tid(self):
        if self.thread:
            return thread.get_tid()
        if not self.dwThreadId:
            self.__get_pid_and_tid()
        return self.dwThreadId

    def __get_pid_and_tid(self):
        self.dwThreadId, self.dwProcessId = \
                                      win32.GetWindowThreadProcessId(self.hWnd)

    def get_process(self):
        if not self.process:
            self.process = self.get_thread().get_process()
        return self.process

    def get_thread(self):
        if not self.thread:
            self.thread = Thread( self.get_tid() )
        return self.thread

    def get_classname(self):
        return win32.GetClassName( self.get_handle() )

    def get_text(self):
        buffer = ctypes.create_string_buffer("", 0x10000)
        win32.SendMessageA(self.get_handle(), win32.WM_GETTEXT, ctypes.byref(buffer), 0x10000)
        return buffer.value

    def set_text(self, text):
        win32.SendMessage(self.get_handle(), win32.WM_SETTEXT, text, len(text))

    def get_parent(self):
        return Window( win32.GetParent( self.get_handle() ), \
                                                    self.process, self.thread )

    def get_children(self):
        return [
                Window( hWnd, self.process, self.thread ) \
                for hWnd in win32.EnumChildWindows( self.get_handle() )
                ]

    def get_tree(self):
        subtree = dict()
        for aWindow in self.get_children():
            subtree[ aWindow.get_handle() ] = aWindow.get_tree()
        return subtree

    def get_root(self):
        hWnd     = self.get_handle()
        hPrevWnd = hWnd
        while hWnd:
            hPrevWnd = hWnd
            hWnd     = win32.GetParent(hWnd)
        return Window(hPrevWnd)

    def enable(self):
        win32.EnableWindow( self.get_handle(), True )

    def disable(self):
        win32.EnableWindow( self.get_handle(), False )

    def show(self, bAsync = True):
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_SHOW )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_SHOW )

    def hide(self, bAsync = True):
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_HIDE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_HIDE )

    def maximize(self, bAsync = True):
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_MAXIMIZE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_MAXIMIZE )

    def minimize(self, bAsync = True):
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_MINIMIZE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_MINIMIZE )

    def restore(self, bAsync = True):
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_RESTORE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_RESTORE )

#==============================================================================

class Module (SymbolContainer):
    """
    Interface to a DLL library loaded in the context of another process.

    @group Properties:
        get_base, get_filename, get_name, get_size, get_entry_point,
        get_process, get_pid

    @group Labels:
        get_label, get_label_at_address, is_address_here,
        resolve, resolve_label, match_name

    @group Handle:
        get_handle, open_handle, close_handle

    @type unknown: str
    @cvar unknown: Suggested tag for unknown modules.

    @type lpBaseOfDll: int
    @ivar lpBaseOfDll: Base of DLL module.
        Use L{get_base} instead.

    @type hFile: L{FileHandle}
    @ivar hFile: Handle to the module file.
        Use L{get_handle} instead.

    @type fileName: str
    @ivar fileName: Module filename.
        Use L{get_filename} instead.

    @type SizeOfImage: int
    @ivar SizeOfImage: Size of the module.
        Use L{get_size} instead.

    @type EntryPoint: int
    @ivar EntryPoint: Entry point of the module.
        Use L{get_entry_point} instead.

    @type process: L{Process}
    @ivar process: Process where the module is loaded.
        Use L{get_process} instead.
    """

    unknown = '<unknown>'

    def __init__(self, lpBaseOfDll, hFile = None, fileName    = None,
                                                  SizeOfImage = None,
                                                  EntryPoint  = None,
                                                  process     = None):
        """
        @type  lpBaseOfDll: str
        @param lpBaseOfDll: Base address of the module.

        @type  hFile: L{FileHandle}
        @param hFile: (Optional) Handle to the module file.

        @type  fileName: str
        @param fileName: (Optional) Module filename.

        @type  SizeOfImage: int
        @param SizeOfImage: (Optional) Size of the module.

        @type  EntryPoint: int
        @param EntryPoint: (Optional) Entry point of the module.

        @type  process: L{Process}
        @param process: (Optional) Process where the module is loaded.
        """
        super(Module, self).__init__()
        self.lpBaseOfDll    = lpBaseOfDll
        self.hFile          = hFile
        self.fileName       = fileName
        self.SizeOfImage    = SizeOfImage
        self.EntryPoint     = EntryPoint
        self.process        = process

    def get_base(self):
        """
        @rtype:  int or None
        @return: Base address of the module.
            Returns C{None} if unknown.
        """
        return self.lpBaseOfDll

    def get_size(self):
        """
        @rtype:  int or None
        @return: Base size of the module.
            Returns C{None} if unknown.
        """
        if not self.SizeOfImage:
            self.__get_size_and_entry_point()
        return self.SizeOfImage

    def get_entry_point(self):
        """
        @rtype:  int or None
        @return: Entry point of the module.
            Returns C{None} if unknown.
        """
        if not self.EntryPoint:
            self.__get_size_and_entry_point()
        return self.EntryPoint

    def __get_size_and_entry_point(self):
        "Get the size and entry point of the module using the Win32 API."
        process = self.get_process()
        if process:
            try:
                handle = process.get_handle()
                base   = self.get_base()
                mi     = win32.GetModuleInformation(handle, base)
                self.SizeOfImage = mi.SizeOfImage
                self.EntryPoint  = mi.EntryPoint
            except WindowsError:
                pass

    def get_filename(self):
        """
        @rtype:  str or None
        @return: Module filename.
            Returns C{None} if unknown.
        """
        if self.fileName is None:
            if self.hFile not in (None, win32.INVALID_HANDLE_VALUE):
                self.fileName = self.hFile.get_filename()
        return self.fileName

    def __filename_to_modname(self, pathname):
        """
        @type  pathname: str
        @param pathname: Pathname to a module.

        @rtype:  str
        @return: Module name.
        """
        filename = PathOperations.pathname_to_filename(pathname)
        if filename:
            filename = filename.lower()
            filepart, extpart = PathOperations.split_extension(filename)
            if filepart and extpart and extpart == '.dll':
                modName = filepart
            else:
                modName = filename
        else:
            modName = pathname
        return modName

    def get_name(self):
        """
        @rtype:  str
        @return: Module name, as used in labels.

        @warning: Names are B{NOT} guaranteed to be unique.

            If you need unique identification for a loaded module,
            use the base address instead.

        @see: L{get_label}
        """
        pathname = self.get_filename()
        if pathname:
            modName = self.__filename_to_modname(pathname)
        else:
            modName = "0x%x" % self.get_base()
        return modName

    def match_name(self, name):
        """
        @rtype:  bool
        @return:
            C{True} if the given name could refer to this module.
            It may not be exactly the same returned by L{get_name}.
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

    def get_process(self):
        """
        @rtype:  L{Process} or None
        @return: Parent Process object.
            Returns C{None} on error.
        """
        return self.process

    def get_pid(self):
        """
        @rtype:  int or None
        @return: Parent process global ID.
            Returns C{None} on error.
        """
        if self.process is None:
            return None
        return self.process.get_pid()

#------------------------------------------------------------------------------

    def open_handle(self):
        """
        Opens a new handle to the module.
        """

        if not self.get_filename():
            msg = "Cannot retrieve filename for module at %s"
            msg = msg % HexDump.address( self.get_base() )
            raise Exception, msg

        hFile = win32.CreateFile(self.get_filename(),
                                           dwShareMode = win32.FILE_SHARE_READ,
                                 dwCreationDisposition = win32.OPEN_EXISTING)
        try:
            self.close_handle()
        finally:
            self.hFile = hFile

    def close_handle(self):
        """
        Closes the handle to the module.
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
        @rtype:  L{FileHandle}
        @return: Handle to the module file.
        """
        if self.hFile in (None, win32.INVALID_HANDLE_VALUE):
            self.open_handle()
        return self.hFile

#------------------------------------------------------------------------------

    def get_label(self, function = None, offset = None):
        """
        Retrieves the label for the given function of this module or the module
        base address if no function name is given.

        @type  function: str
        @param function: (Optional) Exported function name.

        @type  offset: int
        @param offset: (Optional) Offset from the module base address.

        @rtype:  str
        @return: Label for the module base address, plus the offset if given.
        """
        return SymbolOperations.parse_label(self.get_name(), function, offset)

    def get_label_at_address(self, address, offset = None):
        """
        Creates a label from the given memory address.

        If the address belongs to the module, the label is made relative to
        it's base address.

        @type  address: int
        @param address: Memory address.

        @type  offset: None or int
        @param offset: (Optional) Offset value.

        @rtype:  str
        @return: Label pointing to the given address.
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
        except WindowsError, e:
            pass

        # Parse the label and return it.
        return SymbolOperations.parse_label(module, function, offset)

    def is_address_here(self, address):
        """
        Tries to determine if the given address belongs to this module.

        @type  address: int
        @param address: Memory address.

        @rtype:  bool or None
        @return: C{True} if the address belongs to the module,
            C{False} if it doesn't,
            and C{None} if it can't be determined.
        """
        base = self.get_base()
        size = self.get_size()
        if base and size:
            return base <= address < (base + size)
        return None

    def resolve(self, function):
        """
        Resolves a function exported by this module.

        @type  function: str or int
        @param function:
            str: Name of the function.
            int: Ordinal of the function.

        @rtype:  int
        @return: Memory address of the exported function in the process.
            Returns None on error.
        """

        # Unknown DLL filename, there's nothing we can do.
        filename = self.get_filename()
        if not filename:
            return None

        # If the DLL is already mapped locally, resolve the function.
        try:
            hlib    = win32.GetModuleHandle(filename)
            address = win32.GetProcAddress(hlib, function)
        except WindowsError, e:

            # Load the DLL locally, resolve the function and unload it.
            try:
                hlib = win32.LoadLibraryEx(filename,
                                           win32.DONT_RESOLVE_DLL_REFERENCES)
                try:
                    address = win32.GetProcAddress(hlib, function)
                finally:
                    win32.FreeLibrary(hlib)
            except WindowsError, e:
                return None

        # A NULL pointer means the function was not found.
        if address == win32.NULL:
            return None

        # Compensate for DLL base relocations locally and remotely.
        return address - hlib + self.lpBaseOfDll

    def resolve_label(self, label):
        """
        Resolves a label for this module only. If the label refers to another
        module, an exception is raised.

        @type  label: str
        @param label: Label to resolve.

        @rtype:  int
        @return: Memory address pointed to by the label.

        @raise ValueError: The label is malformed or impossible to resolve.
        @raise RuntimeError: Cannot resolve the module or function.
        """

        # Split the label into it's components.
        # Use the fuzzy mode whenever possible.
        aProcess = self.get_process()
        if aProcess is not None:
            (module, procedure, offset) = aProcess.split_label(label)
        else:
            (module, procedure, offset) = Process.split_label(label)

        # If a module name is given that doesn't match ours,
        # raise an exception.
        if module and not self.match_name(module):
            raise RuntimeError, "Label does not belong to this module"

        # Resolve the procedure if given.
        if procedure:
            address = self.resolve(procedure)
            if address is None:

                # If it's a symbol, use the symbol.
                address = self.resolve_symbol(procedure)

                # If it's the keyword "start" use the entry point.
                if address is None and procedure == "start":
                    address = self.get_entry_point()

                # The procedure was not found.
                if address is None:
                    if not module:
                        module = self.get_name()
                    msg = "Can't find procedure %s in module %s"
                    msg = msg % (procedure, module)
                    raise RuntimeError, msg

        # If no procedure is given use the base address of the module.
        else:
            address = self.get_base()

        # Add the offset if given and return the resolved address.
        if offset:
            address = address + offset
        return address

#==============================================================================

class Thread (ThreadDebugOperations):
    """
    Interface to a thread in another process.

    @group Properties:
        get_tid, get_pid, get_process, get_exit_code, is_alive,
        get_name, set_name
    @group Instrumentation:
        suspend, resume, kill, wait
    @group Registers:
        get_context,
        get_register,
        get_flags, get_flag_value,
        get_pc, get_sp, get_fp,
        get_cf, get_df, get_sf, get_tf, get_zf,
        set_context,
        set_register,
        set_flags, set_flag_value,
        set_pc, set_sp, set_fp,
        set_cf, set_df, set_sf, set_tf, set_zf,
        clear_cf, clear_df, clear_sf, clear_tf, clear_zf,
        Flags
    @group Handle:
        get_handle, open_handle, close_handle

    @type dwThreadId: int
    @ivar dwThreadId: Global thread ID. Use L{get_tid} instead.

    @type hThread: L{ThreadHandle}
    @ivar hThread: Handle to the thread. Use L{get_handle} instead.

    @type process: L{Process}
    @ivar process: Parent process object. Use L{get_process} instead.

    @type pInjectedMemory: int
    @ivar pInjectedMemory: If the thread was created by L{Process.inject_code},
        this member contains a pointer to the memory buffer for the injected
        code. Otherwise it's C{None}.

        The L{kill} method uses this member to free the buffer
        when the injected thread is killed.
    """

    def __init__(self, dwThreadId, hThread = None, process = None):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global thread ID.

        @type  hThread: L{ThreadHandle}
        @param hThread: (Optional) Handle to the thread.

        @type  process: L{Process}
        @param process: (Optional) Parent Process object.
        """
        super(Thread, self).__init__()
        self.dwProcessId     = None
        self.dwThreadId      = dwThreadId
        self.hThread         = hThread
        self.pInjectedMemory = None
        self.process         = process
        self.set_name()
        if process is not None and not isinstance(process, Process):
            msg  = "Parent process for Thread must be a Process instance, "
            msg += "got %s instead" % type(process)
            raise TypeError, msg

    def get_process(self):
        """
        @rtype:  L{Process}
        @return: Parent Process object.
        """
        if self.process is None:
            self.process = Process(self.get_pid())
        return self.process

    def get_pid(self):
        """
        @rtype:  int
        @return: Parent process global ID.

        @raise WindowsError: An error occured when calling a Win32 API function.
        @raise RuntimeError: The parent process ID can't be found.
        """
        if self.dwProcessId is None:
            if self.process is None:
                hProcess = self.get_handle()
                try:
                    # I wish this had been implemented before Vista...
                    self.dwProcessId = win32.GetProcessIdOfThread(hProcess)
                except AttributeError:
                    # This method really sucks :P
                    self.dwProcessId = self.__get_pid_by_scanning()
            else:
                self.dwProcessId = self.process.get_pid()
        return self.dwProcessId

    def __get_pid_by_scanning(self):
        'Internally used by get_pid().'
        dwProcessId = None
        dwThreadId = self.get_tid()
        hSnapshot = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPTHREAD)
        try:
            te = win32.Thread32First(hSnapshot)
            while te is not None:
                if te.th32ThreadID == dwThreadId:
                    dwProcessId = te.th32OwnerProcessID
                    break
                te = win32.Thread32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        if dwProcessId is None:
            msg = "Cannot find thread ID %d in any process" % dwThreadId
            raise RuntimeError, msg
        return dwProcessId

    def get_tid(self):
        """
        @rtype:  int
        @return: Thread global ID.
        """
        return self.dwThreadId

    def get_name(self):
        """
        @rtype:  str
        @return: Thread name, or C{None} if the thread is nameless.
        """
        return self.name

    def set_name(self, name = None):
        """
        Sets the thread's name.

        @type  name: str
        @param name: Thread name, or C{None} if the thread is nameless.
        """
        self.name = name

#------------------------------------------------------------------------------

    def open_handle(self, dwDesiredAccess = win32.PROCESS_ALL_ACCESS):
        """
        Opens a new handle to the thread.
        """
        hThread = win32.OpenThread(dwDesiredAccess, win32.FALSE, self.dwThreadId)
        try:
            self.close_handle()
        finally:
            self.hThread = hThread

    def close_handle(self):
        """
        Closes the handle to the thread.
        """
        try:
            if hasattr(self.hThread, 'close'):
                self.hThread.close()
            elif self.hThread not in (None, win32.INVALID_HANDLE_VALUE):
                win32.CloseHandle(self.hThread)
        finally:
            self.hThread = None

    def get_handle(self):
        """
        @rtype:  ThreadHandle
        @return: Handle to the thread.
        """
        if self.hThread in (None, win32.INVALID_HANDLE_VALUE):
            self.open_handle()
        return self.hThread

#------------------------------------------------------------------------------

    def wait(self, dwTimeout = None):
        """
        Waits for the thread to finish executing.

        @type  dwTimeout: int
        @param dwTimeout: (Optional) Timeout value in milliseconds.
            Use C{INFINITE} or C{None} for no timeout.
        """
        self.get_handle().wait(dwTimeout)

    def kill(self, dwExitCode = 0):
        """
        Terminates the thread execution.

        @note: If the C{lpInjectedMemory} member contains a valid pointer,
        the memory is freed.

        @type  dwExitCode: int
        @param dwExitCode: (Optional) Thread exit code.
        """
        win32.TerminateThread(self.get_handle(), dwExitCode)
        if self.pInjectedMemory is not None:
            try:
                self.get_process().free(self.pInjectedMemory)
                self.pInjectedMemory = None
            except Exception:
                pass
##                raise           # XXX DEBUG

    def suspend(self):
        """
        Suspends the thread execution.

        @rtype:  int
        @return: Suspend count. If zero, the thread is running.
        """
        return win32.SuspendThread(self.get_handle())

    def resume(self):
        """
        Resumes the thread execution.

        @rtype:  int
        @return: Suspend count. If zero, the thread is running.
        """
        return win32.ResumeThread(self.get_handle())

    def is_alive(self):
        """
        @rtype:  bool
        @return: C{True} if the thread if currently running.
        """
        try:
            hProcess = self.get_handle()
        except WindowsError:
            return False
        try:
            hProcess.wait(0)
        except WindowsError:
            return False
        return True

    def get_exit_code(self):
        """
        @rtype:  int
        @return: Thread exit code, or C{STILL_ACTIVE} if it's still alive.
        """
        return win32.GetExitCodeThread(self.get_handle())

#------------------------------------------------------------------------------

    def get_windows(self):
        try:
            process = self.get_process()
        except Exception:
            process = None
        return [
                Window( hWnd, process, self ) \
                for hWnd in win32.EnumThreadWindows( self.get_tid() )
                ]

#------------------------------------------------------------------------------

    # TODO
    # A registers cache could be implemented here.
    def get_context(self, ContextFlags = win32.CONTEXT_ALL):
        """
        @rtype:  dict( str S{->} int )
        @return: Dictionary mapping register names to their values.

        @see: L{set_context}
        """
        # Threads can't be suspended when the exit process event arrives.
        # Funny thing is, you can still get the context. (?)
        try:
            self.suspend()
            bSuspended = True
        except WindowsError:
            bSuspended = False
        try:
            return win32.GetThreadContext(self.get_handle(), ContextFlags)
        finally:
            if bSuspended:
                self.resume()

    def set_context(self, context):
        """
        Sets the values of the registers.

        @see: L{get_context}

        @type  context:  dict( str S{->} int )
        @param context: Dictionary mapping register names to their values.
        """
        self.suspend()
        try:
            win32.SetThreadContext(self.get_handle(), context)
        finally:
            self.resume()

    def get_pc(self):
        """
        @rtype:  int
        @return: Value of the program counter register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        return context['Eip']

    def set_pc(self, pc):
        """
        Sets the value of the program counter register.

        @type  pc: int
        @param pc: Value of the program counter register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        context['Eip'] = pc
        self.set_context(context)

    def get_sp(self):
        """
        @rtype:  int
        @return: Value of the stack pointer register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        return context['Esp']

    def set_sp(self, sp):
        """
        Sets the value of the stack pointer register.

        @type  sp: int
        @param sp: Value of the stack pointer register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        context['Esp'] = sp
        self.set_context(context)

    def get_fp(self):
        """
        @rtype:  int
        @return: Value of the frame pointer register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        return context['Ebp']

    def set_fp(self, fp):
        """
        Sets the value of the frame pointer register.

        @type  fp: int
        @param fp: Value of the frame pointer register.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        context['Ebp'] = fp
        self.set_context(context)

    def get_register(self, register):
        """
        @type  register: str
        @param register: Register name.

        @rtype:  int
        @return: Value of the requested register.
        """
        'Returns the value of a specific register.'
        context = self.get_context()
        return context[register]

    def set_register(self, register, value):
        """
        Sets the value of a specific register.

        @type  register: str
        @param register: Register name.

        @rtype:  int
        @return: Register value.
        """
        context = self.get_context()
        context[register] = value
        self.set_context(context)

#------------------------------------------------------------------------------

    class Flags (object):
        'Commonly used processor flags'
        Overflow    = 0x800
        Direction   = 0x400
        Interrupts  = 0x200
        Trap        = 0x100
        Sign        = 0x80
        Zero        = 0x40
        # 0x20 ???
        Auxiliary   = 0x10
        # 0x8 ???
        Parity      = 0x4
        # 0x2 ???
        Carry       = 0x1

    def get_flags(self, FlagMask = 0xFFFFFFFF):
        """
        @type  FlagMask: int
        @param FlagMask: (Optional) Bitwise-AND mask.

        @rtype:  int
        @return: Flags register contents, optionally masking out some bits.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        return context['EFlags'] & FlagMask

    def set_flags(self, eflags, FlagMask = 0xFFFFFFFF):
        """
        Sets the flags register, optionally masking some bits.

        @type  eflags: int
        @param eflags: Flags register contents.

        @type  FlagMask: int
        @param FlagMask: (Optional) Bitwise-AND mask.
        """
        context = self.get_context(win32.CONTEXT_CONTROL)
        context['EFlags'] = (context['EFlags'] & FlagMask) | eflags
        self.set_context(context)

    def get_flag_value(self, FlagBit):
        """
        @type  FlagBit: int
        @param FlagBit: One of the L{Flags}.

        @rtype:  bool
        @return: Boolean value of the requested flag.
        """
        return bool( self.get_flags(FlagBit) )

    def set_flag_value(self, FlagBit, FlagValue):
        """
        Sets a single flag, leaving the others intact.

        @type  FlagBit: int
        @param FlagBit: One of the L{Flags}.

        @type  FlagValue: bool
        @param FlagValue: Boolean value of the flag.
        """
        if FlagValue:
            eflags = FlagBit
        else:
            eflags = 0
        FlagMask = 0xFFFFFFFF ^ FlagBit
        self.set_flags(eflags, FlagMask)

    def get_zf(self):
        """
        @rtype:  bool
        @return: Boolean value of the Zero flag.
        """
        return self.get_flag_value(self.Flags.Zero)

    def get_cf(self):
        """
        @rtype:  bool
        @return: Boolean value of the Carry flag.
        """
        return self.get_flag_value(self.Flags.Carry)

    def get_sf(self):
        """
        @rtype:  bool
        @return: Boolean value of the Sign flag.
        """
        return self.get_flag_value(self.Flags.Sign)

    def get_df(self):
        """
        @rtype:  bool
        @return: Boolean value of the Direction flag.
        """
        return self.get_flag_value(self.Flags.Direction)

    def get_tf(self):
        """
        @rtype:  bool
        @return: Boolean value of the Trap flag.
        """
        return self.get_flag_value(self.Flags.Trap)

    def clear_zf(self):
        'Clears the Zero flag.'
        self.set_flag_value(self.Flags.Zero, False)

    def clear_cf(self):
        'Clears the Carry flag.'
        self.set_flag_value(self.Flags.Carry, False)

    def clear_sf(self):
        'Clears the Sign flag.'
        self.set_flag_value(self.Flags.Sign, False)

    def clear_df(self):
        'Clears the Direction flag.'
        self.set_flag_value(self.Flags.Direction, False)

    def clear_tf(self):
        'Clears the Trap flag.'
        self.set_flag_value(self.Flags.Trap, False)

    def set_zf(self):
        'Sets the Zero flag.'
        self.set_flag_value(self.Flags.Zero, True)

    def set_cf(self):
        'Sets the Carry flag.'
        self.set_flag_value(self.Flags.Carry, True)

    def set_sf(self):
        'Sets the Sign flag.'
        self.set_flag_value(self.Flags.Sign, True)

    def set_df(self):
        'Sets the Direction flag.'
        self.set_flag_value(self.Flags.Direction, True)

    def set_tf(self):
        'Sets the Trap flag.'
        self.set_flag_value(self.Flags.Trap, True)

#==============================================================================

class Process (MemoryOperations, ProcessDebugOperations, SymbolOperations, \
                                          ThreadContainer, ModuleContainer):
    """
    Interface to a process. Contains threads and modules snapshots.

    @group Properties:
        get_pid, get_filename, get_exit_code,
        is_alive, is_debugged

    @group Instrumentation:
        kill, wait, suspend, resume, inject_code, inject_dll

    @group Processes snapshot:
        scan, clear, __contains__, __iter__, __len__

    @group Handle:
        get_handle, open_handle, close_handle

    @type dwProcessId: int
    @ivar dwProcessId: Global process ID. Use L{get_pid} instead.

    @type hProcess: L{ProcessHandle}
    @ivar hProcess: Handle to the process. Use L{get_handle} instead.

    @type fileName: str
    @ivar fileName: Filename of the main module. Use L{get_filename} instead.
    """

    def __init__(self, dwProcessId, hProcess = None, fileName = None):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global process ID.

        @type  hProcess: L{ProcessHandle}
        @param hProcess: Handle to the process.

        @type  fileName: str
        @param fileName: (Optional) Filename of the main module.
        """
        MemoryOperations.__init__(self)
        ProcessDebugOperations.__init__(self)
        SymbolOperations.__init__(self)
        ThreadContainer.__init__(self)
        ModuleContainer.__init__(self)

        self.dwProcessId = dwProcessId
        self.hProcess    = hProcess
        self.fileName    = fileName

    def get_pid(self):
        """
        @rtype:  int
        @return: Process global ID.
        """
        return self.dwProcessId

    def get_filename(self):
        """
        @rtype:  str
        @return: Filename of the main module of the process.
        """
        if not self.fileName:
            self.fileName = self.get_image_name()
        return self.fileName

    def open_handle(self):
        """
        Opens a new handle to the process.
        """
        hProcess = win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE,
                                                              self.dwProcessId)
        try:
            self.close_handle()
        finally:
            self.hProcess = hProcess

    def close_handle(self):
        """
        Closes the handle to the process.
        """
        try:
            if hasattr(self.hProcess, 'close'):
                self.hProcess.close()
            elif self.hProcess not in (None, win32.INVALID_HANDLE_VALUE):
                win32.CloseHandle(self.hProcess)
        finally:
            self.hProcess = None

    def get_handle(self):
        """
        @rtype:  L{ProcessHandle}
        @return: Handle to the process.
        """
        if self.hProcess in (None, win32.INVALID_HANDLE_VALUE):
            self.open_handle()
        return self.hProcess

#------------------------------------------------------------------------------

    def __contains__(self, anObject):
        """
        The same as: C{self.has_thread(anObject) or self.has_module(anObject)}

        @type  anObject: L{Thread}, L{Module} or int
        @param anObject: Object to look for.
            Can be a Thread, Module, thread global ID or module base address.

        @rtype:  bool
        @return: C{True} if the requested object was found in the snapshot.
        """
        return ThreadContainer.__contains__(self, anObject) or \
               ModuleContainer.__contains__(self, anObject)

    def __len__(self):
        """
        @see:    L{get_thread_count}, L{get_module_count}
        @rtype:  int
        @return: Count of L{Thread} and L{Module} objects in this snapshot.
        """
        return ThreadContainer.__len__(self) + \
               ModuleContainer.__len__(self)

    class __ThreadsAndModulesIterator (object):
        """
        Iterator object for L{Process} objects.
        Iterates through L{Thread} objects first, L{Module} objects next.
        """

        def __init__(self, container):
            """
            @type  container: L{Process}
            @param container: L{Thread} and L{Module} container.
            """
            self.__container = container
            self.__iterator  = None
            self.__state     = 0

        def next(self):
            'x.next() -> the next value, or raise StopIteration'
            if self.__state == 0:
                self.__iterator = self.__container.iter_threads()
                self.__state    = 1
            if self.__state == 1:
                try:
                    return self.__iterator.next()
                except StopIteration:
                    self.__iterator = self.__container.iter_modules()
                    self.__state    = 2
            if self.__state == 2:
                try:
                    return self.__iterator.next()
                except StopIteration:
                    self.__iterator = None
                    self.__state    = 3
            raise StopIteration

    def __iter__(self):
        """
        @see:    L{iter_threads}, L{iter_modules}
        @rtype:  iterator
        @return: Iterator of L{Thread} and L{Module} objects in this snapshot.
            All threads are iterated first, then all modules.
        """
        return self.__ThreadsAndModulesIterator(self)

#------------------------------------------------------------------------------

    def wait(self, dwTimeout = None):
        """
        Waits for the process to finish executing.

        @raise WindowsError: On error an exception is raised.
        """
        self.get_handle().wait(dwTimeout)

    def kill(self, dwExitCode = 0):
        """
        Terminates the execution of the process.

        @raise WindowsError: On error an exception is raised.
        """
        win32.TerminateProcess(self.get_handle(), dwExitCode)

    def suspend(self):
        """
        Suspends execution on all threads of the process.

        @raise WindowsError: On error an exception is raised.
        """
        if self.get_thread_count() == 0:
            self.scan_threads()
        suspended = list()
        try:
            for aThread in self.iter_threads():
                aThread.suspend()
                suspended.append(aThread)
        except Exception:
            for aThread in suspended:
                try:
                    aThread.resume()
                except Exception:
                    pass
            raise

    def resume(self):
        """
        Resumes execution on all threads of the process.

        @raise WindowsError: On error an exception is raised.
        """
        if self.get_thread_count() == 0:
            self.scan_threads()
        resumed = list()
        try:
            for aThread in self.iter_threads():
                aThread.resume()
                resumed.append(aThread)
        except Exception:
            for aThread in resumed:
                try:
                    aThread.suspend()
                except Exception:
                    pass
            raise

    def is_debugged(self):
        """
        Tries to determine if the process is being debugged by another process.
        It may detect other debuggers besides WinAppDbg.

        @rtype:  bool
        @return: C{True} if the process has a debugger attached.

        @warning:
            May return inaccurate results when some anti-debug techniques are
            used by the target process.

        @note: To know if a process currently being debugged by a L{Debug}
            object, call L{Debug.is_debugee} instead.
        """
        return win32.CheckRemoteDebuggerPresent(self.get_handle())

    def is_alive(self):
        """
        @rtype:  bool
        @return: C{True} if the process is currently running.
        """
        try:
            self.wait(0)
        except WindowsError, e:
            return e.winerror == win32.WAIT_TIMEOUT
        return False

    def get_exit_code(self):
        """
        @rtype:  int
        @return: Process exit code, or C{STILL_ACTIVE} if it's still alive.

        @warning: If a process returns C{STILL_ACTIVE} as it's exit code,
            you may not be able to determine if it's active or not with this
            method. Use L{is_alive} to check if the process is still active.
            Alternatively you can call L{get_handle} to get the handle object
            and then L{ProcessHandle.wait} on it to wait until the process
            finishes running.
        """
        return win32.GetExitCodeProcess(self.get_handle())

#------------------------------------------------------------------------------

    def scan(self):
        """
        Populates the snapshot of threads and modules.
        """
        self.scan_threads()
        self.scan_modules()

    def clear(self):
        """
        Clears the snapshot of threads and modules.
        """
        self.clear_threads()
        self.clear_modules()

#------------------------------------------------------------------------------

    def get_windows(self):
        window_list = list()
        for thread in self.iter_threads():
            window_list.extend( thread.get_windows() )
        return window_list

#------------------------------------------------------------------------------

    def inject_code(self, payload, lpParameter = 0):
        """
        Injects relocatable code into the process memory and executes it.

        @see: L{inject_dll}

        @type  payload: str
        @param payload: Relocatable code to run in a new thread.

        @type  lpParameter: int
        @param lpParameter: (Optional) Parameter to be pushed in the stack.

        @rtype:  tuple( L{Thread}, int )
        @return: The injected Thread object
            and the memory address where the code was written.

        @raise WindowsError: An exception is raised on error.
        """

        # Uncomment for debugging...
##        payload = '\xCC' + payload

        # Allocate the memory for the shellcode.
        lpStartAddress = self.malloc(len(payload))

        # Catch exceptions so we can free the memory on error.
        try:

            # Write the shellcode to our memory location.
            self.write(lpStartAddress, payload)

            # Start a new thread for the shellcode to run.
            aThread = self.start_thread(lpStartAddress, lpParameter,
                                                            bSuspended = False)

            # Remember the shellcode address.
            #  It will be freed ONLY by the Thread.kill() method
            #  and the EventHandler class, otherwise you'll have to
            #  free it in your code, or have your shellcode clean up
            #  after itself (recommended).
            aThread.pInjectedMemory = lpStartAddress

        # Free the memory on error.
        except Exception, e:
            self.free(lpStartAddress)
            raise

        # Return the Thread object and the shellcode address.
        return aThread, lpStartAddress

    # TODO
    # The shellcode should check for errors, otherwise it just crashes
    # when the DLL can't be loaded or the procedure can't be found.
    # On error the shellcode should execute an int3 instruction.
    def inject_dll(self, dllname, procname = None, lpParameter = 0,
                                               bWait = True, dwTimeout = None):
        """
        Injects a DLL into the process memory.

        @warning: Setting C{bWait} to C{True} when the process is frozen by a
            debug event will cause a deadlock in your debugger.

        @see: L{inject_code}

        @type  dllname: str
        @param dllname: Name of the DLL module to load.

        @type  procname: str
        @param procname: (Optional) Procedure to call when the DLL is loaded.

        @type  lpParameter: int
        @param lpParameter: (Optional) Parameter to the C{procname} procedure.

        @type  bWait: bool
        @param bWait: C{True} to wait for the process to finish.
            C{False} to return immediately.

        @type  dwTimeout: int
        @param dwTimeout: (Optional) Timeout value in milliseconds.
            Ignored if C{bWait} is C{False}.

        @raise WindowsError: An exception is raised on error.
        """

        # Resolve kernel32.dll
        aModule = self.get_module_by_name('kernel32.dll')
        if aModule is None:
            self.scan_modules()
            aModule = self.get_module_by_name('kernel32.dll')
        if aModule is None:
            raise RuntimeError, \
                            "Cannot resolve kernel32.dll in the remote process"

        # Resolve kernel32.dll!LoadLibraryA
        pllib = aModule.resolve('LoadLibraryA')
        if not pllib:
            raise RuntimeError, \
                "Cannot resolve kernel32.dll!LoadLibraryA in the remote process"

        # Resolve kernel32.dll!GetProcAddress
        pgpad = aModule.resolve('GetProcAddress')
        if not pgpad:
            raise RuntimeError, \
             "Cannot resolve kernel32.dll!GetProcAddress in the remote process"

        # Resolve kernel32.dll!VirtualFree
        pvf = aModule.resolve('VirtualFree')
        if not pvf:
            raise RuntimeError, \
             "Cannot resolve kernel32.dll!VirtualFree in the remote process"

        # Shellcode follows...
        code  = ''

        # push dllname
        code += '\xe8' + struct.pack('<L', len(dllname) + 1) + dllname + '\0'

        # mov eax, LoadLibraryA
        code += '\xb8' + struct.pack('<L', pllib)

        # call eax
        code += '\xff\xd0'

        if procname:

            # push procname
            code += '\xe8' + struct.pack('<L', len(procname) + 1)
            code += procname + '\0'

            # push eax
            code += '\x50'

            # mov eax, GetProcAddress
            code += '\xb8' + struct.pack('<L', pgpad)

            # call eax
            code += '\xff\xd0'

            # mov ebp, esp      ; preserve stack pointer
            code += '\x8b\xec'

            # push lpParameter
            code += '\x68' + struct.pack('<L', lpParameter)

            # call eax
            code += '\xff\xd0'

            # mov esp, ebp      ; restore stack pointer
            code += '\x8b\xe5'

        # pop edx       ; our own return address
        code += '\x5a'

        # push MEM_RELEASE  ; dwFreeType
        code += '\x68' + struct.pack('<L', win32.MEM_RELEASE)

        # push 0x1000       ; dwSize, shellcode max size 4096 bytes
        code += '\x68' + struct.pack('<L', 0x1000)

        # call $+5
        code += '\xe8\x00\x00\x00\x00'

        # and dword ptr [esp], 0xFFFFF000   ; align to page boundary
        code += '\x81\x24\x24\x00\xf0\xff\xff'

        # mov eax, VirtualFree
        code += '\xb8' + struct.pack('<L', pvf)

        # push edx      ; our own return address
        code += '\x52'

        # jmp eax   ; VirtualFree will return to our own return address
        code += '\xff\xe0'

        # Inject the shellcode.
        aThread, lpStartAddress = self.inject_code(code, lpParameter)

        # There's no need to free the memory,
        # because the shellcode will free it itself.
        aThread.pInjectedMemory = None

        # Wait for the thread to finish.
        if bWait:
            aThread.wait(dwTimeout)

    def clean_exit(self, dwExitCode = 0, bWait = False, dwTimeout = None):
        """
        Injects a new thread to call ExitProcess().
        Optionally waits for the injected thread to finish.

        @warning: Setting C{bWait} to C{True} when the process is frozen by a
            debug event will cause a deadlock in your debugger.

        @type  dwExitCode: int
        @param dwExitCode: Process exit code.

        @type  bWait: bool
        @param bWait: C{True} to wait for the process to finish.
            C{False} to return immediately.

        @type  dwTimeout: int
        @param dwTimeout: (Optional) Timeout value in milliseconds.
            Ignored if C{bWait} is C{False}.

        @raise WindowsError: An exception is raised on error.
        """
        if not dwExitCode:
            dwExitCode = 0
        pExitProcess = self.resolve_label('kernel32!ExitProcess')
        aThread = self.start_thread(pExitProcess, dwExitCode)
        if bWait:
            aThread.wait(dwTimeout)

#------------------------------------------------------------------------------

    def notify_create_process(self, event):
        """
        Notify the creation of a new process.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.
        """
        # Do not use super() here.
        bCallHandler = ThreadContainer.notify_create_process(self, event)
        bCallHandler = bCallHandler and \
                             ModuleContainer.notify_create_process(self, event)
        return bCallHandler

#==============================================================================

class System (ProcessContainer):
    """
    Interface to a batch of processes, plus some system wide settings.
    Contains a snapshot of processes.

    @group Global settings:
        pageSize,
        set_kill_on_exit_mode, request_debug_privileges,
        enable_step_on_branch_mode, set_symbol_options

    @type pageSize: int
    @cvar pageSize: Page size in bytes. Defaults to 0x1000 but it's
        automatically updated on runtime when importing the module.
    """

    # Try to get the pageSize value on runtime,
    # ignoring exceptions on failure.
    try:
        pageSize = win32.GetSystemInfo().dwPageSize
    except WindowsError:
        pageSize = 0x1000

#------------------------------------------------------------------------------

    @staticmethod
    def request_debug_privileges(bIgnoreExceptions = False):
        """
        Requests debug privileges.

        This may be needed to debug processes running as SYSTEM
        (such as services) since Windows XP.
        """
        try:
            privs  = (
                        (win32.SE_DEBUG_NAME, True),
                     )
            hToken = win32.OpenProcessToken(win32.GetCurrentProcess(),
                                                 win32.TOKEN_ADJUST_PRIVILEGES)
            try:
                win32.AdjustTokenPrivileges(hToken, privs)
            finally:
                win32.CloseHandle(hToken)
            return True
        except Exception, e:
            if not bIgnoreExceptions:
                raise
        return False

    @staticmethod
    def set_kill_on_exit_mode(bKillOnExit = False):
        """
        Automatically detach from processes when the current thread dies.

        Works on the following platforms:

         - Microsoft Windows XP and above.
         - Wine (Windows Emulator).

        Fails on the following platforms:

         - Microsoft Windows 2000 and below.
         - ReactOS.

        @type  bKillOnExit: bool
        @param bKillOnExit: C{True} to automatically kill processes when the
            debugger thread dies. C{False} to automatically detach from
            processes when the debugger thread dies.

        @rtype:  bool
        @return: C{True} on success, C{False} on error.
        """
        try:
            # won't work before calling CreateProcess or DebugActiveProcess
            # http://msdn.microsoft.com/en-us/library/ms679307.aspx
            win32.DebugSetProcessKillOnExit(bKillOnExit)
            return True
        except (AttributeError, WindowsError):
            pass
        return False

    @staticmethod
    def enable_step_on_branch_mode():
        """
        When tracing, call this on every single step event
        for step on branch mode.

        @warning:
            This has a HARDCODED value for a machine specific register (MSR).
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.
        """
        msr         = win32.SYSDBG_MSR()
        msr.Address = 0x1D9
        msr.Data    = 2
        return win32.NtSystemDebugControl(win32.SysDbgWriteMsr, msr,
                                          ctypes.sizeof(win32.SYSDBG_MSR),
                                          win32.NULL, win32.NULL, win32.NULL)

    @staticmethod
    def set_symbol_options(options = None):
        """
        Set the options for the symbol support (dbghelp.dll).

        @type  options: int
        @param options: Option flags. Use C{None} for the default
            options in WinAppDbg.
        """
        if options is None:
            options  = win32.SYMOPT_FAIL_CRITICAL_ERRORS
            options |= win32.SYMOPT_FAVOR_COMPRESSED
            options |= win32.SYMOPT_INCLUDE_32BIT_MODULES
            options |= win32.SYMOPT_NO_PROMPTS
            options |= win32.SYMOPT_UNDNAME
            options |= win32.SYMOPT_LOAD_LINES
        return win32.SymSetOptions(options)
