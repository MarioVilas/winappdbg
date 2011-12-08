#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2011, Mario Vilas
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

@group Instrumentation:
    System, Process, Thread, Module, Window

@group Capabilities (private):
    ModuleContainer, ThreadContainer, ProcessContainer, SymbolContainer,
    ThreadDebugOperations, ProcessDebugOperations,
    MemoryOperations, SymbolOperations, SymbolEnumerator
"""

# FIXME
# I've been told the host process for the latest versions of VMWare
# can't be instrumented, because they try to stop code injection into the VMs.
# The solution appears to be to run the debugger from a user account that
# belongs to the VMware group. I haven't confirmed this yet.

__revision__ = "$Id$"

__all__ =   [
                # Instrumentation classes.
                'System',
                'Process',
                'Thread',
                'Module',
                'Window',
            ]

import win32
import win32.version
from textio import HexInput, HexDump
from util import Regenerator, PathOperations, MemoryAddresses, DebugRegister
from registry import Registry

import re
import os
import sys
import ctypes
import struct
##import weakref

try:
    from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
except ImportError:
    try:
        from distorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
    except ImportError:
        Decode16Bits = None
        Decode32Bits = None
        Decode64Bits = None
        def Decode(*argv, **argd):
            "PLEASE INSTALL DISTORM BEFORE GENERATING THE DOCUMENTATION"
            msg = ("diStorm is not installed or can't be found. "
            "Download it from: http://code.google.com/p/distorm3")
            raise NotImplementedError(msg)

try:
    from psyco.classes import *
except ImportError:
    pass

#==============================================================================

# TODO
# An alternative approach to the toolhelp32 snapshots: parsing the PEB and
# fetching the list of loaded modules from there. That would solve the problem
# of toolhelp32 not working when the process hasn't finished initializing.
# See: http://pferrie.host22.com/misc/lowlevel3.htm

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

    def __initialize_snapshot(self):
        """
        Private method to automatically initialize the snapshot
        when you try to use it without calling any of the scan_*
        methods first. You don't need to call this yourself.
        """
        if not self.__moduleDict:
            self.scan_modules()

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
        self.__initialize_snapshot()
        return lpBaseOfDll in self.__moduleDict

    def get_module(self, lpBaseOfDll):
        """
        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Base address of the DLL to look for.

        @rtype:  L{Module}
        @return: Module object with the given base address.
        """
        self.__initialize_snapshot()
        if lpBaseOfDll not in self.__moduleDict:
            msg = "Unknown DLL base address %s"
            msg = msg % HexDump.address(lpBaseOfDll)
            raise KeyError(msg)
        return self.__moduleDict[lpBaseOfDll]

    def iter_module_addresses(self):
        """
        @see:    L{iter_modules}
        @rtype:  dictionary-keyiterator
        @return: Iterator of DLL base addresses in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__moduleDict.iterkeys()

    def iter_modules(self):
        """
        @see:    L{iter_module_addresses}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Module} objects in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__moduleDict.itervalues()

    def get_module_bases(self):
        """
        @see:    L{iter_module_addresses}
        @rtype:  list( int... )
        @return: List of DLL base addresses in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__moduleDict.keys()

    def get_module_count(self):
        """
        @rtype:  int
        @return: Count of L{Module} objects in this snapshot.
        """
        self.__initialize_snapshot()
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
        @type  address: int
        @param address: Memory address to query.

        @rtype:  L{Module}
        @return: C{Module} object that best matches the given address.
            Returns C{None} if no C{Module} can be found.
        """
        bases = self.get_module_bases()
        bases.sort()
##        bases.append(0x100000000)   # invalid, > 4 gb. address space
        bases.append(0x1000000000000000)    # invalid, > 64 bit address
        if address >= bases[0]:
            i = 0
            max_i = len(bases) - 1  # -1 because last base is fake
            while i < max_i:
                begin, end = bases[i:i+2]
                if begin <= address <= end:
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
        hSnapshot   = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPMODULE, \
                                                                   dwProcessId)
        try:
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
                if not self.__moduleDict.has_key(lpBaseAddress):
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
        finally:
            win32.CloseHandle(hSnapshot)
##        for base in self.get_module_bases(): # XXX triggers a scan
        for base in self.__moduleDict.keys():
            if base not in found_bases:
                self._del_module(base)

    def clear_modules(self):
        """
        Clears the modules snapshot.
        """
        self.__moduleDict = dict()

#------------------------------------------------------------------------------

    # XXX notify_* methods should not trigger a scan

    def _add_module(self, aModule):
        """
        Private method to add a module object to the snapshot.

        @type  aModule: L{Module}
        @param aModule: Module object.
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
        self.__moduleDict[lpBaseOfDll] = aModule

    def _del_module(self, lpBaseOfDll):
        """
        Private method to remove a module object from the snapshot.

        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Module base address.
        """
##        if lpBaseOfDll not in self.__moduleDict:
##            msg = "Unknown base address %d" % lpBaseOfDll
##            raise KeyError(msg)
        self.__moduleDict[lpBaseOfDll].hFile   = None    # handle
        self.__moduleDict[lpBaseOfDll].process = None    # circular reference
        del self.__moduleDict[lpBaseOfDll]

    def __add_loaded_module(self, event):
        """
        Private method to automatically add new module objects from debug events.

        @type  event: L{Event}
        @param event: Event object.
        """
        lpBaseOfDll = event.get_module_base()
        hFile       = event.get_file_handle()
##        if not self.has_module(lpBaseOfDll):  # XXX this would trigger a scan
        if not self.__moduleDict.has_key(lpBaseOfDll):
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

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        self.__add_loaded_module(event)
        return True

    def notify_load_dll(self, event):
        """
        Notify the load of a new module.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{LoadDLLEvent}
        @param event: Load DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        self.__add_loaded_module(event)
        return True

    def notify_unload_dll(self, event):
        """
        Notify the release of a loaded module.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{UnloadDLLEvent}
        @param event: Unload DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        lpBaseOfDll = event.get_module_base()
##        if self.has_module(lpBaseOfDll):  # XXX this would trigger a scan
        if self.__moduleDict.has_key(lpBaseOfDll):
            self._del_module(lpBaseOfDll)
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
        find_threads_by_name, get_windows,
        clear_threads, clear_dead_threads, close_thread_handles

    @group Event notifications (private):
        notify_create_process,
        notify_create_thread,
        notify_exit_thread
    """

    def __init__(self):
        super(ThreadContainer, self).__init__()
        self.__threadDict = dict()

    def __initialize_snapshot(self):
        """
        Private method to automatically initialize the snapshot
        when you try to use it without calling any of the scan_*
        methods first. You don't need to call this yourself.
        """
        if not self.__threadDict:
            self.scan_threads()

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

    def has_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Thread} object with the given global ID.
        """
        self.__initialize_snapshot()
        return dwThreadId in self.__threadDict

    def get_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.

        @rtype:  L{Thread}
        @return: Thread object with the given global ID.
        """
        self.__initialize_snapshot()
        if dwThreadId not in self.__threadDict:
            msg = "Unknown thread ID: %d" % dwThreadId
            raise KeyError(msg)
        return self.__threadDict[dwThreadId]

    def iter_thread_ids(self):
        """
        @see:    L{iter_threads}
        @rtype:  dictionary-keyiterator
        @return: Iterator of global thread IDs in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__threadDict.iterkeys()

    def iter_threads(self):
        """
        @see:    L{iter_thread_ids}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Thread} objects in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__threadDict.itervalues()

    def get_thread_ids(self):
        """
        @rtype:  list( int )
        @return: List of global thread IDs in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__threadDict.keys()

    def get_thread_count(self):
        """
        @rtype:  int
        @return: Count of L{Thread} objects in this snapshot.
        """
        self.__initialize_snapshot()
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

    # XXX TODO
    # Support for string searches on the window captions.

    def get_windows(self):
        """
        @rtype:  list of L{Window}
        @return: Returns a list of windows handled by this process.
        """
        window_list = list()
        for thread in self.iter_threads():
            window_list.extend( thread.get_windows() )
        return window_list

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
        self._add_thread(aThread)
        return aThread

#------------------------------------------------------------------------------

    # TODO
    # maybe put all the toolhelp code into their own set of classes?
    #
    # XXX this method musn't end up calling __initialize_snapshot by accident!
    def scan_threads(self):
        """
        Populates the snapshot with running threads.
        """

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

##        dead_tids   = set( self.get_thread_ids() ) # XXX triggers a scan
        dead_tids   = self._get_thread_ids()
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
##                    if not self.has_thread(dwThreadId): # XXX triggers a scan
                    if not self._has_thread_id(dwThreadId):
                        aThread = Thread(dwThreadId, process = self)
                        self._add_thread(aThread)
                te = win32.Thread32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        for tid in dead_tids:
            self._del_thread(tid)

    def clear_dead_threads(self):
        """
        Remove Thread objects from the snapshot
        referring to threads no longer running.
        """
        for tid in self.get_thread_ids():
            aThread = self.get_thread(tid)
            if not aThread.is_alive():
                self._del_thread(aThread)

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

    # XXX notify_* methods should not trigger a scan

    def _add_thread(self, aThread):
        """
        Private method to add a thread object to the snapshot.

        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
##        if not isinstance(aThread, Thread):
##            if hasattr(aThread, '__class__'):
##                typename = aThread.__class__.__name__
##            else:
##                typename = str(type(aThread))
##            msg = "Expected Thread, got %s instead" % typename
##            raise TypeError(msg)
        dwThreadId = aThread.dwThreadId
##        if dwThreadId in self.__threadDict:
##            msg = "Already have a Thread object with ID %d" % dwThreadId
##            raise KeyError(msg)
        aThread.dwProcessId = self.get_pid()
        self.__threadDict[dwThreadId] = aThread

    def _del_thread(self, dwThreadId):
        """
        Private method to remove a thread object from the snapshot.

        @type  dwThreadId: int
        @param dwThreadId: Global thread ID.
        """
##        if dwThreadId not in self.__threadDict:
##            msg = "Unknown thread ID: %d" % dwThreadId
##            raise KeyError(msg)
        self.__threadDict[dwThreadId].hThread = None    # handle
        self.__threadDict[dwThreadId].process = None    # circular reference
        del self.__threadDict[dwThreadId]

    def _has_thread_id(self, dwThreadId):
        """
        Private method to test for a thread in the snapshot without triggering
        an automatic scan.
        """
        return self.__threadDict.has_key(dwThreadId)

    def _get_thread_ids(self):
        """
        Private method to get the list of thread IDs currently in the snapshot
        without triggering an automatic scan.
        """
        return self.__threadDict.keys()

    def __add_created_thread(self, event):
        """
        Private method to automatically add new thread objects from debug events.

        @type  event: L{Event}
        @param event: Event object.
        """
        dwThreadId  = event.get_tid()
        hThread     = event.get_thread_handle()
##        if not self.has_thread(dwThreadId):   # XXX this would trigger a scan
        if not self._has_thread_id(dwThreadId):
            aThread = Thread(dwThreadId, hThread, self)
            teb_ptr = event.get_teb()   # remember the TEB pointer
            if teb_ptr:
                aThread._teb_ptr = teb_ptr
            self._add_thread(aThread)
        else:
            aThread = self.get_thread(dwThreadId)
            if hThread != win32.INVALID_HANDLE_VALUE:
                aThread.hThread = hThread   # may have more privileges

    def notify_create_process(self, event):
        """
        Notify the creation of the main thread of this process.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        self.__add_created_thread(event)
        return True

    def notify_create_thread(self, event):
        """
        Notify the creation of a new thread in this process.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{CreateThreadEvent}
        @param event: Create thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        self.__add_created_thread(event)
        return True

    def notify_exit_thread(self, event):
        """
        Notify the termination of a thread.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{ExitThreadEvent}
        @param event: Exit thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwThreadId = event.get_tid()
##        if self.has_thread(dwThreadId):   # XXX this would trigger a scan
        if self._has_thread_id(dwThreadId):
            self._del_thread(dwThreadId)
        return True

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
        find_processes_by_filename, get_pid_from_tid,
        get_windows,
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

    def __initialize_snapshot(self):
        """
        Private method to automatically initialize the snapshot
        when you try to use it without calling any of the scan_*
        methods first. You don't need to call this yourself.
        """
        if not self.__processDict:
##            self.scan()                     # recursive scan
            try:
                self.scan_processes()       # normal scan
            except Exception:
                self.scan_processes_fast()  # fast scan (no filenames)

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

    def has_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.

        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Process} object with the given global ID.
        """
        self.__initialize_snapshot()
        return dwProcessId in self.__processDict

    def get_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.

        @rtype:  L{Process}
        @return: Process object with the given global ID.
        """
        self.__initialize_snapshot()
        if dwProcessId not in self.__processDict:
            msg = "Unknown process ID %d" % dwProcessId
            raise KeyError(msg)
        return self.__processDict[dwProcessId]

    def iter_process_ids(self):
        """
        @see:    L{iter_processes}
        @rtype:  dictionary-keyiterator
        @return: Iterator of global process IDs in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__processDict.iterkeys()

    def iter_processes(self):
        """
        @see:    L{iter_process_ids}
        @rtype:  dictionary-valueiterator
        @return: Iterator of L{Process} objects in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__processDict.itervalues()

    def get_process_ids(self):
        """
        @see:    L{iter_process_ids}
        @rtype:  list( int )
        @return: List of global process IDs in this snapshot.
        """
        self.__initialize_snapshot()
        return self.__processDict.keys()

    def get_process_count(self):
        """
        @rtype:  int
        @return: Count of L{Process} objects in this snapshot.
        """
        self.__initialize_snapshot()
        return len(self.__processDict)

#------------------------------------------------------------------------------

    # XXX TODO
    # Support for string searches on the window captions.

    def get_windows(self):
        """
        @rtype:  list of L{Window}
        @return: Returns a list of windows
            handled by all processes in this snapshot.
        """
        window_list = list()
        for process in self.iter_processes():
            window_list.extend( process.get_windows() )
        return window_list

    def get_pid_from_tid(self, dwThreadId):
        """
        Retrieves the global ID of the process that owns the thread.

        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.

        @rtype:  int
        @return: Process global ID.

        @raise KeyError: The thread does not exist.
        """
        try:

            # No good, because in XP and below it tries to get the PID
            # through the toolhelp API, and that's slow. We don't want
            # to scan for threads over and over for each call.
##            dwProcessId = Thread(dwThreadId).get_pid()

            # This API only exists in Vista and above.
            hThread     = Thread(dwThreadId).get_handle()
            dwProcessId = win32.GetProcessIdOfThread(hThread)

        # If all else fails, go through all processes in the snapshot
        # looking for the one that owns the thread we're looking for.
        # If the snapshot was empty the iteration should trigger an
        # automatic scan. Otherwise, it'll look for the thread in what
        # could possibly be an outdated snapshot.
        except Exception:
            for aProcess in self.iter_processes():
                if aProcess.has_thread(dwThreadId):
                    return aProcess.get_pid()

        # The thread wasn't found, so let's refresh the snapshot and retry.
        # Normally this shouldn't happen since this function is only useful
        # for the debugger, so the thread should already exist in the snapshot.
        self.scan_processes_and_threads()
        for aProcess in self.iter_processes():
            if aProcess.has_thread(dwThreadId):
                return aProcess.get_pid()

        # No luck! It appears to be the thread doesn't exist after all.
        msg = "Unknown thread ID %d" % dwThreadId
        raise KeyError(msg)

#------------------------------------------------------------------------------

    @staticmethod
    def argv_to_cmdline(argv):
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
            if not token:
                token = '""'
            else:
                if '"' in token:
                    token = token.replace('"', '\\"')
                if  ' ' in token  or \
                    '\t' in token or \
                    '\n' in token or \
                    '\r' in token:
                        token = '"%s"' % token
            cmdline.append(token)
        return ' '.join(cmdline)

    @staticmethod
    def cmdline_to_argv(lpCmdLine):
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

    def start_process(self, lpCmdLine, **kwargs):
        """
        Starts a new process for instrumenting (or debugging).

        @type  lpCmdLine: str
        @param lpCmdLine: Command line to execute. Can't be an empty string.

        @type    bConsole: bool
        @keyword bConsole: True to inherit the console of the debugger.
            Defaults to C{False}.

        @type    bDebug: bool
        @keyword bDebug: C{True} to attach to the new process.
            To debug a process it's best to use the L{Debug} class instead.
            Defaults to C{False}.

        @type    bFollow: bool
        @keyword bFollow: C{True} to automatically attach to the child
            processes of the newly created process. Ignored unless C{bDebug} is
            C{True}. Defaults to C{False}.

        @type    bInheritHandles: bool
        @keyword bInheritHandles: C{True} if the new process should inherit
            it's parent process' handles. Defaults to C{False}.

        @type    bSuspended: bool
        @keyword bSuspended: C{True} to suspend the main thread before any code
            is executed in the debugee. Defaults to C{False}.

        @type    dwParentProcessId: int or None
        @keyword dwParentProcessId: C{None} if the debugger process should be
            the parent process (default), or a process ID to forcefully set as
            the debugee's parent (only available for Windows Vista and above).

        @rtype:  L{Process}
        @return: Process object.
        """
        
        bConsole            = kwargs.pop('bConsole', False)
        bDebug              = kwargs.pop('bDebug', False)
        bFollow             = kwargs.pop('bFollow', False)
        bSuspended          = kwargs.pop('bSuspended', False)
        bInheritHandles     = kwargs.pop('bInheritHandles', False)
        dwParentProcessId   = kwargs.pop('dwParentProcessId', None)
        if kwargs:
            raise TypeError("Unknown keyword arguments: %s" % kwargs.keys())
        if not lpCmdLine:
            raise ValueError("Missing command line to execute!")
        
        dwCreationFlags  = 0
        dwCreationFlags |= win32.CREATE_DEFAULT_ERROR_MODE
        dwCreationFlags |= win32.CREATE_BREAKAWAY_FROM_JOB
        if not bConsole:
            dwCreationFlags |= win32.DETACHED_PROCESS
        if bSuspended:
            dwCreationFlags |= win32.CREATE_SUSPENDED
        if bDebug:
            dwCreationFlags |= win32.DEBUG_PROCESS
            if not bFollow:
                dwCreationFlags |= win32.DEBUG_ONLY_THIS_PROCESS
        lpStartupInfo = None
        
        if dwParentProcessId is not None:
            myPID = win32.GetCurrentProcessId()
            if dwParentProcessId != myPID:
                if self.has_process(dwParentProcessId):
                    ParentProcess = self.get_process(dwParentProcessId)
                else:
                    ParentProcess = Process(dwParentProcessId)
                ParentProcessHandle = ParentProcess.get_handle()._as_parameter_
                AttributeList = (
                    (
                        win32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        ParentProcessHandle
                    ),
                )
                AttributeList = win32.ProcThreadAttributeList(AttributeList)
                StartupInfoEx           = win32.STARTUPINFOEX()
                StartupInfo             = StartupInfoEx.StartupInfo
                StartupInfo.cb          = win32.sizeof(win32.STARTUPINFOEX)
                StartupInfo.lpReserved  = 0
                StartupInfo.lpDesktop   = 0
                StartupInfo.lpTitle     = 0
                StartupInfo.dwFlags     = 0
                StartupInfo.cbReserved2 = 0
                StartupInfo.lpReserved2 = 0
                StartupInfoEx.lpAttributeList = AttributeList.value
                lpStartupInfo = StartupInfoEx
                dwCreationFlags |= win32.EXTENDED_STARTUPINFO_PRESENT
        
        pi = None
        try:
            pi = win32.CreateProcess(win32.NULL, lpCmdLine,
                                        bInheritHandles = bInheritHandles,
                                        dwCreationFlags = dwCreationFlags,
                                        lpStartupInfo   = lpStartupInfo)            
            aProcess = Process(pi.dwProcessId, pi.hProcess)
            aThread  = Thread (pi.dwThreadId,  pi.hThread)
            aProcess._add_thread(aThread)
            self._add_process(aProcess)
        except:
            if pi is not None:
                try:
                    win32.TerminateProcess(pi.hProcess)
                except WindowsError:
                    pass
                pi.hThread.close()
                pi.hProcess.close()
            raise
        
        return aProcess

#------------------------------------------------------------------------------

    # XXX this methods musn't end up calling __initialize_snapshot by accident!

    def scan(self):
        """
        Populates the snapshot with running processes and threads,
        and loaded modules.
        
        @raise WindowsError: An error occurred, and the scan may be incomplete.
        """
        try:
            self.scan_processes_and_threads()
        except Exception:
            self.scan_processes_fast()
            raise
        self.scan_modules()

    def scan_processes_and_threads(self):
        """
        Populates the snapshot with running processes and threads.
        """

        # The main module filename may be spoofed by malware,
        # since this information resides in usermode space.
        # See: http://www.ragestorm.net/blogs/?p=163

        our_pid    = win32.GetCurrentProcessId()
##        dead_pids  = set( self.get_process_ids() ) # XXX triggers a scan
        dead_pids  = set( self.__processDict.keys() )
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
##                    if not self.has_process(dwProcessId): # XXX triggers a scan
                    if not self.__processDict.has_key(dwProcessId):
                        aProcess = Process(dwProcessId)
                        self._add_process(aProcess)
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
##                    if self.has_process(dwProcessId): # XXX triggers a scan
                    if self.__processDict.has_key(dwProcessId):
                        aProcess = self.get_process(dwProcessId)
                    else:
                        aProcess = Process(dwProcessId)
                        self._add_process(aProcess)
                    dwThreadId = te.th32ThreadID
                    found_tids.add(dwThreadId)
##                    if not aProcess.has_thread(dwThreadId): # XXX triggers a scan
                    if not aProcess._has_thread_id(dwThreadId):
                        aThread = Thread(dwThreadId, process = aProcess)
                        aProcess._add_thread(aThread)
                te = win32.Thread32Next(hSnapshot)

        # Always close the snapshot handle before returning
        finally:
            win32.CloseHandle(hSnapshot)

        # Remove dead processes
        for pid in dead_pids:
            self._del_process(pid)

        # Remove dead threads
##        for aProcess in self.iter_processes(): # XXX triggers a scan
        for aProcess in self.__processDict.itervalues():
##            dead_tids = set( aProcess.get_thread_ids() ) # XXX triggers a scan
            dead_tids = set( aProcess._get_thread_ids() )
            dead_tids.difference_update(found_tids)
            for tid in dead_tids:
                aProcess._del_thread(tid)


    def scan_modules(self):
        """
        Populates the snapshot with loaded modules.
        
        @rtype: bool
        @return: C{True} if the snapshot is complete, C{False} if the debugger
            doesn't have permission to scan some processes. In either case, the
            snapshot is complete for all processes the debugger has access to.
        """
        complete = True
##        for aProcess in self.iter_processes(): # XXX triggers a scan
        for aProcess in self.__processDict.itervalues():
            try:
                aProcess.scan_modules()
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_ACCESS_DENIED:
                    complete = False
                else:
                    raise
        return complete

    def scan_processes(self):
        """
        Populates the snapshot with running processes.
        """

        # The module filenames may be spoofed by malware,
        # since this information resides in usermode space.
        # See: http://www.ragestorm.net/blogs/?p=163

        our_pid   = win32.GetCurrentProcessId()
##        dead_pids  = set( self.get_process_ids() ) # XXX triggers a scan
        dead_pids  = set( self.__processDict.keys() )
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
##                    if not self.has_process(dwProcessId): # XXX triggers a scan
                    if not self.__processDict.has_key(dwProcessId):
                        aProcess = Process(dwProcessId)
                        self._add_process(aProcess)
                    elif pe.szExeFile:
                        aProcess = self.get_process(dwProcessId)
                        if not aProcess.fileName:
                            aProcess.fileName = pe.szExeFile
                pe = win32.Process32Next(hSnapshot)
        finally:
            win32.CloseHandle(hSnapshot)
        for pid in dead_pids:
            self._del_process(pid)

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
##        old_pids = set( self.get_process_ids() ) # XXX triggers a scan
        old_pids = set( self.__processDict.keys() )

        # Ignore our own pid
        our_pid  = win32.GetCurrentProcessId()
        if our_pid in new_pids:
            new_pids.remove(our_pid)
        if our_pid in old_pids:
            old_pids.remove(our_pid)

        # Add newly found pids
        for pid in new_pids.difference(old_pids):
            self._add_process( Process(pid) )

        # Remove missing pids
        for pid in old_pids.difference(new_pids):
            self._del_process(pid)

    def clear_dead_processes(self):
        """
        Removes Process objects from the snapshot
        referring to processes no longer running.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            if not aProcess.is_alive():
                self._del_process(aProcess)

    def clear_unattached_processes(self):
        """
        Removes Process objects from the snapshot
        referring to processes not being debugged.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            if not aProcess.is_being_debugged():
                self._del_process(aProcess)

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
        dwProcessId = self.get_pid_from_tid(dwThreadId)
        if dwProcessId is None:
            return False
        return self.has_process(dwProcessId)

    def get_thread(self, dwThreadId):
        dwProcessId = self.get_pid_from_tid(dwThreadId)
        if dwProcessId is None:
            msg = "Unknown thread ID %d" % dwThreadId
            raise KeyError(msg)
        return self.get_process(dwProcessId).get_thread(dwThreadId)

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

    # XXX notify_* methods should not trigger a scan

    def _add_process(self, aProcess):
        """
        Private method to add a process object to the snapshot.

        @type  aProcess: L{Process}
        @param aProcess: Process object.
        """
##        if not isinstance(aProcess, Process):
##            if hasattr(aProcess, '__class__'):
##                typename = aProcess.__class__.__name__
##            else:
##                typename = str(type(aProcess))
##            msg = "Expected Process, got %s instead" % typename
##            raise TypeError(msg)
        dwProcessId = aProcess.dwProcessId
##        if dwProcessId in self.__processDict:
##            msg = "Process already exists: %d" % dwProcessId
##            raise KeyError(msg)
        self.__processDict[dwProcessId] = aProcess

    def _del_process(self, dwProcessId):
        """
        Private method to remove a process object from the snapshot.

        @type  dwProcessId: int
        @param dwProcessId: Global process ID.
        """
##        if dwProcessId not in self.__processDict:
##            msg = "Unknown process ID %d" % dwProcessId
##            raise KeyError(msg)
        self.__processDict[dwProcessId].hProcess = None # handle
        self.__processDict[dwProcessId].clear()         # circular reference
        del self.__processDict[dwProcessId]

    # Notify the creation of a new process.
    def notify_create_process(self, event):
        """
        Notify the creation of a new process.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
        dwThreadId  = event.get_tid()
        hProcess    = event.get_process_handle()
##        if not self.has_process(dwProcessId): # XXX this would trigger a scan
        if not self.__processDict.has_key(dwProcessId):
            aProcess = Process(dwProcessId, hProcess)
            self._add_process(aProcess)
            aProcess.fileName = event.get_filename()
        else:
            aProcess = self.get_process(dwProcessId)
            if hProcess != win32.INVALID_HANDLE_VALUE:
                aProcess.hProcess = hProcess    # may have more privileges
            if not aProcess.fileName:
                fileName = event.get_filename()
                if fileName:
                    aProcess.fileName = fileName
        return aProcess.notify_create_process(event)   # pass it to the process

    def notify_exit_process(self, event):
        """
        Notify the termination of a process.

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
##        if self.has_process(dwProcessId): # XXX this would trigger a scan
        if self.__processDict.has_key(dwProcessId):
            self._del_process(dwProcessId)
        return True

#==============================================================================

# TODO
# * This methods do not take into account that code breakpoints change the
#   memory. This object should talk to BreakpointContainer to retrieve the
#   original memory contents where code breakpoints are enabled.
# * A memory cache could be implemented here.
class MemoryOperations (object):
    """
    Encapsulates the capabilities to manipulate the memory of a process.

    @group Instrumentation:
        malloc, free, mprotect, mquery,
        take_memory_snapshot, generate_memory_snapshot, restore_memory_snapshot

    @group Memory mapping:
        get_memory_map, get_mapped_filenames,
        is_pointer, is_address_valid, is_address_free, is_address_reserved,
        is_address_commited, is_address_guard, is_address_readable,
        is_address_writeable, is_address_copy_on_write, is_address_executable,
        is_address_executable_and_writeable,
        is_buffer,
        is_buffer_readable, is_buffer_writeable, is_buffer_executable,
        is_buffer_executable_and_writeable

    @group Memory read:
        read, read_char, read_uint, read_pointer, read_string, read_structure,
        peek, peek_char, peek_uint, peek_pointer, peek_string

    @group Memory write:
        write, write_char, write_uint, write_pointer,
        poke, poke_char, poke_uint, poke_pointer
    """

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
        # XXX TODO
        # + Maybe change page permissions before trying to read?
        if not self.is_buffer(lpBaseAddress, nSize):
            raise ctypes.WinError(win32.ERROR_INVALID_ADDRESS)
        data = win32.ReadProcessMemory(self.get_handle(), lpBaseAddress, nSize)
        if len(data) != nSize:
            raise ctypes.WinError()
        return data

    def write(self, lpBaseAddress, lpBuffer):
        """
        Writes to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

        @see: L{poke}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  lpBuffer: str
        @param lpBuffer: Bytes to write.

        @raise WindowsError: On error an exception is raised.
        """
        r = self.poke(lpBaseAddress, lpBuffer)
        if r != len(lpBuffer):
            raise ctypes.WinError()

    def read_uint(self, lpBaseAddress):
        """
        Reads a single unsigned integer from the memory of the process.

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
        Writes a single unsigned integer to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

        @see: L{poke_uint}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  unpackedDword: int, long
        @param unpackedDword: Value to write.

        @raise WindowsError: On error an exception is raised.
        """
        packedDword = struct.pack('<L', unpackedDword)
        self.write(lpBaseAddress, packedDword)

    def read_pointer(self, lpBaseAddress):
        """
        Reads a single pointer value from the memory of the process.

        @see: L{peek_pointer}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Pointer value read from the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        lpvoidLength = win32.sizeof(win32.LPVOID)
        packedValue = self.read(lpBaseAddress, lpvoidLength)
        if lpvoidLength == 4:
            lpvoidFmt   = '<L'
        else:
            lpvoidFmt   = '<Q'
        unpackedValue = struct.unpack(lpvoidFmt, packedValue)[0]
        return unpackedValue

    def write_pointer(self, lpBaseAddress, unpackedValue):
        """
        Writes a single pointer value to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

        @see: L{poke_pointer}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  unpackedValue: int, long
        @param unpackedValue: Value to write.

        @raise WindowsError: On error an exception is raised.
        """
        lpvoidLength    = win32.sizeof(win32.LPVOID)
        if lpvoidLength == 4:
            lpvoidFmt   = '<L'
        else:
            lpvoidFmt   = '<Q'
        packedValue = struct.pack(lpvoidFmt, unpackedValue)
        self.write(lpBaseAddress, packedValue)

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

        @note: Page permissions may be changed temporarily while writing.

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

# XXX TODO
##    def write_structure(self, lpBaseAddress, sStructure):
##        """
##        Writes a ctypes structure into the memory of the process.
##
##        @note: Page permissions may be changed temporarily while writing.
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
        # XXX TODO
        # + Maybe change page permissions before trying to read?
        # + Maybe use mquery instead of get_memory_map?
        #   (less syscalls if we break out of the loop earlier)
        data = ''
        if nSize > 0:
            try:
                for mbi in self.get_memory_map(lpBaseAddress,
                                               lpBaseAddress + nSize):
                    if not mbi.is_readable():
                        nSize = mbi.BaseAddress - lpBaseAddress
                        break
                if nSize > 0:
                    data = win32.ReadProcessMemory(self.get_handle(),
                                                          lpBaseAddress, nSize)
            except WindowsError:
                pass
        return data

    def poke(self, lpBaseAddress, lpBuffer):
        """
        Writes to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

        @see: L{write}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  lpBuffer: str
        @param lpBuffer: Bytes to write.

        @rtype:  int
        @return: Number of bytes written.
            May be less than the number of bytes to write.
        """
        hProcess = self.get_handle()
        mbi = self.mquery(lpBaseAddress)
        if not mbi.has_content():
            raise ctypes.WinError(win32.ERROR_INVALID_ADDRESS)
        if mbi.is_image() or mbi.is_mapped():
            prot = win32.PAGE_WRITECOPY
        elif mbi.is_writeable():
            prot = None
        elif mbi.is_executable():
            prot = win32.PAGE_EXECUTE_READWRITE
        else:
            prot = win32.PAGE_READWRITE
        if prot is not None:
            self.mprotect(lpBaseAddress, len(lpBuffer), prot)
        try:
            r = win32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer)
        finally:
            if prot is not None:
                self.mprotect(lpBaseAddress, len(lpBuffer), mbi.Protect)
        return r

    def peek_uint(self, lpBaseAddress):
        """
        Reads a single unsigned integer from the memory of the process.

        @see: L{read_uint}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Integer value read from the process memory.
            Returns zero on error.
        """
        dwordLength = win32.sizeof(win32.UINT)
        packedDword = self.peek(lpBaseAddress, dwordLength)
        if len(packedDword) < dwordLength:
            packedDword += '\x00' * (dwordLength - len(packedDword))
        unpackedDword = struct.unpack('<L', packedDword)[0]
        return unpackedDword

    def poke_uint(self, lpBaseAddress, unpackedDword):
        """
        Writes a single unsigned integer to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

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

    def peek_pointer(self, lpBaseAddress):
        """
        Reads a single pointer value from the memory of the process.

        @see: L{read_pointer}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin reading.

        @rtype:  int
        @return: Pointer value read from the process memory.
            Returns zero on error.
        """
        lpvoidLength = win32.sizeof(win32.LPVOID)
        packedValue = self.read(lpBaseAddress, lpvoidLength)
        if len(packedValue) < lpvoidLength:
            packedValue += '\x00' * (lpvoidLength - len(packedValue))
        if lpvoidLength == 4:
            lpvoidFmt   = '<L'
        else:
            lpvoidFmt   = '<Q'
        unpackedValue = struct.unpack(lpvoidFmt, packedValue)[0]
        return unpackedValue

    def poke_pointer(self, lpBaseAddress, unpackedValue):
        """
        Writes a single pointer value to the memory of the process.

        @note: Page permissions may be changed temporarily while writing.

        @see: L{write_pointer}

        @type  lpBaseAddress: int
        @param lpBaseAddress: Memory address to begin writing.

        @type  unpackedValue: int, long
        @param unpackedValue: Value to write.

        @rtype:  int
        @return: Number of bytes written.
            May be less than the number of bytes to write.
        """
        lpvoidLength    = win32.sizeof(win32.LPVOID)
        if lpvoidLength == 4:
            lpvoidFmt   = '<L'
        else:
            lpvoidFmt   = '<Q'
        packedValue     = struct.pack(lpvoidFmt, unpackedValue)
        dwBytesWritten  = self.poke(lpBaseAddress, packedValue)
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

        @note: Page permissions may be changed temporarily while writing.

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
            It B{doesn't} include the terminating null character.
            Returns an empty string on failure.
        """

        # Validate the parameters.
        if not lpBaseAddress or dwMaxSize == 0:
            if fUnicode:
                return u''
            return ''
        if not dwMaxSize:
            dwMaxSize = 0x1000

        # Read the string.
        szString = self.peek(lpBaseAddress, dwMaxSize)

        # If the string is Unicode...
        if fUnicode:

            # Decode the string.
            szString = unicode(szString, 'U16', 'replace')
##            try:
##                szString = unicode(szString, 'U16')
##            except UnicodeDecodeError:
##                szString = struct.unpack('H' * (len(szString) / 2), szString)
##                szString = [ unichr(c) for c in szString ]
##                szString = u''.join(szString)

            # Truncate the string when the first null char is found.
            szString = szString[ : szString.find(u'\0') ]

        # If the string is ANSI...
        else:

            # Truncate the string when the first null char is found.
            szString = szString[ : szString.find('\0') ]

        # Return the decoded string.
        return szString

#------------------------------------------------------------------------------

    def malloc(self, dwSize, lpAddress = None):
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
        Returns a L{win32.MemoryBasicInformation} object.

        @see: U{http://msdn.microsoft.com/en-us/library/aa366907(VS.85).aspx}

        @type  lpAddress: int
        @param lpAddress: Address of memory to query.

        @rtype:  L{win32.MemoryBasicInformation}
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

        @raise WindowsError: On error an exception is raised.
        """
        win32.VirtualFreeEx(self.get_handle(), lpAddress, dwSize)

#------------------------------------------------------------------------------

    def is_pointer(self, address):
        """
        Determines if an address is a valid code or data pointer.

        That is, the address must be valid and must point to code or data in
        the target process.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address is a valid code or data pointer.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.has_content()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_free()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_reserved()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_commited()

    def is_address_guard(self, address):
        """
        Determines if an address belongs to a guard page.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return: C{True} if the address belongs to a guard page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_guard()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_readable()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_writeable()

    def is_address_copy_on_write(self, address):
        """
        Determines if an address belongs to a commited, copy-on-write page.
        The page may or may not have additional permissions.

        @note: Returns always C{False} for kernel mode addresses.

        @type  address: int
        @param address: Memory address to query.

        @rtype:  bool
        @return:
            C{True} if the address belongs to a commited, copy-on-write page.

        @raise WindowsError: An exception is raised on error.
        """
        try:
            mbi = self.mquery(address)
        except WindowsError, e:
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_copy_on_write()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_executable()

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
            if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                return False
            raise
        return mbi.is_executable_and_writeable()

    def is_buffer(self, address, size):
        """
        Determines if the given memory area is a valid code or data buffer.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is a valid code or data buffer,
            C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.has_content():
                return False
            size = size - mbi.RegionSize
        return True

    def is_buffer_readable(self, address, size):
        """
        Determines if the given memory area is readable.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is readable, C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.is_readable():
                return False
            size = size - mbi.RegionSize
        return True

    def is_buffer_writeable(self, address, size):
        """
        Determines if the given memory area is writeable.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is writeable, C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.is_writeable():
                return False
            size = size - mbi.RegionSize
        return True

    def is_buffer_copy_on_write(self, address, size):
        """
        Determines if the given memory area is marked as copy-on-write.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is marked as copy-on-write,
            C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.is_copy_on_write():
                return False
            size = size - mbi.RegionSize
        return True

    def is_buffer_executable(self, address, size):
        """
        Determines if the given memory area is executable.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is executable, C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.is_executable():
                return False
            size = size - mbi.RegionSize
        return True

    def is_buffer_executable_and_writeable(self, address, size):
        """
        Determines if the given memory area is writeable and executable.

        Looking for writeable and executable pages is important when
        exploiting a software vulnerability.

        @note: Returns always C{False} for kernel mode addresses.

        @see: L{mquery}

        @type  address: int
        @param address: Memory address.

        @type  size: int
        @param size: Number of bytes. Must be greater than zero.

        @rtype:  bool
        @return: C{True} if the memory area is writeable and executable,
            C{False} otherwise.

        @raise ValueError: The size argument must be greater than zero.
        @raise WindowsError: On error an exception is raised.
        """
        if size <= 0:
            raise ValueError("The size argument must be greater than zero")
        while size > 0:
            try:
                mbi = self.mquery(address)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    return False
                raise
            if not mbi.is_executable():
                return False
            size = size - mbi.RegionSize
        return True

    def get_memory_map(self, minAddr = None, maxAddr = None):
        """
        Produces a memory map to the process address space.
        Optionally restrict the map to the given address range.

        @see: L{mquery}

        @type  minAddr: int
        @param minAddr: (Optional) Starting address in address range to query.

        @type  maxAddr: int
        @param maxAddr: (Optional) Ending address in address range to query.

        @rtype:  list( L{win32.MemoryBasicInformation} )
        @return: List of memory region information objects.
        """
        if minAddr is None:
            minAddr = 0
        if maxAddr is None:
            maxAddr = win32.LPVOID(-1).value  # XXX HACK
        if minAddr > maxAddr:
            minAddr, maxAddr = maxAddr, minAddr
        minAddr     = MemoryAddresses.align_address_to_page_start(minAddr)
        if maxAddr != MemoryAddresses.align_address_to_page_start(maxAddr):
            maxAddr = MemoryAddresses.align_address_to_page_end(maxAddr)
        prevAddr    = minAddr - 1
        currentAddr = minAddr
        memoryMap   = list()
        while currentAddr < maxAddr and currentAddr > prevAddr:
            try:
                mbi = self.mquery(currentAddr)
            except WindowsError, e:
                if win32.winerror(e) == win32.ERROR_INVALID_PARAMETER:
                    break
                raise
            memoryMap.append(mbi)
            prevAddr    = currentAddr
            currentAddr = mbi.BaseAddress + mbi.RegionSize
        return memoryMap

    def get_mapped_filenames(self, memoryMap = None):
        """
        Retrieves the filenames for memory mapped files in the debugee.

        @type  memoryMap: list( L{win32.MemoryBasicInformation} )
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
##                print str(e)    # XXX DEBUG
                pass
            mappedFilenames[baseAddress] = fileName
        return mappedFilenames

    def generate_memory_snapshot(self, minAddr = None, maxAddr = None):
        """
        Returns a generator that allows you to iterate through the memory
        contents of a process.

        It's basically the same as the L{take_memory_snapshot} method, but it
        takes the snapshot of each memory region as it goes, as opposed to
        taking the whole snapshot at once. This allows you to work with very
        large snapshots without a significant performance penalty.

        Example::
            # Print the memory contents of a process.
            process.suspend()
            try:
                snapshot = process.generate_memory_snapshot()
                for mbi in snapshot:
                    print HexDump.hexblock(mbi.content, mbi.BaseAddress)
            finally:
                process.resume()

        The downside of this is the process must remain suspended while
        iterating the snapshot, otherwise strange things may happen.

        The snapshot can be iterated more than once. Each time it's iterated
        the memory contents of the process will be fetched again.

        You can also iterate the memory of a dead process, just as long as the
        last open handle to it hasn't been closed.

        @see: L{take_memory_snapshot}

        @type  minAddr: int
        @param minAddr: (Optional) Starting address in address range to query.

        @type  maxAddr: int
        @param maxAddr: (Optional) Ending address in address range to query.

        @rtype:  generator of L{win32.MemoryBasicInformation}
        @return: Generator that when iterated returns memory region information
            objects. Two extra properties are added to these objects:
             - C{filename}: Mapped filename, or C{None}.
             - C{content}: Memory contents, or C{None}.
        """
        return Regenerator(self.__generate_memory_snapshot, minAddr, maxAddr)

    def __generate_memory_snapshot(self, minAddr = None, maxAddr = None):
        """
        Internally used by L{generate_memory_snapshot}.
        """

        # One may feel tempted to include calls to self.suspend() and
        # self.resume() here, but that wouldn't work on a dead process.
        # It also wouldn't be needed when debugging since the process is
        # already suspended when the debug event arrives. So it's up to
        # the user to suspend the process if needed.

        # Get the memory map.
        memory = self.get_memory_map(minAddr, maxAddr)

        # Abort if the map couldn't be retrieved.
        if not memory:
            return

        # Get the mapped filenames.
        filenames = self.get_mapped_filenames(memory)

        # Trim the first memory information block if needed.
        if minAddr is not None:
            minAddr = MemoryAddresses.align_address_to_page_start(minAddr)
            mbi = memory[0]
            if mbi.BaseAddress < minAddr:
                mbi.RegionSize  = mbi.BaseAddress + mbi.RegionSize - minAddr
                mbi.BaseAddress = minAddr

        # Trim the last memory information block if needed.
        if maxAddr is not None:
            if maxAddr != MemoryAddresses.align_address_to_page_start(maxAddr):
                maxAddr = MemoryAddresses.align_address_to_page_end(maxAddr)
            mbi = memory[-1]
            if mbi.BaseAddress + mbi.RegionSize > maxAddr:
                mbi.RegionSize = maxAddr - mbi.BaseAddress

        # Read the contents of each block and yield it.
        while memory:
            mbi = memory.pop(0) # so the garbage collector can take it
            mbi.filename = filenames.get(mbi.BaseAddress, None)
            if mbi.has_content():
                mbi.content = self.read(mbi.BaseAddress, mbi.RegionSize)
            else:
                mbi.content = None
            yield mbi

    def take_memory_snapshot(self, minAddr = None, maxAddr = None):
        """
        Takes a snapshot of the memory contents of the process.

        It's best if the process is suspended when taking the snapshot.
        Execution can be resumed afterwards.

        You can also iterate the memory of a dead process, just as long as the
        last open handle to it hasn't been closed.

        @warning: If the target process has a very big memory footprint, the
            resulting snapshot will be equally big. This may result in a severe
            performance penalty.

        @see: L{generate_memory_snapshot}

        @type  minAddr: int
        @param minAddr: (Optional) Starting address in address range to query.

        @type  maxAddr: int
        @param maxAddr: (Optional) Ending address in address range to query.

        @rtype:  list( L{win32.MemoryBasicInformation} )
        @return: List of memory region information objects.
            Two extra properties are added to these objects:
             - C{filename}: Mapped filename, or C{None}.
             - C{content}: Memory contents, or C{None}.
        """
        return list( self.generate_memory_snapshot(minAddr, maxAddr) )

    def restore_memory_snapshot(self, snapshot, bSkipMappedFiles = True):
        """
        Attempts to restore the memory state as it was when the given snapshot
        was taken.

        @warning: Currently only the memory contents, state and protect bits
            are restored. Under some circumstances this method may fail (for
            example if memory was freed and then reused by a mapped file).

        @type  snapshot: list( L{win32.MemoryBasicInformation} )
        @param snapshot: Memory snapshot returned by L{take_memory_snapshot}.
            Snapshots returned by L{generate_memory_snapshot} don't work here.

        @type  bSkipMappedFiles: bool
        @param bSkipMappedFiles: C{True} to avoid restoring the contents of
            memory mapped files, C{False} otherwise. Use with care! Setting
            this to C{False} can cause undesired side effects - changes to
            memory mapped files may be written to disk by the OS. Also note
            that most mapped files are typically executables and don't change,
            so trying to restore their contents is usually a waste of time.

        @raise WindowsError: An error occured while restoring the snapshot.
        @raise RuntimeError: An error occured while restoring the snapshot.
        @raise TypeError: A snapshot of the wrong type was passed.
        """
        if not isinstance(snapshot, list):
            raise TypeError( "Only snapshots returned by " \
                             "take_memory_snapshots() can be used here." )

        # Get the process handle.
        hProcess = self.get_handle()

        # Freeze the process.
        self.suspend()
        try:

            # For each memory region in the snapshot...
            for old_mbi in snapshot:

                # If the region matches, restore it directly.
                new_mbi = self.mquery(old_mbi.BaseAddress)
                if new_mbi.BaseAddress == old_mbi.BaseAddress and new_mbi.RegionSize == old_mbi.RegionSize:
                    self.__restore_mbi(hProcess, new_mbi, old_mbi)

                # If the region doesn't match, restore it page by page.
                else:
                    # We need a copy so we don't corrupt the snapshot.
                    old_mbi = win32.MemoryBasicInformation(old_mbi)

                    # Get the overlapping range of pages.
                    old_start = old_mbi.BaseAddress
                    old_end   = old_start + old_mbi.RegionSize
                    new_start = new_mbi.BaseAddress
                    new_end   = new_start + new_mbi.RegionSize
                    if old_start > new_start:
                        start = old_start
                    else:
                        start = new_start
                    if old_end < new_end:
                        end = old_end
                    else:
                        end = new_end

                    # Restore each page in the overlapping range.
                    step = System.pageSize
                    old_mbi.RegionSize = step
                    new_mbi.RegionSize = step
                    address = start
                    while address < end:
                        old_mbi.BaseAddress = address
                        new_mbi.BaseAddress = address
                        self.__restore_mbi(hProcess, new_mbi, old_mbi)
                        address = address + step

        # Resume execution.
        finally:
            self.resume()

    def __restore_mbi(self, hProcess, new_mbi, old_mbi):
        """
        Used internally by L{restore_memory_snapshot}.
        """

##        print "Restoring %s-%s" % (HexDump.address(old_mbi.BaseAddress), HexDump.address(old_mbi.BaseAddress + old_mbi.RegionSize))

        # Restore the region state.
        if new_mbi.State != old_mbi.State:
            if new_mbi.is_free():
                if old_mbi.is_reserved():

                    # Free -> Reserved
                    address = win32.VirtualAllocEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_RESERVE, old_mbi.Protect)
                    if address != old_mbi.BaseAddress:
                        self.free(address)
                        msg = "Error restoring region at address %s"
                        msg = msg % HexDump(old_mbi.BaseAddress)
                        raise RuntimeError(msg)
                    new_mbi.Protect = old_mbi.Protect   # permissions already restored

                else:   # elif old_mbi.is_commited():

                    # Free -> Commited
                    address = win32.VirtualAllocEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_RESERVE | win32.MEM_COMMIT, old_mbi.Protect)
                    if address != old_mbi.BaseAddress:
                        self.free(address)
                        msg = "Error restoring region at address %s"
                        msg = msg % HexDump(old_mbi.BaseAddress)
                        raise RuntimeError(msg)
                    new_mbi.Protect = old_mbi.Protect   # permissions already restored

            elif new_mbi.is_reserved():
                if old_mbi.is_commited():

                    # Reserved -> Commited
                    address = win32.VirtualAllocEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_COMMIT, old_mbi.Protect)
                    if address != old_mbi.BaseAddress:
                        self.free(address)
                        msg = "Error restoring region at address %s"
                        msg = msg % HexDump(old_mbi.BaseAddress)
                        raise RuntimeError(msg)
                    new_mbi.Protect = old_mbi.Protect   # permissions already restored

                else:   # elif old_mbi.is_free():

                    # Reserved -> Free
                    win32.VirtualFreeEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_RELEASE)

            else:   # elif new_mbi.is_commited():
                if old_mbi.is_reserved():

                    # Commited -> Reserved
                    win32.VirtualFreeEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_DECOMMIT)

                else:   # elif old_mbi.is_free():

                    # Commited -> Free
                    win32.VirtualFreeEx(hProcess, old_mbi.BaseAddress, old_mbi.RegionSize, win32.MEM_DECOMMIT | win32.MEM_RELEASE)

        new_mbi.State = old_mbi.State

        # Restore the region permissions.
        if old_mbi.is_commited() and old_mbi.Protect != new_mbi.Protect:
            win32.VirtualProtectEx(hProcess, old_mbi.BaseAddress,
                                   old_mbi.RegionSize, old_mbi.Protect)
            new_mbi.Protect = old_mbi.Protect

        # Restore the region data.
        # Ignore write errors when the region belongs to a mapped file.
        if old_mbi.has_content():
            if old_mbi.Type != 0:
                if not bSkipMappedFiles:
                    self.poke(old_mbi.BaseAddress, old_mbi.content)
            else:
                self.write(old_mbi.BaseAddress, old_mbi.content)
            new_mbi.content = old_mbi.content

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
##        try:
##            SymbolName = win32.UnDecorateSymbolName(SymbolName)
##        except Exception, e:
##            pass
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
            SymOptions = win32.SymGetOptions()
            win32.SymSetOptions(SymOptions                          | \
                                win32.SYMOPT_ALLOW_ZERO_ADDRESS     | \
                                win32.SYMOPT_CASE_INSENSITIVE       | \
                                win32.SYMOPT_FAVOR_COMPRESSED       | \
                                win32.SYMOPT_INCLUDE_32BIT_MODULES  | \
                                win32.SYMOPT_UNDNAME)
            try:
                win32.SymSetOptions(SymOptions | win32.SYMOPT_ALLOW_ABSOLUTE_SYMBOLS)
            except WindowsError:
                pass
            try:
                try:
                    win32.SymLoadModule64(hProcess, hFile, None, None, BaseOfDll, SizeOfDll)
                except WindowsError:
                    ImageName = self.get_filename()
                    win32.SymLoadModule64(hProcess, None, ImageName, None, BaseOfDll, SizeOfDll)
                try:
                    win32.SymEnumerateSymbols64(hProcess, BaseOfDll, Enumerator)
                finally:
                    win32.SymUnloadModule64(hProcess, BaseOfDll)
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
        """
        Tries to find the closest matching symbol for the given address.

        @type  address: int
        @param address: Memory address to query.

        @rtype: None or tuple( str, int, int )
        @return: Returns a tuple consisting of:
             - Name
             - Address
             - Size (in bytes)
            Returns C{None} if no symbol could be matched.
        """
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
        is_system_defined_breakpoint, get_system_breakpoint,
        get_user_breakpoint, get_breakin_breakpoint,
        get_wow64_system_breakpoint, get_wow64_user_breakpoint,
        get_wow64_breakin_breakpoint
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
            raise ValueError("Invalid module name: %s" % module)
        if function is not None and ('!' in function or '+' in function):
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
        # If the module is not found, check for the special symbol "main".
        if module:
            modobj = self.get_module_by_name(module)
            if not modobj:
                if method == "main":
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
        elif function:
            for modobj in self.iter_modules():
                address = modobj.resolve(function)
                if address is not None:
                    break
            if address is None:
                msg = "Function %r not found in any module" % function
                raise RuntimeError(msg)

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
        return address is not None and (
            address == self.get_system_breakpoint()         or \
            address == self.get_wow64_system_breakpoint()   or \
            address == self.get_user_breakpoint()           or \
            address == self.get_wow64_user_breakpoint()     or \
            address == self.get_breakin_breakpoint()        or \
            address == self.get_wow64_breakin_breakpoint()
        )

    # TODO
    # The memory addresses of system breakpoints could be cached.
    # Since they're all in system libraries it's not likely they'll ever
    # change their address during the lifetime of the process... I don't
    # suppose a program could happily unload ntdll.dll and survive.
    # The difficulty is knowing when resolution fails because the breakpoint
    # does not exist in the current version of Windows, and when it's simply
    # the process module snapshot not having been yet initialized.

    # FIXME
    # In Wine, the system breakpoint seems to be somewhere in kernel32.
    # In Windows 2000 I've been told it's in ntdll!NtDebugBreak (not sure yet).
    def get_system_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the system breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll!DbgBreakPoint")
        except Exception:
            return None

    # Equivalent of ntdll!DbgBreakPoint in Wow64.
    def get_wow64_system_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the Wow64 system breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll32!DbgBreakPoint")
        except Exception:
            return None

    # I don't know when this breakpoint is actually used...
    def get_user_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the user breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll!DbgUserBreakPoint")
        except Exception:
            return None

    # Equivalent of ntdll!DbgBreakPoint in Wow64.
    def get_wow64_user_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the Wow64 user breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll32!DbgUserBreakPoint")
        except Exception:
            return None

    # This breakpoint can only be resolved when the
    # debugging symbols for ntdll.dll are loaded.
    def get_breakin_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the remote breakin breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll!DbgUiRemoteBreakin")
        except Exception:
            return None

    # Equivalent of ntdll!DbgBreakPoint in Wow64.
    def get_wow64_breakin_breakpoint(self):
        """
        @rtype:  int or None
        @return: Memory address of the Wow64 remote breakin breakpoint
            within the process address space.
            Returns C{None} on error.
        """
        try:
            return self.resolve_label("ntdll32!DbgUiRemoteBreakin")
        except Exception:
            return None

    def load_symbols(self):
        """
        Loads the debugging symbols for all modules in this snapshot.
        Automatically called by L{get_symbols}.
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

        @rtype:  list of tuple( str, int, int )
        @return: List of symbols.
            Each symbol is represented by a tuple that contains:
                - Symbol name
                - Symbol memory address
                - Symbol size in bytes
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

        @rtype:  iterator of tuple( str, int, int )
        @return: Iterator of symbols.
            Each symbol is represented by a tuple that contains:
                - Symbol name
                - Symbol memory address
                - Symbol size in bytes
        """
        for aModule in self.iter_modules():
            for symbol in aModule.iter_symbols():
                yield symbol

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
        """
        Tries to find the closest matching symbol for the given address.

        @type  address: int
        @param address: Memory address to query.

        @rtype: None or tuple( str, int, int )
        @return: Returns a tuple consisting of:
             - Name
             - Address
             - Size (in bytes)
            Returns C{None} if no symbol could be matched.
        """
        # Any module may have symbols pointing anywhere in memory, so there's
        # no easy way to optimize this. I guess we're stuck with brute force.
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
        get_teb, get_teb_address, is_wow64

    @group Debugging:
        get_seh_chain_pointer, set_seh_chain_pointer,
        get_seh_chain, get_wait_chain

    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string, disassemble_instruction, disassemble_current

    @group Stack:
        get_stack_frame, get_stack_frame_range, get_stack_range,
        get_stack_trace, get_stack_trace_with_labels,
        read_stack_data, read_stack_dwords, read_stack_qwords,
        peek_stack_data, peek_stack_dwords, peek_stack_qwords

    @group Miscellaneous:
        read_code_bytes, peek_code_bytes,
        peek_pointers_in_data, peek_pointers_in_registers,
        get_linear_address, get_label_at_pc
    """

    def is_wow64(self):
        """
        Determines if the thread is running under WOW64.

        @rtype:  bool
        @return:
            C{True} if the thread is running under WOW64. That is, it belongs
            to a 32-bit application running in a 64-bit Windows.

            C{False} if the thread belongs to either a 32-bit application
            running in a 32-bit Windows, or a 64-bit application running in a
            64-bit Windows.

        @raise WindowsError: On error an exception is raised.

        @see: U{http://msdn.microsoft.com/en-us/library/aa384249(VS.85).aspx}
        """
        try:
            wow64 = self.__wow64
        except AttributeError:
            if (System.bits == 32 and not System.wow64):
                wow64 = False
            else:
                wow64 = self.get_process().is_wow64()
            self.__wow64 = wow64
        return wow64

    def get_teb(self):
        """
        Returns a copy of the TEB.
        To dereference pointers in it call L{Process.read_structure}.

        @rtype:  L{TEB}
        @return: TEB structure.
        @raise WindowsError: An exception is raised on error.
        """
        return self.get_process().read_structure( self.get_teb_address(),
                                                  win32.TEB )

    def get_teb_address(self):
        """
        Returns a remote pointer to the TEB.

        @rtype:  int
        @return: Remote pointer to the L{TEB} structure.
        @raise WindowsError: An exception is raised on error.
        """
        try:
            return self._teb_ptr
        except AttributeError:
            try:
                tbi = win32.NtQueryInformationThread( self.get_handle(),
                                                      win32.ThreadBasicInformation)
                address = tbi.TebBaseAddress
            except WindowsError:
                address = self.get_linear_address('SegFs', 0)   # fs:[0]
                if not address:
                    raise
            self._teb_ptr = address
            return address

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

        @raise ValueError: Address is too large for selector.

        @raise WindowsError:
            The current architecture does not support selectors.
            Selectors only exist in x86-based systems.
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
            msg = "Address %s too large for segment %s (selector %d)"
            msg = msg % (HexDump.address(address), segment, selector)
            raise ValueError(msg)
        return Base + address

    def get_label_at_pc(self):
        """
        @rtype:  str
        @return: Label that points to the instruction currently being executed.
        """
        return self.get_process().get_label_at_address( self.get_pc() )

    def get_seh_chain_pointer(self):
        """
        Get the pointer to the first structured exception handler block.

        @rtype:  int
        @return: Remote pointer to the first block of the structured exception
            handlers linked list. If the list is empty, the returned value is
            C{0xFFFFFFFF}.

        @raise NotImplementedError:
            This method is only supported in 32 bits versions of Windows.
        """
        if System.arch != win32.ARCH_I386:
            raise NotImplementedError(
                "SEH chain parsing is only supported in 32-bit Windows.")

        process = self.get_process()
        address = self.get_linear_address( 'SegFs', 0 )
        return process.read_pointer( address )

    def set_seh_chain_pointer(self, value):
        """
        Change the pointer to the first structured exception handler block.

        @type  value: int
        @param value: Value of the remote pointer to the first block of the
            structured exception handlers linked list. To disable SEH set the
            value C{0xFFFFFFFF}.

        @raise NotImplementedError:
            This method is only supported in 32 bits versions of Windows.
        """
        if System.arch != win32.ARCH_I386:
            raise NotImplementedError(
                "SEH chain parsing is only supported in 32-bit Windows.")

        process = self.get_process()
        address = self.get_linear_address( 'SegFs', 0 )
        process.write_pointer( address, value )

    def get_seh_chain(self):
        """
        @rtype:  list of tuple( int, int )
        @return: List of structured exception handlers.
            Each SEH is represented as a tuple of two addresses:
                - Address of this SEH block
                - Address of the SEH callback function
            Do not confuse this with the contents of the SEH block itself,
            where the first member is a pointer to the B{next} block instead.

        @raise NotImplementedError:
            This method is only supported in 32 bits versions of Windows.
        """
        seh_chain = list()
        try:
            process = self.get_process()
            seh = self.get_seh_chain_pointer()
            while seh != 0xFFFFFFFF:
                seh_func = process.read_pointer( seh + 4 )
                seh_chain.append( (seh, seh_func) )
                seh = process.read_pointer( seh )
        except WindowsError, e:
            seh_chain.append( (seh, None) )
        return seh_chain

    def get_wait_chain(self):
        """
        @rtype:
            tuple of (
            list of L{win32.WAITCHAIN_NODE_INFO} structures,
            bool)
        @return:
            Wait chain for the thread.
            The boolean indicates if there's a cycle in the chain.
        @raise AttributeError:
            This method is only suppported in Windows Vista and above.
        @see:
            U{http://msdn.microsoft.com/en-us/library/ms681622%28VS.85%29.aspx}
        """
        hWct = win32.OpenThreadWaitChainSession()
        try:
            return win32.GetThreadWaitChain(hWct, None, 0, self.get_tid())
        finally:
            win32.CloseThreadWaitChainSession(hWct)

    def get_stack_range(self):
        """
        @rtype:  tuple( int, int )
        @return: Stack beginning and end pointers, in memory addresses order.
            That is, the first pointer is the stack top, and the second pointer
            is the stack bottom, since the stack grows towards lower memory
            addresses.
        @raise   WindowsError: Raises an exception on error.
        """
        teb = self.get_teb()
        tib = teb.NtTib
        return ( tib.StackLimit, tib.StackBase )    # top, bottom

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

        @raise WindowsError: Raises an exception on error.
        """
        aProcess = self.get_process()
        st, sb   = self.get_stack_range()   # top, bottom
        fp       = self.get_fp()
        trace    = list()
        if aProcess.get_module_count() == 0:
            aProcess.scan_modules()
        while depth > 0:
            if fp == 0:
                break
            if not st <= fp < sb:
                break
            ra  = aProcess.peek_pointer(fp + 4)
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
            fp = aProcess.peek_pointer(fp)
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

        @raise WindowsError: Raises an exception on error.
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

        @raise WindowsError: Raises an exception on error.
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
        st, sb   = self.get_stack_range()   # top, bottom
        sp       = self.get_sp()
        fp       = self.get_fp()
        size     = fp - sp
        if not st <= sp < sb:
            raise RuntimeError('Stack pointer lies outside the stack')
        if not st <= fp < sb:
            raise RuntimeError('Frame pointer lies outside the stack')
        if sp > fp:
            raise RuntimeError('No valid stack frame found')
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
        if count > 0:
            stackData = self.read_stack_data(count * 4, offset)
            return struct.unpack('<'+('L'*count), stackData)
        return ()

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

    def read_stack_qwords(self, count, offset = 0):
        """
        Reads QWORDs from the top of the stack.

        @type  count: int
        @param count: Number of QWORDs to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  tuple( int... )
        @return: Tuple of integers read from the stack.

        @raise WindowsError: Could not read the requested data.
        """
        stackData = self.read_stack_data(count * 8, offset)
        return struct.unpack('<'+('Q'*count), stackData)

    def peek_stack_qwords(self, count, offset = 0):
        """
        Tries to read QWORDs from the top of the stack.

        @type  count: int
        @param count: Number of QWORDs to read.

        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.

        @rtype:  tuple( int... )
        @return: Tuple of integers read from the stack.
            May be less than the requested number of QWORDs.
        """
        stackData = self.peek_stack_data(count * 8, offset)
        if len(stackData) & 7:
            stackData = stackData[:-len(stackData) & 7]
        if not stackData:
            return ()
        return struct.unpack('<'+('Q'*count), stackData)

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

    def disassemble_string(self, lpAddress, code):
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
        aProcess = self.get_process()
        return aProcess.disassemble_string(lpAddress, code)

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

    def disassemble_instruction(self, lpAddress):
        """
        Disassemble the instruction at the given memory address.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @rtype:  tuple( long, int, str, str )
        @return: The tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aProcess = self.get_process()
        return aProcess.disassemble(lpAddress, 15)[0]

    def disassemble_current(self):
        """
        Disassemble the instruction at the program counter of the given thread.

        @rtype:  tuple( long, int, str, str )
        @return: The tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        return self.disassemble_instruction(self.get_pc())

#==============================================================================

# TODO
# + remote GetLastError

class ProcessDebugOperations (object):
    """
    Encapsulates several useful debugging routines for processes.

    @group Properties:
        is_wow64, get_dep_policy, get_peb, get_peb_address,
        get_entry_point, get_main_module, get_image_base, get_image_name,
        get_command_line, get_environment,
        get_command_line_block,
        get_environment_block, get_environment_data, parse_environment_data

    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string, disassemble_instruction, disassemble_current

    @group Debugging:
        flush_instruction_cache, debug_break, peek_pointers_in_data
    """

    # Regular expression to find hexadecimal values of any size.
    __hexa_parameter = re.compile('0x[0-9A-Za-z]+')

    def __fixup_labels(self, disasm):
        """
        Private method used when disassembling from process memory.

        It has no return value because the list is modified in place. On return
        all raw memory addresses are replaced by labels when possible.

        @type  disasm: list of tuple(int, int, str, str)
        @param disasm: Output of one of the dissassembly functions.
        """
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

    def disassemble_string(self, lpAddress, code):
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

        @raise NotImplementedError:
            No compatible disassembler was found for the current platform.
        """
        if System.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            msg = "No disassembler found for architecture: %s" % System.arch
            raise NotImplementedError(msg)
        if (not System.wow64 and System.bits == 32) or self.is_wow64():
            return Decode(lpAddress, code, Decode32Bits)
        return Decode(lpAddress, code, Decode64Bits)

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

    def disassemble_instruction(self, lpAddress):
        """
        Disassemble the instruction at the given memory address.

        @type  lpAddress: int
        @param lpAddress: Memory address where to read the code from.

        @rtype:  tuple( long, int, str, str )
        @return: The tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        return self.disassemble(lpAddress, 15)[0]

    def disassemble_current(self, dwThreadId):
        """
        Disassemble the instruction at the program counter of the given thread.

        @type  dwThreadId: int
        @param dwThreadId: Global thread ID.
            The program counter for this thread will be used as the disassembly
            address.

        @rtype:  tuple( long, int, str, str )
        @return: The tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.
        """
        aThread = self.get_thread(dwThreadId)
        return self.disassemble_instruction(aThread.get_pc())

#------------------------------------------------------------------------------

    def flush_instruction_cache(self):
        """
        Flush the instruction cache. This is required if the process memory is
        modified and one or more threads are executing nearby the modified
        memory region.

        @see: U{http://blogs.msdn.com/oldnewthing/archive/2003/12/08/55954.aspx#55958}

        @raise WindowsError: Raises exception on error.
        """
        win32.FlushInstructionCache( self.get_handle() )

    def debug_break(self):
        """
        Triggers the system breakpoint in the process.

        @raise WindowsError: On error an exception is raised.
        """
        # The exception is raised by a new thread.
        # When continuing the exception, the thread dies by itself.
        # This thread is hidden from the debugger.
        win32.DebugBreakProcess( self.get_handle() )

    def is_wow64(self):
        """
        Determines if the process is running under WOW64.

        @rtype:  bool
        @return:
            C{True} if the process is running under WOW64. That is, a 32-bit
            application running in a 64-bit Windows.

            C{False} if the process is either a 32-bit application running in
            a 32-bit Windows, or a 64-bit application running in a 64-bit
            Windows.

        @raise WindowsError: On error an exception is raised.

        @see: U{http://msdn.microsoft.com/en-us/library/aa384249(VS.85).aspx}
        """
        try:
            wow64 = self.__wow64
        except AttributeError:
            if (System.bits == 32 and not System.wow64):
                wow64 = False
            else:
                hProcess = self.get_handle()
                try:
                    wow64 = win32.IsWow64Process(hProcess)
                except AttributeError:
                    wow64 = False
            self.__wow64 = wow64
        return wow64

    def get_dep_policy(self):
        """
        Retrieves the DEP (Data Execution Prevention) policy for this process.
        
        @note: This method is only available in Windows XP SP3 and above.
            When run on previous versions of Windows a C{WindowsError}
            exception is raised with code C{ERROR_NOT_SUPPORTED}.
        
        @see: U{http://msdn.microsoft.com/en-us/library/bb736297(v=vs.85).aspx}
        
        @rtype:  tuple(int, int)
        @return:
            The first member of the tuple is the DEP flags. It can be a
            combination of the following values:
             - 0: DEP is disabled for this process.
             - 1: DEP is enabled for this process. (C{PROCESS_DEP_ENABLE})
             - 2: DEP-ATL thunk emulation is disabled for this process.
                  (C{PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION})
            
            The second member of the tuple is the permanent flag. If C{TRUE}
            the DEP settings cannot be changed in runtime for this process.
        
        @raise WindowsError: On error an exception is raised.
        """
        try:
            return win32.kernel32.GetProcessDEPPolicy( self.get_handle() )
        except AttributeError:
            raise ctypes.WinError(win32.ERROR_NOT_SUPPORTED)

#------------------------------------------------------------------------------

    def get_peb(self):
        """
        Returns a copy of the PEB.
        To dereference pointers in it call L{Process.read_structure}.

        @rtype:  L{win32.PEB}
        @return: PEB structure.
        @raise WindowsError: An exception is raised on error.
        """
        return self.read_structure(self.get_peb_address(), win32.PEB)

    def get_peb_address(self):
        """
        Returns a remote pointer to the PEB.

        @rtype:  int
        @return: Remote pointer to the L{win32.PEB} structure.
            Returns C{None} on error.
        """
        try:
            return self._peb_ptr
        except AttributeError:
            pbi = win32.NtQueryInformationProcess(self.get_handle(),
                                                     win32.ProcessBasicInformation)
            address = pbi.PebBaseAddress
            self._peb_ptr = address
            return address

    def get_entry_point(self):
        """
        Alias to C{process.get_main_module().get_entry_point()}.
        
        @rtype:  int
        @return: Address of the entry point of the main module.
        """
        return self.get_main_module().get_entry_point()

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

    def get_image_name(self):
        """
        @rtype:  int
        @return: Filename of the process main module.

            This method does it's best to retrieve the filename.
            However sometimes this is not possible, so C{None} may
            be returned instead.
        """

        # Method 1: Module.fileName
        # It's cached if the filename was already found by the other methods,
        # if it came with the corresponding debug event, or it was found by the
        # toolhelp API.
        try:
            mainModule = self.get_main_module()
            name = mainModule.fileName
            if not name:
                name = None
        except (KeyError, AttributeError, WindowsError):
            name = None

        # Method 2: QueryFullProcessImageName()
        # Not implemented until Windows Vista.
        if not name:
            try:
                name = win32.QueryFullProcessImageName(self.get_handle())
            except (AttributeError, WindowsError):
                name = None

        # Method 3: GetProcessImageFileName()
        #
        # Not implemented until Windows XP.
        # For more info see http://blog.voidnish.com/?p=72
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

        # Method 4: GetModuleFileNameEx()
        # Not implemented until Windows 2000.
        #
        # May be spoofed by malware, since this information resides
        # in usermode space (see http://www.ragestorm.net/blogs/?p=163).
        if not name:
            try:
                try:
                    name = win32.GetModuleFileNameEx(self.get_handle())
                except WindowsError:
                    name = win32.GetModuleFileNameEx(self.get_handle(),
                                                     self.get_image_base())
                if name:
                    name = PathOperations.native_to_win32_pathname(name)
                else:
                    name = None
            except (AttributeError, WindowsError):
                if not name:
                    name = None

        # Method 5: PEB.ProcessParameters->ImagePathName
        #
        # May fail since it's using an undocumented internal structure.
        #
        # May be spoofed by malware, since this information resides
        # in usermode space (see http://www.ragestorm.net/blogs/?p=163).
        if not name:
            try:
                peb = self.get_peb()
                pp = self.read_structure(peb.ProcessParameters,
                                             win32.RTL_USER_PROCESS_PARAMETERS)
                s = pp.ImagePathName
                name = self.peek_string(s.Buffer,
                                    dwMaxSize=s.MaximumLength, fUnicode=True)
                if name:
                    name = PathOperations.native_to_win32_pathname(name)
                else:
                    name = None
            except (AttributeError, WindowsError):
                name = None

        # Method 6: Module.get_filename()
        # It tries to get the filename from the file handle.
        #
        # There are currently some problems due to the strange way the API
        # works - it returns the pathname without the drive letter, and I
        # couldn't figure out a way to fix it.
        if not name:
            if vars().has_key('mainModule'):
                try:
                    name = mainModule.get_filename()
                    if not name:
                        name = None
                except (AttributeError, WindowsError):
                    name = None

        # Remember the filename.
        if name:
            try:
                mainModule.fileName = name
            except UnboundLocalError:
                pass

        # Return the image filename, or None on error.
        return name

    def get_command_line_block(self):
        """
        Retrieves the command line block memory address and size.

        @rtype:  tuple(int, int)
        @return: Tuple with the memory address of the command line block
            and it's maximum size in Unicode characters.

        @raise WindowsError: On error an exception is raised.
        """
        peb = self.get_peb()
        pp = self.read_structure(peb.ProcessParameters,
                                             win32.RTL_USER_PROCESS_PARAMETERS)
        s = pp.CommandLine
        return (s.Buffer, s.MaximumLength)

    def get_environment_block(self):
        """
        Retrieves the environment block memory address for the process.

        @note: The size is always C{None} on Windows XP and below.

        @rtype:  tuple(int, int)
        @return: Tuple with the memory address of the environment block
            and it's size.

        @raise WindowsError: On error an exception is raised.
        """
        peb = self.get_peb()
        pp = self.read_structure(peb.ProcessParameters,
                                             win32.RTL_USER_PROCESS_PARAMETERS)
        Environment = pp.Environment
        try:
            EnvironmentSize = pp.EnvironmentSize
        except AttributeError:
            EnvironmentSize = None

        return (Environment, EnvironmentSize)

    def get_command_line(self):
        """
        Retrieves the command line with wich the program was started.

        @rtype:  str
        @return: Command line string.

        @raise WindowsError: On error an exception is raised.
        """
        (Buffer, MaximumLength) = self.get_command_line_block()
        CommandLine = self.peek_string(Buffer, dwMaxSize=MaximumLength,
                                                            fUnicode=True)
        gst = win32.GuessStringType
        if gst.t_default == gst.t_ansi:
            CommandLine = str(CommandLine)
        return CommandLine

    def get_environment_data(self):
        """
        Retrieves the environment block data with wich the program is running.

        @rtype:  list of str
        @return: Environment keys and values separated by a C{=} character,
            as found in the process memory.

        @raise WindowsError: On error an exception is raised.
        """
        block         = list()
        address, size = self.get_environment_block()
        char_size     = ctypes.sizeof(win32.WCHAR)

        # If we know the block size, read the memory once and parse it.
        if size:
            data = self.peek(address, size)
            while data:
                chunk = ctypes.create_unicode_string(data).value
                if not chunk:
                    break
                block.append(chunk)
                data = data[ (len(chunk) + 1) * char_size : ]

        # If we don't know the block size, read the memory many times.
        # XXX FIXME
        # This is inefficient! A process memory cache would help here...
        else:
            while 1:
                chunk = self.peek_string(address,  dwMaxSize = System.pageSize,
                                                    fUnicode = True)
##                print "Chunk: ",
##                print chunk
                if not chunk:
                    break
                block.append(chunk)
                address += (len(chunk) + 1) * char_size

        # Return the environment data.
        return block

    @staticmethod
    def parse_environment_data(block):
        """
        Parse the environment block into a Python dictionary.

        @note: Duplicated keys are joined using null characters.

        @type  block: list of str
        @param block: List of Unicode strings as returned by
            L{get_environment_data}.

        @rtype:  dict(str S{->} str)
        @return: Dictionary of environment keys and values.
        """
        environment = dict()

        # Split the blocks into key/value pairs.
        for chunk in block:
            sep = chunk.find(u'=')
            if sep >= 0:
                key, value = chunk[:sep], chunk[sep:]
            else:
                key, value = chunk, u''
            if not environment.has_key(key):
                environment[key] = value
            else:
                environment[key] += u'\0' + value

        # Convert to ANSI if this is the default string type.
        gst = win32.GuessStringType
        if gst.t_default == gst.t_ansi:
            environment = dict( [ (str(key), str(value)) \
                                for (key, value) in environment.iteritems() ] )

        # Return the environment dictionary.
        return environment

    def get_environment(self):
        """
        Retrieves the environment with wich the program is running.

        @note: Duplicated keys are joined using null characters.

        @rtype:  dict(str S{->} str)
        @return: Dictionary of environment keys and values.

        @raise WindowsError: On error an exception is raised.
        """
        return self.parse_environment_data( self.get_environment_data() )

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
        ptrSize = win32.sizeof(win32.LPVOID)
        if ptrSize == 4:
            ptrFmt = '<L'
        else:
            ptrFmt = '<Q'
        if len(data) > 0:
            for i in xrange(0, len(data), peekStep):
                packed          = data[i:i+ptrSize]
                if len(packed) == ptrSize:
                    address     = struct.unpack(ptrFmt, packed)[0]
##                    if not address & (~0xFFFF): continue
                    peek_data   = self.peek(address, peekSize)
                    if peek_data:
                        result[i] = peek_data
        return result

#==============================================================================

# Unlike Process, Thread and Module, there's no container for Window objects.
# That's because Window objects don't really store any data besides the handle.

# XXX TODO
# * implement sending fake user input (mouse and keyboard messages)
# * maybe implement low-level hooks? (they don't require a dll to be injected)

# XXX TODO
#
# Will it be possible to implement window hooks too? That requires a DLL to be
# injected in the target process. Perhaps with CPython it could be done easier,
# compiling a native extension is the safe bet, but both require having a non
# pure Python module, which is something I was trying to avoid so far.
#
# Another possibility would be to malloc some CC's in the target process and
# point the hook callback to it. We'd need to have the remote procedure call
# feature first as (I believe) the hook can't be set remotely in this case.

class Window (object):
    """
    Interface to an open window in the current desktop.

    @group Properties:
        hWnd, dwProcessId, dwThreadId,
        get_handle, get_pid, get_tid,
        get_process, get_thread,
        set_process, set_thread,
        get_classname, get_text, set_text, get_placement, set_placement,
        screen_to_client, client_to_screen

    @group State:
        is_valid, is_visible, is_enabled, is_maximized, is_minimized, is_child,
        is_zoomed, is_iconic

    @group Navigation:
        get_parent, get_children, get_root, get_tree,
        get_child_at

    @group Instrumentation:
        enable, disable, show, hide, maximize, minimize, restore, move, kill

    @group Low-level access:
        send, post

    @type hWnd: int
    @ivar hWnd: Window handle.

    @type dwProcessId: int
    @ivar dwProcessId: Global ID of the process that owns this window.

    @type dwThreadId: int
    @ivar dwThreadId: Global ID of the thread that owns this window.

    @type process: L{Process}
    @ivar process: Process that owns this window.
        Use the L{get_process} method instead.

    @type thread: L{Thread}
    @ivar thread: Thread that owns this window.
        Use the L{get_thread} method instead.
    """

    def __init__(self, hWnd = None, process = None, thread = None):
        """
        @type  hWnd: int or L{win32.HWND}
        @param hWnd: Window handle.

        @type  process: L{Process}
        @param process: (Optional) Process that owns this window.

        @type  thread: L{Thread}
        @param thread: (Optional) Thread that owns this window.
        """
        self.hWnd        = hWnd
        self.dwProcessId = None
        self.dwThreadId  = None
        self.set_process(process)
        self.set_thread(thread)

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Window object to an API call.
        """
        return self.get_handle()

    def get_handle(self):
        """
        @rtype:  int
        @return: Window handle.
        @raise ValueError: No window handle set.
        """
        if self.hWnd is None:
            raise ValueError("No window handle set!")
        return self.hWnd

    def get_pid(self):
        """
        @rtype:  int
        @return: Global ID of the process that owns this window.
        """
        if self.dwProcessId is not None:
            return self.dwProcessId
        self.__get_pid_and_tid()
        return self.dwProcessId

    def get_tid(self):
        """
        @rtype:  int
        @return: Global ID of the thread that owns this window.
        """
        if self.dwThreadId is not None:
            return self.dwThreadId
        self.__get_pid_and_tid()
        return self.dwThreadId

    def __get_pid_and_tid(self):
        "Internally used by get_pid() and get_tid()."
        self.dwThreadId, self.dwProcessId = \
                                      win32.GetWindowThreadProcessId(self.hWnd)

    def get_process(self):
        """
        @rtype:  L{Process}
        @return: Parent Process object.
            Returns C{None} if unknown.
        """
        if self.__process is not None:
##            if isinstance(self.__process, weakref.ref):
##                process = self.__process()
##                if process is not None:
##                    return process
####                else:   # XXX DEBUG
####                    print "Lost reference to parent process at %r" % self
##            else:
                return self.__process
        # can't use weakrefs here, it's our only reference
        self.__process = Process(self.get_pid())
        return self.__process

    def set_process(self, process = None):
        """
        Manually set the parent process. Use with care!

        @type  process: L{Process}
        @param process: (Optional) Process object. Use C{None} for no process.
        """
        if process is None:
            self.__process = None
        else:
            if not isinstance(process, Process):
                msg  = "Parent process must be a Process instance, "
                msg += "got %s instead" % type(process)
                raise TypeError(msg)
            self.dwProcessId = process.get_pid()
##            self.__process = weakref.ref(process)
            self.__process = process

    # This horrible kludge is needed to keep Epydoc from complaining...
    # if it wasn't for that it'd be a tidy one liner. :P
    tmp = get_process.__doc__, set_process.__doc__
    del get_process.__doc__
    del set_process.__doc__
    process = property(get_process, set_process)
    get_process.__doc__, set_process.__doc__ = tmp
    del tmp

    def get_thread(self):
        """
        @rtype:  L{Thread}
        @return: Parent Thread object.
            Returns C{None} if unknown.
        """
        if self.__thread is not None:
##            if isinstance(self.__thread, weakref.ref):
##                thread = self.__thread()
##                if thread is not None:
##                    return thread
####                else:   # XXX DEBUG
####                    print "Lost reference to parent thread at %r" % self
##            else:
                return self.__thread
        # can't use weakrefs here, it's our only reference
        self.__thread = Thread(self.get_tid())
        return self.__thread

    def set_thread(self, thread = None):
        """
        Manually set the thread process. Use with care!

        @type  thread: L{Thread}
        @param thread: (Optional) Thread object. Use C{None} for no thread.
        """
        if thread is None:
            self.__thread = None
        else:
            if not isinstance(thread, Thread):
                msg  = "Parent thread must be a Thread instance, "
                msg += "got %s instead" % type(thread)
                raise TypeError(msg)
            self.dwThreadId = thread.get_tid()
##            self.__thread = weakref.ref(thread)
            self.__thread = thread

    # This horrible kludge is needed to keep Epydoc from complaining...
    # if it wasn't for that it'd be a tidy one liner. :P
    tmp = get_thread.__doc__, set_thread.__doc__
    del get_thread.__doc__
    del set_thread.__doc__
    thread = property(get_thread, set_thread)
    get_thread.__doc__, set_thread.__doc__ = tmp
    del tmp

    def __get_window(self, hWnd):
        """
        User internally to get another Window from this one.
        It'll try to copy the parent Process and Thread references if possible.
        """
        window = Window(hWnd)
        if window.get_pid() == self.get_pid():
            window.set_process( self.get_process() )
        if window.get_tid() == self.get_tid():
            window.set_thread( self.get_thread() )
        return window

#------------------------------------------------------------------------------

    def get_classname(self):
        """
        @rtype:  str
        @return: Window class name.
        @raise WindowsError: An error occured while processing this request.
        """
        return win32.GetClassName( self.get_handle() )

    def get_text(self):
        """
        @see:    L{set_text}
        @rtype:  str
        @return: Window text (caption).
        """
        length = self.send(win32.WM_GETTEXTLENGTH)
        if not length:
            raise ctypes.WinError()
        length = length + 1
        c_buffer = ctypes.create_string_buffer("", length)
        success = self.send(win32.WM_GETTEXT, length, c_buffer)
        if success == 0:
            return ""
        return c_buffer.value

    def set_text(self, text):
        """
        Set the window text (caption).

        @see: L{get_text}

        @type  text: str
        @param text: New window text.
        """
        return self.send(win32.WM_SETTEXT, len(text), text)

    def get_placement(self):
        """
        Retrieve the window placement in the desktop.

        @see: L{set_placement}

        @rtype:  L{win32.WindowPlacement}
        @return: Window placement in the desktop.
        """
        return win32.GetWindowPlacement( self.get_handle() )

    def set_placement(self, placement):
        """
        Set the window placement in the desktop.

        @see: L{get_placement}

        @type  placement: L{win32.WindowPlacement}
        @param placement: Window placement in the desktop.

        @raise WindowsError: An error occured while processing this request.
        """
        win32.SetWindowPlacement( self.get_handle(), placement )

    # XXX TODO
    # * get_screen_rect, get_client_rect
    # * properties x, y, width, height
    # * properties left, top, right, bottom

#------------------------------------------------------------------------------

    def client_to_screen(self, x, y):
        """
        Translates window client coordinates to screen coordinates.

        @note: This is a simplified interface to some of the functionality of
            the L{win32.Point} class.

        @see: {win32.Point.client_to_screen}

        @type  x: int
        @param x: Horizontal coordinate.
        @type  y: int
        @param y: Vertical coordinate.

        @rtype:  tuple( int, int )
        @return: Translated coordinates in a tuple (x, y).

        @raise WindowsError: An error occured while processing this request.
        """
        return tuple( ClientToScreen( self.get_handle(), (x, y) ) )

    def screen_to_client(self, x, y):
        """
        Translates window screen coordinates to client coordinates.

        @note: This is a simplified interface to some of the functionality of
            the L{win32.Point} class.

        @see: {win32.Point.screen_to_client}

        @type  x: int
        @param x: Horizontal coordinate.
        @type  y: int
        @param y: Vertical coordinate.

        @rtype:  tuple( int, int )
        @return: Translated coordinates in a tuple (x, y).

        @raise WindowsError: An error occured while processing this request.
        """
        return tuple( ScreenToClient( self.get_handle(), (x, y) ) )

#------------------------------------------------------------------------------

    def get_parent(self):
        """
        @see:    L{get_children}
        @rtype:  L{Window} or None
        @return: Parent window. Returns C{None} if the window has no parent.
        @raise WindowsError: An error occured while processing this request.
        """
        hWnd = win32.GetParent( self.get_handle() )
        if hWnd:
            return self.__get_window(hWnd)

    def get_children(self):
        """
        @see:    L{get_parent}
        @rtype:  list( L{Window} )
        @return: List of child windows.
        @raise WindowsError: An error occured while processing this request.
        """
        return [
                self.__get_window(hWnd) \
                for hWnd in win32.EnumChildWindows( self.get_handle() )
                ]

    def get_tree(self):
        """
        @see:    L{get_root}
        @rtype:  dict( L{Window} S{->} dict( ... ) )
        @return: Dictionary of dictionaries forming a tree of child windows.
        @raise WindowsError: An error occured while processing this request.
        """
        subtree = dict()
        for aWindow in self.get_children():
            subtree[ aWindow ] = aWindow.get_tree()
        return subtree

    def get_root(self):
        """
        @see:    L{get_tree}
        @rtype:  L{Window}
        @return: Root window for this tree.
        @raise RuntimeError: Can't find the root window for this tree.
        @raise WindowsError: An error occured while processing this request.
        """
        hWnd     = self.get_handle()
        history  = set()
        hPrevWnd = hWnd
        while hWnd and hWnd not in history:
            history.add(hWnd)
            hPrevWnd = hWnd
            hWnd     = win32.GetParent(hWnd)
        if hWnd in history:
            # See: https://docs.google.com/View?id=dfqd62nk_228h28szgz
            raise RuntimeError("Can't find the root window for this tree")
        if hPrevWnd != self.hWnd:
            return self.__get_window(hPrevWnd)
        return self

    def get_child_at(self, x, y):
        """
        Get the child window located at the given coordinates. If no such
        window exists an exception is raised.

        @see: L{get_children}

        @type  x: int
        @param x: Horizontal coordinate.
        @type  y: int
        @param y: Vertical coordinate.

        @rtype:  L{Window}
        @return: Child window at the requested position. If no such window
            exists a C{WindowsError} exception is raised.

        @raise WindowsError: An error occured while processing this request.
        """
        win32.ChildWindowFromPoint( self.get_handle(), (x, y) )
##        win32.RealChildWindowFromPoint( self.get_handle(), (x, y) )

#------------------------------------------------------------------------------

    def is_valid(self):
        """
        @rtype:  bool
        @return: C{True} if the window handle is still valid.
        """
        return win32.IsWindow( self.get_handle() )

    def is_visible(self):
        """
        @see: {show}, {hide}
        @rtype:  bool
        @return: C{True} if the window is in a visible state.
        """
        return win32.IsWindowVisible( self.get_handle() )

    def is_enabled(self):
        """
        @see: {enable}, {disable}
        @rtype:  bool
        @return: C{True} if the window is in an enabled state.
        """
        return win32.IsWindowEnabled( self.get_handle() )

    def is_maximized(self):
        """
        @see: L{maximize}
        @rtype:  bool
        @return: C{True} if the window is maximized.
        """
        return win32.IsZoomed( self.get_handle() )

    def is_minimized(self):
        """
        @see: L{minimize}
        @rtype:  bool
        @return: C{True} if the window is minimized.
        """
        return win32.IsIconic( self.get_handle() )

    def is_child(self):
        """
        @see: L{get_parent}
        @rtype:  bool
        @return: C{True} if the window is a child window.
        """
        return win32.IsChild( self.get_handle() )

    is_zoomed = is_maximized
    is_iconic = is_minimized

#------------------------------------------------------------------------------

    def enable(self):
        """
        Enable the user input for the window.

        @see: L{disable}

        @raise WindowsError: An error occured while processing this request.
        """
        win32.EnableWindow( self.get_handle(), True )

    def disable(self):
        """
        Disable the user input for the window.

        @see: L{enable}

        @raise WindowsError: An error occured while processing this request.
        """
        win32.EnableWindow( self.get_handle(), False )

    def show(self, bAsync = True):
        """
        Make the window visible.

        @see: L{hide}

        @type  bAsync: bool
        @param bAsync: Perform the request asynchronously.

        @raise WindowsError: An error occured while processing this request.
        """
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_SHOW )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_SHOW )

    def hide(self, bAsync = True):
        """
        Make the window invisible.

        @see: L{show}

        @type  bAsync: bool
        @param bAsync: Perform the request asynchronously.

        @raise WindowsError: An error occured while processing this request.
        """
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_HIDE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_HIDE )

    def maximize(self, bAsync = True):
        """
        Maximize the window.

        @see: L{minimize}, L{restore}

        @type  bAsync: bool
        @param bAsync: Perform the request asynchronously.

        @raise WindowsError: An error occured while processing this request.
        """
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_MAXIMIZE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_MAXIMIZE )

    def minimize(self, bAsync = True):
        """
        Minimize the window.

        @see: L{maximize}, L{restore}

        @type  bAsync: bool
        @param bAsync: Perform the request asynchronously.

        @raise WindowsError: An error occured while processing this request.
        """
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_MINIMIZE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_MINIMIZE )

    def restore(self, bAsync = True):
        """
        Unmaximize and unminimize the window.

        @see: L{maximize}, L{minimize}

        @type  bAsync: bool
        @param bAsync: Perform the request asynchronously.

        @raise WindowsError: An error occured while processing this request.
        """
        if bAsync:
            win32.ShowWindowAsync( self.get_handle(), win32.SW_RESTORE )
        else:
            win32.ShowWindow( self.get_handle(), win32.SW_RESTORE )

    def move(self, x, y, width, height, bRepaint = True):
        """
        Moves and/or resizes the window.

        @note: This is request is performed syncronously.

        @type  x: int
        @param x: New horizontal coordinate.

        @type  y: int
        @param y: New vertical coordinate.

        @type  width: int
        @param width: Desired window width.

        @type  height: int
        @param height: Desired window height.

        @type  bRepaint: bool
        @param bRepaint: C{True} if the window should be redrawn afterwards.

        @raise WindowsError: An error occured while processing this request.
        """
        # XXX TODO
        # Make the parameters optional by querying the current position first.
        win32.MoveWindow(self.get_handle(), x, y, width, height, bRepaint)

    def kill(self):
        """
        Signals the program to quit.

        @note: This is an asyncronous request.

        @raise WindowsError: An error occured while processing this request.
        """
        self.post(win32.WM_QUIT)

    def send(self, uMsg, wParam = None, lParam = None):
        """
        Send a low-level window message syncronically.

        @type  uMsg: int
        @param uMsg: Message code.

        @param wParam:
            The type and meaning of this parameter depends on the message.

        @param lParam:
            The type and meaning of this parameter depends on the message.

        @rtype:  int
        @return: The meaning of the return value depends on the window message.
            Typically a value of C{0} means an error occured. You can get the
            error code by calling L{win32.GetLastError}.
        """
        return win32.SendMessage(self.get_handle(), uMsg, wParam, lParam)

    def post(self, uMsg, wParam = None, lParam = None):
        """
        Post a low-level window message asyncronically.

        @type  uMsg: int
        @param uMsg: Message code.

        @param wParam:
            The type and meaning of this parameter depends on the message.

        @param lParam:
            The type and meaning of this parameter depends on the message.

        @raise WindowsError: An error occured while sending the message.
        """
        win32.PostMessage(self.get_handle(), uMsg, wParam, lParam)

#==============================================================================

class Module (SymbolContainer):
    """
    Interface to a DLL library loaded in the context of another process.

    @group Properties:
        get_base, get_filename, get_name, get_size, get_entry_point,
        get_process, set_process, get_pid

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
        Use the L{get_process} method instead.
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
        self.set_process(process)

    # Not really sure if it's a good idea...
##    def __eq__(self, aModule):
##        """
##        Compare two Module objects. The comparison is made using the process
##        IDs and the module bases.
##
##        @type  aModule: L{Module}
##        @param aModule: Another Module object.
##
##        @rtype:  bool
##        @return: C{True} if the two process IDs and module bases are equal,
##            C{False} otherwise.
##        """
##        return isinstance(aModule, Module)           and \
##               self.get_pid() == aModule.get_pid()   and \
##               self.get_base() == aModule.get_base()

    def get_process(self):
        """
        @rtype:  L{Process}
        @return: Parent Process object.
            Returns C{None} if unknown.
        """
        if self.__process is not None:
##            if isinstance(self.__process, weakref.ref):
##                process = self.__process()
##                if process is not None:
##                    return process
####                else:   # XXX DEBUG
####                    print "Lost reference to parent process at %r" % self
##            else:
                return self.__process
        # no way to guess!
        return None

    def set_process(self, process = None):
        """
        Manually set the parent process. Use with care!

        @type  process: L{Process}
        @param process: (Optional) Process object. Use C{None} for no process.
        """
        if process is None:
            self.__process = None
        else:
            if not isinstance(process, Process):
                msg  = "Parent process must be a Process instance, "
                msg += "got %s instead" % type(process)
                raise TypeError(msg)
##            self.__process = weakref.ref(process)
            self.__process = process

    # This horrible kludge is needed to keep Epydoc from complaining...
    # if it wasn't for that it'd be a tidy one liner. :P
    tmp = get_process.__doc__, set_process.__doc__
    del get_process.__doc__
    del set_process.__doc__
    process = property(get_process, set_process)
    get_process.__doc__, set_process.__doc__ = tmp
    del tmp

    def get_pid(self):
        """
        @rtype:  int or None
        @return: Parent process global ID.
            Returns C{None} on error.
        """
        process = self.get_process()
        if process is not None:
            return process.get_pid()

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
##                raise       # XXX DEBUG
                pass

    def get_filename(self):
        """
        @rtype:  str or None
        @return: Module filename.
            Returns C{None} if unknown.
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
        @type  pathname: str
        @param pathname: Pathname to a module.

        @rtype:  str
        @return: Module name.
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

#------------------------------------------------------------------------------

    def open_handle(self):
        """
        Opens a new handle to the module.

        The new handle is stored in the L{hFile} property.
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

        @note: Normally you don't need to call this method. All handles
            created by I{WinAppDbg} are automatically closed when the garbage
            collector claims them. So unless you've been tinkering with it,
            setting L{hFile} to C{None} should be enough.
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
        if address in (None, 0):
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
            raise RuntimeError("Label does not belong to this module")

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
                    raise RuntimeError(msg % (procedure, module))

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
        get_tid, get_pid, get_process, set_process, get_exit_code, is_alive,
        get_name, set_name, get_windows
    @group Instrumentation:
        suspend, resume, kill, wait
    @group Registers:
        get_context,
        get_register,
        get_flags, get_flag_value,
        get_pc, get_sp, get_fp,
        get_gp, get_rp,
        get_cf, get_df, get_sf, get_tf, get_zf,
        set_context,
        set_register,
        set_flags, set_flag_value,
        set_pc, set_sp, set_fp,
        set_gp, set_rp,
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
        self.set_name()
        self.set_process(process)

    # Not really sure if it's a good idea...
##    def __eq__(self, aThread):
##        """
##        Compare two Thread objects. The comparison is made using the IDs.
##
##        @warning:
##            If you have two Thread instances with different handles the
##            equality operator still returns C{True}, so be careful!
##
##        @type  aThread: L{Thread}
##        @param aThread: Another Thread object.
##
##        @rtype:  bool
##        @return: C{True} if the two thread IDs are equal,
##            C{False} otherwise.
##        """
##        return isinstance(aThread, Thread)           and \
##               self.get_tid() == aThread.get_tid()

    def get_process(self):
        """
        @rtype:  L{Process}
        @return: Parent Process object.
            Returns C{None} if unknown.
        """
        if self.__process is not None:
##            if isinstance(self.__process, weakref.ref):
##                process = self.__process()
##                if process is not None:
##                    return process
####                else:   # XXX DEBUG
####                    print "Lost reference to parent process at %r" % self
##            else:
                return self.__process
        # can't use weakrefs here, it's our only reference
        self.__process = Process(self.get_pid())
        return self.__process

    def set_process(self, process = None):
        """
        Manually set the parent Process object. Use with care!

        @type  process: L{Process}
        @param process: (Optional) Process object. Use C{None} for no process.
        """
        if process is None:
            self.__process = None
        else:
            if not isinstance(process, Process):
                msg  = "Parent process must be a Process instance, "
                msg += "got %s instead" % type(process)
                raise TypeError(msg)
            self.dwProcessId = process.get_pid()
##            self.__process = weakref.ref(process)
            self.__process = process

    # This horrible kludge is needed to keep Epydoc from complaining...
    # if it wasn't for that it'd be a tidy one liner. :P
    tmp = get_process.__doc__, set_process.__doc__
    del get_process.__doc__
    del set_process.__doc__
    process = property(get_process, set_process)
    get_process.__doc__, set_process.__doc__ = tmp
    del tmp

    def get_pid(self):
        """
        @rtype:  int
        @return: Parent process global ID.

        @raise WindowsError: An error occured when calling a Win32 API function.
        @raise RuntimeError: The parent process ID can't be found.
        """
        if self.dwProcessId is None:
            if self.__process is not None:
                # Infinite loop if self.__process is None
                self.dwProcessId = self.get_process().get_pid()
            else:
                hThread = self.get_handle()
                try:
                    # I wish this had been implemented before Vista...
                    # XXX TODO find the real ntdll call under this api
                    self.dwProcessId = win32.GetProcessIdOfThread(hThread)
                except AttributeError:
                    # This method really sucks :P
                    self.dwProcessId = self.__get_pid_by_scanning()
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
            raise RuntimeError(msg)
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

        The new handle is stored in the L{hThread} property.
        """
        hThread = win32.OpenThread(dwDesiredAccess, win32.FALSE, self.dwThreadId)

        # In case hThread was set to an actual handle value instead of a Handle
        # object. This shouldn't happen unless the user tinkered with hFile.
        if not hasattr(self.hThread, '__del__'):
            self.close_handle()

        self.hThread = hThread

    def close_handle(self):
        """
        Closes the handle to the thread.

        @note: Normally you don't need to call this method. All handles
            created by I{WinAppDbg} are automatically closed when the garbage
            collector claims them. So unless you've been tinkering with it,
            setting L{hThread} to C{None} should be enough.
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
##                raise           # XXX DEBUG
                pass

    # XXX TODO
    # suspend() and resume() should have a counter of how many times a thread
    # was suspended, so on debugger exit they could (optionally!) be restored

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

    # XXX TODO
    # Support for string searches on the window captions.

    def get_windows(self):
        """
        @rtype:  list of L{Window}
        @return: Returns a list of windows handled by this thread.
        """
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
    def get_context(self, ContextFlags = None):
        """
        @type  ContextFlags: int
        @param ContextFlags: Optional, specify which registers to retrieve.
            Defaults to C{win32.CONTEXT_ALL} which retrieves all registes
            for the current platform.

        @rtype:  dict( str S{->} int )
        @return: Dictionary mapping register names to their values.

        @see: L{set_context}
        """

        # Get the thread handle.
        hThread = self.get_handle()

        # Threads can't be suspended when the exit process event arrives.
        # Funny thing is, you can still get the context. (?)
        try:
            self.suspend()
            bSuspended = True
        except WindowsError:
            bSuspended = False

        # If an exception is raised, make sure the thread execution is resumed.
        try:

            # If we're not in WOW64, things are simple :)
            if not System.wow64:
##                if self.is_wow64():
##                    if ContextFlags is not None:
##                        ContextFlags = ContextFlags & (~win32.ContextArchMask)
##                        ContextFlags = ContextFlags | win32.WOW64_CONTEXT_i386
##                    ctx = win32.Wow64GetThreadContext(hThread,
##                                                 ContextFlags = ContextFlags)
##                else:
                    ctx = win32.GetThreadContext(hThread,
                                                 ContextFlags = ContextFlags)

            # If we're in WOW64, things are tricky!
            else:
                if self.is_wow64():
                    ctx = win32.GetThreadContext(hThread,
                                                 ContextFlags = ContextFlags)
                else:
                    # XXX only i386/AMD64 is supported in this particular case
                    if System.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
                        raise NotImplementedError()
                    if ContextFlags is not None:
                        ContextFlags = ContextFlags & (~win32.ContextArchMask)
                        ContextFlags = ContextFlags | win32.context_amd64.CONTEXT_AMD64
                    ctx = win32.context_amd64.GetThreadContext(hThread,
                                                 ContextFlags = ContextFlags)
        finally:
            if bSuspended:
                self.resume()
        return ctx

    def set_context(self, context):
        """
        Sets the values of the registers.

        @see: L{get_context}

        @type  context:  dict( str S{->} int )
        @param context: Dictionary mapping register names to their values.
        """
        # No fix for the exit process event bug.
        # Setting the context of a dead thread is pointless anyway.
        self.suspend()
        try:
            if System.bits == 64 and self.is_wow64():
                win32.Wow64SetThreadContext(self.get_handle(), context)
            else:
                win32.SetThreadContext(self.get_handle(), context)
        finally:
            self.resume()

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

    if win32.CONTEXT.arch in (win32.ARCH_I386, win32.ARCH_AMD64):

        def get_pc(self):
            """
            @rtype:  int
            @return: Value of the program counter register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.pc

        def set_pc(self, pc):
            """
            Sets the value of the program counter register.

            @type  pc: int
            @param pc: Value of the program counter register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.pc = pc
            self.set_context(context)

        def get_sp(self):
            """
            @rtype:  int
            @return: Value of the stack pointer register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.sp

        def set_sp(self, sp):
            """
            Sets the value of the stack pointer register.

            @type  sp: int
            @param sp: Value of the stack pointer register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.sp = sp
            self.set_context(context)

        def get_fp(self):
            """
            @rtype:  int
            @return: Value of the frame pointer register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.fp

        def set_fp(self, fp):
            """
            Sets the value of the frame pointer register.

            @type  fp: int
            @param fp: Value of the frame pointer register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.fp = fp
            self.set_context(context)

    elif win32.CONTEXT.arch == win32.ARCH_IA64:

        def get_gp(self):
            """
            @rtype:  int
            @return: Value of the GP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.gp

        def set_gp(self, gp):
            """
            Sets the value of the frame pointer register.

            @type  gp: int
            @param gp: Value of the GP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.gp = gp
            self.set_context(context)

        def get_sp(self):
            """
            @rtype:  int
            @return: Value of the SP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.sp

        def set_sp(self, sp):
            """
            Sets the value of the SP register.

            @type  sp: int
            @param sp: Value of the SP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.sp = sp
            self.set_context(context)

        def get_rp(self):
            """
            @rtype:  int
            @return: Value of the RP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            return context.rp

        def set_rp(self, rp):
            """
            Sets the value of the RP register.

            @type  rp: int
            @param rp: Value of the RP register.
            """
            context = self.get_context(win32.CONTEXT_CONTROL)
            context.rp = rp
            self.set_context(context)

#------------------------------------------------------------------------------

    if win32.CONTEXT.arch in (win32.ARCH_I386, win32.ARCH_AMD64):

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
        kill, wait, suspend, resume, inject_code, inject_dll, clean_exit

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

        The new handle is stored in the L{hProcess} property.
        """
        hProcess = win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE,
                                                              self.dwProcessId)

        # In case hProcess was set to an actual handle value instead of a Handle
        # object. This shouldn't happen unless the user tinkered with hFile.
        if not hasattr(self.hProcess, '__del__'):
            self.close_handle()

        self.hProcess = hProcess

    def close_handle(self):
        """
        Closes the handle to the process.

        @note: Normally you don't need to call this method. All handles
            created by I{WinAppDbg} are automatically closed when the garbage
            collector claims them. So unless you've been tinkering with it,
            setting L{hProcess} to C{None} should be enough.
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

    # Not really sure if it's a good idea...
##    def __eq__(self, aProcess):
##        """
##        Compare two Process objects. The comparison is made using the IDs.
##
##        @warning:
##            If you have two Process instances with different handles the
##            equality operator still returns C{True}, so be careful!
##
##        @type  aProcess: L{Process}
##        @param aProcess: Another Process object.
##
##        @rtype:  bool
##        @return: C{True} if the two process IDs are equal,
##            C{False} otherwise.
##        """
##        return isinstance(aProcess, Process)         and \
##               self.get_pid() == aProcess.get_pid()

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

        def __iter__(self):
            'x.__iter__() <==> iter(x)'
            return self

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
            return win32.winerror(e) == win32.WAIT_TIMEOUT
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

        @raise NotImplementedError: The target platform is not supported.
            Currently calling a procedure in the library is only supported in
            the I{i386} architecture.

        @raise WindowsError: An exception is raised on error.
        """

        # Resolve kernel32.dll
        aModule = self.get_module_by_name('kernel32.dll')
        if aModule is None:
            self.scan_modules()
            aModule = self.get_module_by_name('kernel32.dll')
        if aModule is None:
            raise RuntimeError(
                "Cannot resolve kernel32.dll in the remote process")

        # Old method, using shellcode.
        if procname:
            if System.arch != win32.ARCH_I386:
                raise NotImplementedError()
            dllname = str(dllname)

            # Resolve kernel32.dll!LoadLibraryA
            pllib = aModule.resolve('LoadLibraryA')
            if not pllib:
                raise RuntimeError(
                    "Cannot resolve kernel32.dll!LoadLibraryA"
                    " in the remote process")

            # Resolve kernel32.dll!GetProcAddress
            pgpad = aModule.resolve('GetProcAddress')
            if not pgpad:
                raise RuntimeError(
                    "Cannot resolve kernel32.dll!GetProcAddress"
                    " in the remote process")

            # Resolve kernel32.dll!VirtualFree
            pvf = aModule.resolve('VirtualFree')
            if not pvf:
                raise RuntimeError(
                    "Cannot resolve kernel32.dll!VirtualFree"
                    " in the remote process")

            # Shellcode follows...
            code  = ''.encode('utf8')

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

        # New method, not using shellcode.
        else:

            # Resolve kernel32.dll!LoadLibrary (A/W)
            if type(dllname) == type(u''):
                pllibname = 'LoadLibraryW'
                bufferlen = (len(dllname) + 1) * 2
                dllname = win32.ctypes.create_unicode_buffer(dllname).raw[:bufferlen + 1]
            else:
                pllibname = 'LoadLibraryA'
                dllname   = str(dllname) + '\x00'
                bufferlen = len(dllname)
            pllib = aModule.resolve(pllibname)
            if not pllib:
                msg = "Cannot resolve kernel32.dll!%s in the remote process"
                raise RuntimeError(msg % pllibname)

            # Copy the library name into the process memory space.
            pbuffer = self.malloc(bufferlen)
            try:
                self.write(pbuffer, dllname)

                # Create a new thread to load the library.
                aThread = self.start_thread(pllib, pbuffer)

                # Remember the buffer address.
                #  It will be freed ONLY by the Thread.kill() method
                #  and the EventHandler class, otherwise you'll have to
                #  free it in your code.
                aThread.pInjectedMemory = pbuffer

            # Free the memory on error.
            except Exception:
                self.free(pbuffer, bufferlen)
                raise

        # Wait for the thread to finish.
        # XXX TODO free the injected memory here too
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

        This is done automatically by the L{Debug} class, you shouldn't need
        to call it yourself.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
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

    @group Platform settings:
        arch, bits, os, wow64, pageSize

    @group Instrumentation:
        find_window, get_window_at, get_desktop_window, get_foreground_window

    @group Debugging:
        load_dbghelp, request_debug_privileges

    @group Postmortem debugging:
        get_postmortem_debugger, set_postmortem_debugger,
        get_postmortem_exclusion_list, add_to_postmortem_exclusion_list,
        remove_from_postmortem_exclusion_list

    @group Miscellaneous global settings:
        set_kill_on_exit_mode, read_msr, write_msr, enable_step_on_branch_mode,
        get_last_branch_location

    @type arch: str
    @cvar arch: Name of the processor architecture we're running on.
        For more details see L{win32.version._get_arch}.

    @type bits: int
    @cvar bits: Size of the machine word in bits for the current architecture.
        For more details see L{win32.version._get_bits}.

    @type os: str
    @cvar os: Name of the Windows version we're runing on.
        For more details see L{win32.version._get_os}.

    @type wow64: bool
    @cvar wow64: C{True} if the debugger is a 32 bits process running in a 64
        bits version of Windows, C{False} otherwise.

    @type pageSize: int
    @cvar pageSize: Page size in bytes. Defaults to 0x1000 but it's
        automatically updated on runtime when importing the module.

    @type registry: L{Registry}
    @cvar registry: Windows Registry for this machine.
    """

    arch  = win32.arch
    bits  = win32.bits
    os    = win32.os
    wow64 = win32.wow64

    pageSize = MemoryAddresses.pageSize

    registry = Registry()

#------------------------------------------------------------------------------

    @staticmethod
    def find_window(className = None, windowName = None):
        """
        Find the first top-level window in the current desktop to match the
        given class name and/or window name. If neither are provided any
        top-level window will match.

        @see: L{get_window_at}

        @type  className: str
        @param className: (Optional) Class name of the window to find.
            If C{None} or not used any class name will match the search.

        @type  windowName: str
        @param windowName: (Optional) Caption text of the window to find.
            If C{None} or not used any caption text will match the search.

        @rtype:  L{Window} or None
        @return: A window that matches the request. There may be more matching
            windows, but this method only returns one. If no matching window
            is found, the return value is C{None}.

        @raise WindowsError: An error occured while processing this request.
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

        @see: L{find_window}

        @type  x: int
        @param x: Horizontal coordinate.
        @type  y: int
        @param y: Vertical coordinate.

        @rtype:  L{Window}
        @return: Window at the requested position. If no such window
            exists a C{WindowsError} exception is raised.

        @raise WindowsError: An error occured while processing this request.
        """
        return Window( win32.WindowFromPoint( (x, y) ) )

    @staticmethod
    def get_desktop_window():
        """
        @rtype:  L{Window}
        @return: Returns the desktop window.
        @raise WindowsError: An error occured while processing this request.
        """
        return Window( win32.GetDesktopWindow() )

    @staticmethod
    def get_foreground_window():
        """
        @rtype:  L{Window}
        @return: Returns the foreground window.
        @raise WindowsError: An error occured while processing this request.
        """
        return Window( win32.GetForegroundWindow() )

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
        Defines the behavior of the debugged processes when the debugging
        thread dies. This method only affects the calling thread.

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

        @note:
            This call will fail if a debug port was not created. That is, if
            the debugger isn't attached to at least one process. For more info
            see: U{http://msdn.microsoft.com/en-us/library/ms679307.aspx}
        """
        try:
            # won't work before calling CreateProcess or DebugActiveProcess
            win32.DebugSetProcessKillOnExit(bKillOnExit)
        except (AttributeError, WindowsError):
            return False
        return True

    @classmethod
    def load_dbghelp(cls, pathname = None):
        """
        Load the C{dbghelp.dll} library shipped with the Debugging Tools for
        Windows. Essentially this enables symbol server support, since this
        version is newer than the one pre-installed with Windows, and the
        symbol server loader library (C{SymSrv.dll}) is present in the same
        directory.

        For this method to have any effect it MUST be called BEFORE any
        function in C{dbghelp.dll}. It's recommended that you call it right
        after starting your debug script, or after instancing the L{Debug}
        object.

        Example::
            from winappdbg import Debug

            def simple_debugger( argv ):

                # Instance a Debug object, passing it the event handler callback
                debug = Debug( my_event_handler )
                try:

                    # Enable support for symbol downloading
                    debug.system.load_dbghelp()

                    # Start a new process for debugging
                    debug.execv( argv )

                    # Wait for the debugee to finish
                    debug.loop()

                # Stop the debugger
                finally:
                    debug.stop()

        @see: U{http://msdn.microsoft.com/en-us/library/ms679294(VS.85).aspx}

        @type  pathname: str
        @param pathname:
            (Optional) Full pathname to the C{dbghelp.dll} library.

        @rtype:  ctypes.WinDLL
        @return: Loaded instance of C{dbghelp.dll}.

        @raise NotImplementedError: This feature was not implemented for the
            current architecture.

        @raise WindowsError: An error occured while processing this request.
        """
        if not pathname:
            if cls.arch == win32.ARCH_AMD64:
                if cls.wow64:
                    pathname = os.path.join(
                                        os.getenv("ProgramFiles(x86)",
                                            os.getenv("ProgramFiles")),
                                        "Debugging Tools for Windows (x86)",
                                        "dbghelp.dll")
                else:
                    pathname = os.path.join(
                                        os.getenv("ProgramFiles"),
                                        "Debugging Tools for Windows (x64)",
                                        "dbghelp.dll")
            elif cls.arch == win32.ARCH_I386:
                pathname = os.path.join(
                                    os.getenv("ProgramFiles"),
                                    "Debugging Tools for Windows (x86)",
                                    "dbghelp.dll")
            else:
                msg = "Architecture %s is not currently supported."
                raise NotImplementedError(msg  % cls.arch)
        return ctypes.windll.LoadLibrary(pathname)

    @classmethod
    def read_msr(cls, address):
        """
        Read the contents of the specified MSR (Machine Specific Register).

        @type  address: int
        @param address: MSR to read.

        @rtype:  int
        @return: Value of the specified MSR.

        @raise WindowsError:
            Raises an exception on error.

        @raise NotImplementedError:
            Current architecture is not C{i386} or C{amd64}.

        @warning:
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.
        """
        if cls.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            raise NotImplementedError(
                "MSR reading is only supported on i386 or amd64 processors.")
        msr         = win32.SYSDBG_MSR()
        msr.Address = address
        msr.Data    = 0
        win32.NtSystemDebugControl(win32.SysDbgReadMsr,
                                   InputBuffer  = msr,
                                   OutputBuffer = msr)
        return msr.Data

    @classmethod
    def write_msr(cls, address, value):
        """
        Set the contents of the specified MSR (Machine Specific Register).

        @type  address: int
        @param address: MSR to write.

        @type  value: int
        @param value: Contents to write on the MSR.

        @raise WindowsError:
            Raises an exception on error.

        @raise NotImplementedError:
            Current architecture is not C{i386} or C{amd64}.

        @warning:
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.
        """
        if cls.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            raise NotImplementedError(
                "MSR writing is only supported on i386 or amd64 processors.")
        msr         = win32.SYSDBG_MSR()
        msr.Address = address
        msr.Data    = value
        win32.NtSystemDebugControl(win32.SysDbgWriteMsr, InputBuffer = msr)

    @classmethod
    def enable_step_on_branch_mode(cls):
        """
        When tracing, call this on every single step event
        for step on branch mode.

        @raise WindowsError:
            Raises C{ERROR_DEBUGGER_INACTIVE} if the debugger is not attached
            to least one process.

        @raise NotImplementedError:
            Current architecture is not C{i386} or C{amd64}.

        @warning:
            This method uses the processor's machine specific registers (MSR).
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.

        @note:
            It doesn't seem to work in VMWare or VirtualBox machines.
            Maybe it fails in other virtualization/emulation environments,
            no extensive testing was made so far.
        """
        cls.write_msr(DebugRegister.DebugCtlMSR,
                DebugRegister.BranchTrapFlag | DebugRegister.LastBranchRecord)

    @classmethod
    def get_last_branch_location(cls):
        """
        Returns the source and destination addresses of the last taken branch.

        @rtype: tuple( int, int )
        @return: Source and destination addresses of the last taken branch.

        @raise WindowsError:
            Raises an exception on error.

        @raise NotImplementedError:
            Current architecture is not C{i386} or C{amd64}.

        @warning:
            This method uses the processor's machine specific registers (MSR).
            It could potentially brick your machine.
            It works on my machine, but your mileage may vary.

        @note:
            It doesn't seem to work in VMWare or VirtualBox machines.
            Maybe it fails in other virtualization/emulation environments,
            no extensive testing was made so far.
        """
        LastBranchFromIP = cls.read_msr(DebugRegister.LastBranchFromIP)
        LastBranchToIP   = cls.read_msr(DebugRegister.LastBranchToIP)
        return ( LastBranchFromIP, LastBranchToIP )

    @classmethod
    def get_postmortem_debugger(cls, bits = None):
        """
        Returns the postmortem debugging settings from the Registry.

        @see: L{set_postmortem_debugger}

        @type  bits: int
        @param bits: Set to C{32} for the 32 bits debugger, or C{64} for the
            64 bits debugger. Set to {None} for the default (L{System.bits}.

        @rtype:  tuple( str, bool, int )
        @return: A tuple containing the command line string to the postmortem
            debugger, a boolean specifying if user interaction is allowed
            before attaching, and an integer specifying a user defined hotkey.
            Any member of the tuple may be C{None}.
            See L{set_postmortem_debugger} for more details.

        @raise WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'
        else:
            keyname = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'

        key = cls.registry[keyname]

        debugger = key.get('Debugger')
        auto     = key.get('Auto')
        hotkey   = key.get('UserDebuggerHotkey')

        if auto is not None:
            auto = bool(auto)

        return (debugger, auto, hotkey)

    @classmethod
    def get_postmortem_exclusion_list(cls, bits = None):
        """
        Returns the exclusion list for the postmortem debugger.

        @see: L{get_postmortem_debugger}

        @type  bits: int
        @param bits: Set to C{32} for the 32 bits debugger, or C{64} for the
            64 bits debugger. Set to {None} for the default (L{System.bits}).

        @rtype:  list( str )
        @return: List of excluded application filenames.

        @raise WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'
        else:
            keyname = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'

        try:
            key = cls.registry[keyname]
        except KeyError:
            return []

        return [name for (name, enabled) in key.items() if enabled]

    @classmethod
    def set_postmortem_debugger(cls, cmdline,
                                auto = None, hotkey = None, bits = None):
        """
        Sets the postmortem debugging settings in the Registry.

        @warning: This method requires administrative rights.

        @see: L{get_postmortem_debugger}

        @type  cmdline: str
        @param cmdline: Command line to the new postmortem debugger.
            When the debugger is invoked, the first "%ld" is replaced with the
            process ID and the second "%ld" is replaced with the event handle.
            Don't forget to enclose the program filename in double quotes if
            the path contains spaces.

        @type  auto: bool
        @param auto: Set to C{True} if no user interaction is allowed, C{False}
            to prompt a confirmation dialog before attaching.
            Use C{None} to leave this value unchanged.

        @type  hotkey: int
        @param hotkey: Virtual key scan code for the user defined hotkey.
            Use C{0} to disable the hotkey.
            Use C{None} to leave this value unchanged.

        @type  bits: int
        @param bits: Set to C{32} for the 32 bits debugger, or C{64} for the
            64 bits debugger. Set to {None} for the default (L{System.bits}).

        @rtype:  tuple( str, bool, int )
        @return: Previously defined command line and auto flag.

        @raise WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'
        else:
            keyname = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug'

        key = cls.registry[keyname]

        if cmdline is not None:
            key['Debugger'] = cmdline
        if auto is not None:
            key['Auto'] = int(bool(auto))
        if hotkey is not None:
            key['UserDebuggerHotkey'] = int(hotkey)

    @classmethod
    def add_to_postmortem_exclusion_list(cls, pathname, bits = None):
        """
        Adds the given filename to the exclusion list for postmortem debugging.

        @warning: This method requires administrative rights.

        @see: L{get_postmortem_exclusion_list}

        @type  pathname: str
        @param pathname:
            Application pathname to exclude from postmortem debugging.

        @type  bits: int
        @param bits: Set to C{32} for the 32 bits debugger, or C{64} for the
            64 bits debugger. Set to {None} for the default (L{System.bits}).

        @raise WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'
        else:
            keyname = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'

        try:
            key = cls.registry[keyname]
        except KeyError:
            key = cls.registry.create(keyname)

        key[pathname] = 1

    @classmethod
    def remove_from_postmortem_exclusion_list(cls, pathname, bits = None):
        """
        Removes the given filename to the exclusion list for postmortem
        debugging from the Registry.

        @warning: This method requires administrative rights.

        @warning: Don't ever delete entries you haven't created yourself!
            Some entries are set by default for your version of Windows.
            Deleting them might deadlock your system under some circumstances.
            
            For more details see:
            U{http://msdn.microsoft.com/en-us/library/bb204634(v=vs.85).aspx}

        @see: L{get_postmortem_exclusion_list}

        @type  pathname: str
        @param pathname: Application pathname to remove from the postmortem
            debugging exclusion list.

        @type  bits: int
        @param bits: Set to C{32} for the 32 bits debugger, or C{64} for the
            64 bits debugger. Set to {None} for the default (L{System.bits}).

        @raise WindowsError:
            Raises an exception on error.
        """
        if bits is None:
            bits = cls.bits
        elif bits not in (32, 64):
            raise NotImplementedError("Unknown architecture (%r bits)" % bits)

        if bits == 32 and cls.bits == 64:
            keyname = 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'
        else:
            keyname = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList'

        try:
            key = cls.registry[keyname]
        except KeyError:
            return

        try:
            del key[pathname]
        except KeyError:
            return
