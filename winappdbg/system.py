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

# $Id$

"""
Instrumentation library.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation}

@group Instrumentation:
    System, Process, Thread, Module
@group Handles (private):
    Handle, ProcessHandle, ThreadHandle, FileHandle
@group Capabilities (private):
    ModuleContainer, ThreadContainer, ProcessContainer,
    ThreadDebugOperations, ProcessDebugOperations,
    MemoryOperations
"""

# this library can be imported directly
# to manipulate processes and threads
# without the need for the debugger

__all__ =   [
                # Instrumentation classes.
                'System',
                'Process',
                'Thread',
                'Module',
                
                # Win32 handle wrapper classes.
                'Handle',
                'ProcessHandle',
                'ThreadHandle',
                'FileHandle',
            ]

import win32
from textio import HexInput

import ctypes
import struct

##import traceback

try:
    from distorm import Decode, Decode32Bits
except ImportError:
    Decode32Bits = None
    def Decode(*argv, **argd):
        "PLEASE INSTALL DISTORM BEFORE GENERATING THE DOCUMENTATION"
        msg = ("diStorm is not installed or can't be found. "
        "Download it from: http://www.ragestorm.net/distorm/")
        raise NotImplementedError, msg

#==============================================================================

class Handle (object):
    """
    Encapsulates win32 handles to avoid leaking them.
    
    @see: L{ProcessHandle}, L{ThreadHandle}, L{FileHandle}
    """

    def __init__(self, aHandle = None, bOwnership = True):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle object.
        
        @type  bOwnership: bool
        @param bOwnership:
           True if we own the handle and we need to close it.
           False if someone else will be calling L{win32.CloseHandle}.
        """
        super(Handle, self).__init__()
        if aHandle == win32.INVALID_HANDLE_VALUE:
            aHandle = None
        self.value      = aHandle
        self.bOwnership = bool(bOwnership)

    def __del__(self):
        """
        Closes the win32 handle when the python object is destroyed.
        """
        if self.bOwnership and self.value is not None:
            try:
                win32.CloseHandle(self.value)
            except WindowsError:
                pass

    def __copy__(self):
        """
        Duplicates the win32 handle when copying the python object.
        """
        return self.dup()

    def __deepcopy__(self):
        """
        Duplicates the win32 handle when copying the python object.
        """
        return self.dup()

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes. Required by the win32 module.
        """
        return self.value

    def dup(self):
        """
        @rtype:  L{Handle}
        @return: A new handle to the same win32 object.
        """
        hHandle = win32.DuplicateHandle(self.value)
        return self.__class__(hHandle, bOwnership = True)

    def wait(self, dwMilliseconds = None):
        """
        Wait for the win32 object to be signaled.
        
        @type  dwMilliseconds: int
        @param dwMilliseconds: (Optional) Timeout value in milliseconds.
        """
        if dwMilliseconds is None:
            dwMilliseconds = win32.INFINITE
        r = win32.WaitForSingleObject(self.value, dwMilliseconds)
        if r != win32.WAIT_OBJECT_0:
            raise ctypes.WinError()

#------------------------------------------------------------------------------

class ProcessHandle (Handle):
    """
    Win32 process handle.
    
    @see: L{Handle}
    """

    def get_pid(self):
        """
        @rtype:  int
        @return: Process global ID.
        """
        return win32.GetProcessId(self.value)

#------------------------------------------------------------------------------

class ThreadHandle (Handle):
    """
    Win32 thread handle.
    
    @see: L{Handle}
    """

    def get_tid(self):
        """
        @rtype:  int
        @return: Thread global ID.
        """
        return win32.GetThreadId(self.value)

#------------------------------------------------------------------------------

# TODO
# maybe add file mapping support here?
class FileHandle (Handle):
    """
    Win32 file handle.
    
    @see: L{Handle}
    """

    def get_filename(self):
        """
        @rtype:  str, None
        @return: Name of the open file, or C{None} on error.
        """

        # XXX TO DO update wrapper to avoid using ctypes objects
        try:
            dwBufferSize      = 0x1004
            lpFileInformation = ctypes.create_string_buffer(dwBufferSize)
            win32.GetFileInformationByHandleEx(self.value,
                                        win32.FILE_INFO_BY_HANDLE_CLASS.FileNameInfo,
                                        lpFileInformation, dwBufferSize)
            FileNameLength = struct.unpack('<L', lpFileInformation.raw[:4])[0] + 1
            FileName = str(lpFileInformation.raw[4:FileNameLength+4])
            FileName = FileName.replace('\x00', '')
            if FileName:
                return FileName
        except AttributeError:
            pass
##        except WindowsError:
##            pass
        return None

#------------------------------------------------------------------------------
# Static methods for filename and pathname manipulation.

# TODO
# Maybe these should be moved to a class of it's own?

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

#==============================================================================

def dllbaseparam(f):
    """
    Decorator to perform type checking on the C{lpBaseOfDll} parameter.
    
    @warning: This is only useful for debugging the debugger itself,
        otherwise the code should be commented out.
    
    @see: U{http://www.canonical.org/~kragen/isinstance/}
    """
    return f
##    def d(self, lpBaseOfDll, *argv, **argd):
##        if isinstance(lpBaseOfDll, Module):
##            msg = "Expected DLL base address, got Module instead"
##            raise TypeError, msg
##        if lpBaseOfDll < 0:
##            msg = "Invalid DLL base address: %r" % lpBaseOfDll
##            raise ValueError, msg
##        return f(self, lpBaseOfDll, *argv, **argd)
##    d.__doc__ = f.__doc__
##    return d

class ModuleContainer (object):
    """
    Encapsulates the capability to contain Module objects.
    
    @group Modules snapshot:
        scan_modules,
        get_module, get_module_bases, get_module_count,
        get_module_from_address, get_module_from_name,
        has_module, iter_modules, iter_module_addresses,
        clear_modules
    
    @group Debugging:
        get_system_breakpoint
    """

    def __init__(self):
        super(ModuleContainer, self).__init__()
        self.__moduleDict = dict()

    def __contains__(self, anObject):
        """
        @type  anObject: L{Module}, int
        @param anObject:
            C{Module}: Module object to look for.
            C{int}: Base address of the DLL to look for.
        
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

    @dllbaseparam
    def has_module(self, lpBaseOfDll):
        """
        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Base address of the DLL to look for.
        
        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Module} object with the given base address.
        """
        return self.__moduleDict.has_key(lpBaseOfDll)

    @dllbaseparam
    def get_module(self, lpBaseOfDll):
        """
        @type  lpBaseOfDll: int
        @param lpBaseOfDll: Base address of the DLL to look for.
        
        @rtype:  L{Module}
        @return: Module object with the given base address.
        """
        if not self.__moduleDict.has_key(lpBaseOfDll):
            msg = "Unknown DLL base address %.08x"
            msg = msg % lpBaseOfDll
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
        @rtype:  list( int )
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

    def get_module_from_name(self, modName):
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
        if FileHandle.path_is_absolute(modName):
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
        if modDict.has_key(modName):
            return modDict[modName]

        # modName is a base filename without extension.
        filepart, extpart = FileHandle.split_extension(modName)
        if filepart and extpart and extpart.lower() == ".dll":
            if modDict.has_key(filepart):
                return modDict[filepart]

        # modName is a base address.
        try:
            baseAddress = HexInput.integer(modName)
        except ValueError:
            raise
            return None
        if self.has_module(baseAddress):
            return self.get_module(baseAddress)

        # Module not found.
        return None

    def get_module_from_address(self, address):
        """
        @type  address: int
        @param address: Memory address to query.
        
        @rtype:  L{Module}
        @return: C{Module} object that best matches the given address.
            Returns C{None} if no C{Module} can be found.
        """
        bases = self.get_module_bases()
        bases.sort()
        bases.insert(0, 0x00000000)
        bases.append(   0xFFFFFFFF)
        for i in xrange(len(bases)-1):
            begin, end = bases[i:i+2]
            if begin <= address <= end:
                if not self.has_module(begin):
                    break
                return self.get_module(begin)
        return None

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
                szModule      = me.szModule
                found_bases.add(lpBaseAddress)
                if not self.has_module(lpBaseAddress):
                    if szModule:
                        aModule = Module(lpBaseAddress, fileName = szModule)
                    else:
                        aModule = Module(lpBaseAddress)
                    self.__add_module(aModule)
                else:
                    if szModule:
                        aModule = self.get_module(lpBaseAddress)
                        if not aModule.fileName:
                            aModule.fileName = szModule
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
##        if self.__moduleDict.has_key(lpBaseOfDll):
##            msg = "Module already exists: %d" % lpBaseOfDll
##            raise KeyError, msg
        self.__moduleDict[lpBaseOfDll] = aModule

##    @dllbaseparam
    def __del_module(self, lpBaseOfDll):
##        if not self.__moduleDict.has_key(lpBaseOfDll):
##            msg = "Unknown base address %d" % lpBaseOfDll
##            raise KeyError, msg
        del self.__moduleDict[lpBaseOfDll]

    def __add_loaded_module(self, event):
        lpBaseOfDll = event.get_module_base()
        hFile       = event.get_file_handle()
        if self.has_module(lpBaseOfDll):
            aModule = self.get_module(lpBaseOfDll)
            if hFile != win32.INVALID_HANDLE_VALUE:
                aModule.hFile = hFile
            if not aModule.fileName:
                fileName = event.get_filename()
                if fileName:
                    aModule.fileName = fileName
        else:
            fileName = event.get_filename()
            aModule  = Module(lpBaseOfDll, hFile, fileName)
            self.__add_module(aModule)

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

def threadidparam(f):
    """
    Decorator to perform type checking on the C{dwThreadId} parameter.

    @warning: This is only useful for debugging the debugger itself,
        otherwise the code should be commented out.

    @see: U{http://www.canonical.org/~kragen/isinstance/}
    """
    return f
##    def d(self, dwThreadId, *argv, **argd):
##        if isinstance(dwThreadId, Thread):
##            msg = "Expected thread ID, got Thread instead"
##            raise TypeError, msg
##        if dwThreadId < 0:
##            msg = "Invalid thread ID: %r" % dwThreadId
##            raise ValueError, msg
##        return f(self, dwThreadId, *argv, **argd)
##    d.__doc__ = f.__doc__
##    return d

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
##        if self.__threadDict.has_key(dwThreadId):
##            msg = "Already have a Thread object with ID %d" % dwThreadId
##            raise KeyError, msg
        aThread.dwProcessId = self.get_pid()
        self.__threadDict[dwThreadId] = aThread

##    @threadidparam
    def __del_thread(self, dwThreadId):
##        if not self.__threadDict.has_key(dwThreadId):
##            msg = "Unknown thread ID: %d" % dwThreadId
##            raise KeyError, msg
        del self.__threadDict[dwThreadId]

    @threadidparam
    def has_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.
        
        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Thread} object with the given global ID.
        """
        return self.__threadDict.has_key(dwThreadId)

    @threadidparam
    def get_thread(self, dwThreadId):
        """
        @type  dwThreadId: int
        @param dwThreadId: Global ID of the thread to look for.
        
        @rtype:  L{Thread}
        @return: Thread object with the given global ID.
        """
        if not self.__threadDict.has_key(dwThreadId):
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
        
        @type    bExactMatch: bool
        @keyword bExactMatch: C{True} if the name must be
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
        
        @type    bSuspended: bool
        @keyword bSuspended: C{True} if the new thread should be suspended.
            In that case use L{Thread.resume} to start execution.
        """
        if bSuspended:
            dwCreationFlags = win32.CREATE_SUSPENDED
        else:
            dwCreationFlags = 0
        hThread, dwThreadId = win32.CreateRemoteThread(self.get_handle(), 0, 0,
                                lpStartAddress, lpParameter, dwCreationFlags)
        hThread = ThreadHandle(hThread, bOwnership = True)
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

# TODO
# * This methods do not take into account that code breakpoints change the
#   memory. This object should talk to BreakpointContainer to retrieve the
#   original memory contents where code breakpoints are enabled.
# * Add a method to return the memory map for a given process.
# * A memory cache could be implemented here.
class MemoryOperations (object):
    """
    Encapsulates the capabilities to manipulate the memory of a process.
    
    @group Memory allocation:
        malloc, free, mprotect, mquery
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
        packedDword     = struct.pack('<L', unpackedDword)
        dwBytesWritten  = self.write(lpBaseAddress, packedDword)
        if dwBytesWritten != len(packedDword):
            raise ctypes.WinError()

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
        @param lpBaseAddress: Memory address to begin writing.
        
        @type  stype: ctypes.Structure or a subclass.
        @param stype: Structure definition.
        
        @rtype:  int
        @return: Structure instance filled in with data
            read from the process memory.
        
        @raise WindowsError: On error an exception is raised.
        """
        data = self.read(lpBaseAddress, ctypes.sizeof(stype))
        buff = ctypes.create_string_buffer(data)
        ptr  = ctypes.cast(ctypes.pointer(buff), ctypes.POINTER(stype))
        return ptr.contents

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
        
        @type    fUnicode: bool
        @keyword fUnicode: C{True} is the string is expected to be Unicode,
            C{False} if it's expected to be ANSI.
        
        @type    dwMaxSize: int
        @keyword dwMaxSize: Maximum allowed string length to read, in bytes.
        
        @rtype:  str, unicode
        @return: String read from the process memory space.
            Returns an empty string on failure.
        """
        szString = ''
        if lpBaseAddress != win32.NULL:
            szString = self.peek(lpBaseAddress, dwMaxSize)
            if fUnicode:
                szString = szString[:szString.find('\x00\x00') + 2]
                szString = unicode(szString, 'U16', 'ignore')
            else:
                szString = szString[:szString.find('\x00') + 1]
        return szString

#------------------------------------------------------------------------------

    def malloc(self, dwSize, lpAddress = win32.NULL):
        """
        Allocates memory into the address space of the process.
        
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
        
        @type  lpAddress: int
        @param lpAddress: Address of memory to free.
        
        @type  dwSize: int
        @param dwSize: (Optional) Number of bytes to free.
        
        @rtype:  bool
        @return: C{True} on success, C{False} on error.
        """
        success = win32.VirtualFreeEx(self.get_handle(), lpAddress, dwSize)
        return bool(success)

#==============================================================================

# TODO
# Add symbol support using the debug help API.
# http://msdn.microsoft.com/en-us/library/ms679291(VS.85).aspx

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
        U{https://apps.sourceforge.net/trac/winappdbg/wiki/Labels}
    
    @group Labels:
        create_label,
        create_label_from_address,
        split_label,
        split_label_fuzzy,
        resolve_label
    """

    @staticmethod
    def create_label(module = None, function = None, offset = None):
        """
        Creates a label from a module and a function name, plus an offset.
        
        @type  module: None or str
        @param module: (Optional) Module name.
        
        @type  function: None, str or int
        @param function: (Optional) Function name or ordinal.
        
        @type  offset: None or str
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
    def split_label(label):
        """
        Splits a label created with L{create_label}.
        
        To parse labels with a less strict syntax, use the L{split_label_fuzzy}
        method instead.
        
        @type  label: str
        @param label: Label to split.
        
        @rtype:  tuple( str, str, str )
        @return: Tuple containing the C{module} name,
            the C{function} name, and the C{offset} value.
            
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
                raise ValueError, "Invalid label: %s" % label

            # module ! function
            if function:
                if '+' in module:
                    raise ValueError, "Invalid label: %s" % label

                # module ! function + offset
                if '+' in function:
                    try:
                        function, offset = function.split('+')
                    except ValueError:
                        raise ValueError, "Invalid label: %s" % label
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError, "Invalid label: %s" % label
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
                        raise ValueError, "Invalid label: %s" % label
                    try:
                        offset = HexInput.integer(offset)
                    except ValueError:
                        raise ValueError, "Invalid label: %s" % label

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
        
        It's more flexible in it's syntax parsing than the L{split_label}
        module, as it allows the exclamation mark (B{C{!}}) to be omitted.
        
        The ambiguity is resolved by searching the modules in the snapshot to
        guess if a label refers to a module or a function.
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
            return self.split_label(label)

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
                raise ValueError, "Invalid label: %s" % label
            try:
                offset = HexInput.integer(offset)
            except ValueError:
                raise ValueError, "Invalid label: %s" % label
            label = prefix

        modobj = self.get_module_from_name(label)
        if modobj:

            # module
            # module + offset
            module = modobj.get_name()

        else:

            # offset
            try:
                offset = HexInput.integer(label)

                # If only a hardcoded address is given,
                # rebuild the label using create_label_from_address.
                # Then parse it again, but this time strictly,
                # both because there is no need for fuzzy syntax and
                # to prevent an infinite recursion if there's a bug here.
                try:
                    new_label = self.create_label_from_address(offset)
                    module, function, offset = self.split_label(new_label)
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
            modobj = self.get_module_from_name(module)
            if not modobj:
                msg = "Module %s not found" % module
                raise RuntimeError, msg
    
            # Resolve the function.
            if function:
                address = modobj.resolve(function)
                if address is None:
                    msg = "Function %s not found in module %s"
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
                msg = "Function %s not found in any module" % function
                raise RuntimeError, msg

        # Return the address plus the offset.
        if offset:
            address = address + offset
        return address

    def create_label_from_address(self, address):
        """
        Creates a label from the given memory address.
        
        @type  address: int
        @param address: Memory address.
        
        @rtype:  str
        @return: Label pointing to the given address.
        """
        modobj = self.get_module_from_address(address)
        if modobj is None:
            label = self.create_label(None, None, address)
        else:
            
            # TODO
            # enumerate exported functions and debug symbols,
            # then find the closest match
            
            module = modobj.get_name()
            offset = address - modobj.get_base()
            label = self.create_label(module, None, offset)
        return label

#==============================================================================

class ThreadDebugOperations (object):
    """
    Encapsulates several useful debugging routines for threads.
    
    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string
    @group Stack:
        get_stack_data, get_stack_dwords, get_stack_frame, get_stack_range,
        get_stack_trace
    @group Miscellaneous:
        get_teb, get_code_bytes,
        peek_pointers_in_data, peek_pointers_in_registers
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

    def get_stack_range(self):
        """
        @rtype:  tuple( int, int )
        @return: Stack base pointer and stack limit pointer.
        """
        teb = self.get_teb()
        return (teb.NtTib.StackBase, teb.NtTib.StackLimit)

    def get_stack_trace(self, depth = 16):
        """
        Tries to get a stack trace for the current function.
        Only works for functions with standard prologue and epilogue.
        
        @type    depth: int
        @keyword depth: Maximum depth of stack trace.
        
        @rtype:  tuple of tuple( int, int, str )
        @return: Stack trace of the thread
            as a tuple of ( return address, frame pointer, module filename ).
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
            lib = aProcess.get_module_from_address(ra)
            if lib is None:
                lib = ""
            else:
                if lib.fileName:
                    lib = lib.fileName
                else:
##                    lib = "Module at 0x%.08x" % lib.lpBaseOfDll
                    lib = "0x%.08x" % lib.lpBaseOfDll
            trace.append( (fp, ra, lib) )
            fp = aProcess.peek_uint(fp)
        return tuple(trace)

    def get_stack_frame(self, max_size = None):
        """
        Tries to read the contents of the current stack frame.
        Only works for functions with standard prologue and epilogue.
        
        @type    depth: int
        @keyword depth: Maximum depth of stack trace.
        
        @rtype:  str
        @return: Stack frame data.
            May return an empty string.
        
        @raise RuntimeError: The stack frame is invalid,
            or the function doesn't have a standard prologue
            and epilogue.
        
        @raise WindowsError: An error occured when reading
            data from the process memory.
        """
        aProcess = self.get_process()
        sb, sl   = self.get_stack_range()
        sp       = self.get_sp()
        fp       = self.get_fp()
        size     = fp - sp
        if not sb <= sp < sl:
            raise RuntimeError, 'Stack pointer lies outside the stack'
        if not sb <= fp < sl:
            raise RuntimeError, 'No valid frame pointer found'
        if size < 0:
            raise RuntimeError, 'No valid stack frame found'
        if max_size and size > max_size:
            size = max_size
        return aProcess.peek(sp, size)

    def get_stack_data(self, size = 128, offset = 0):
        """
        Tries to read the contents of the top of the stack.
        
        @type  size: int
        @param size: Number of bytes to read.
        
        @type  offset: int
        @param offset: Offset from the stack pointer to begin reading.
        
        @rtype:  str
        @return: Stack data.
            Returns an empty string on error.
        """
        aProcess = self.get_process()
        return aProcess.peek(self.get_sp() + offset, size)

    def get_stack_dwords(self, count, offset = 0):
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
        stackData = self.get_stack_data(count * 4, offset)
        if len(stackData) & 3:
            stackData = stackData[:-len(stackData) & 3]
        if not stackData:
            return ()
        return struct.unpack('<'+('L'*count), stackData)

    def get_code_bytes(self, size = 128, offset = 0):
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
        aProcess = self.get_process()
        return aProcess.peek(self.get_pc() + offset, size)

    def peek_pointers_in_registers(self, peekSize = 16):
        """
        Tries to guess which values in the registers are valid pointers,
        and reads some data from them.
        
        @type  peekSize: int
        @param peekSize: Number of bytes to read from each pointer found.
        
        @rtype:  dict( str S{->} str )
        @return: Dictionary mapping register names to the data they point to.
        """
        aProcess  = self.get_process()
        registers = self.get_context(win32.CONTEXT_INTEGER)
        data      = dict()
        for (reg_name, reg_value) in registers.iteritems():
            if reg_name != 'ContextFlags':
                if reg_value & 0xFFFF0000:
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

    @threadidparam
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

class ProcessDebugOperations (object):
    """
    Encapsulates several useful debugging routines for processes.

    @group Properties:
        get_peb, get_main_module, get_image_base, get_image_name
    @group Disassembly:
        disassemble, disassemble_around, disassemble_around_pc,
        disassemble_string
    @group Miscellaneous:
        flush_instruction_cache, peek_pointers_in_data
    """

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
        return Decode(lpAddress, code, Decode32Bits)

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
        data = self.read(lpAddress, dwSize)
        return self.disassemble_string(lpAddress, data)

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
        dwDelta = int(dwSize / 2)
        addr_1 = lpAddress - dwDelta
        addr_2 = lpAddress
        size_1 = dwDelta
        size_2 = dwSize - dwDelta
        data_1 = self.read(addr_1, size_1)
        data_2 = self.read(addr_2, size_2)
        disasm_1 = self.disassemble_string(addr_1, data_1)
        disasm_2 = self.disassemble_string(addr_2, data_2)
        return disasm_1 + disasm_2

    @threadidparam
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
            except KeyError:
                name = None
            except AttributeError:
                name = None
            except WindowsError:
                name = None

        # method 2: QueryFullProcessImageName()
        # not implemented until Windows Vista.
        if not name:
            try:
                name = win32.QueryFullProcessImageName(self.get_handle())
            except AttributeError:
                name = None
            except WindowsError:
                name = None

        # method 3: GetProcessImageFileName()
        # not implemented until Windows XP.
        # for more info see http://blog.voidnish.com/?p=72
        if not name:
            try:
                name = win32.GetProcessImageFileName(self.get_handle())
                name = self.native_to_win32_pathname(name)
            except AttributeError:
                name = None
            except WindowsError:
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
                name = self.native_to_win32_pathname(name)
            except AttributeError:
                name = None
            except WindowsError:
                name = None

##        # method 5: NtQueryInformationProcess(ProcessImageFileName)
##        # not implemented in W2K.
##        # may fail since it's not officially part of the Win32 API.
##        # FIXME not working on XP either :( returns STATUS_INVALID_INFO_CLASS
##        if not name:
##            try:
##                name = win32.NtQueryInformationProcess(self.get_handle(),
##                                                win32.ProcessImageFileName)
##            except AttributeError:
##                name = None
##            except WindowsError, e:
##                print e     # XXX
##                name = None

##        # method 6: PEB.ProcessParameters.ImagePathName
##        # may fail since it's using an undocumented internal structure.
##        if not name:
##            try:
##                peb = self.get_peb()
##                rupp = self.read_structure(peb.ProcessParameters,
##                                             win32.RTL_USER_PROCESS_PARAMETERS)
##                name = self.read(rupp.ImagePathName.Buffer,
##                                                     rupp.ImagePathName.Length)
##            except AttributeError:
##                name = None
##            except WindowsError:
##                name = None

        # return the image filename, or None on error.
        return name

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

def processidparam(f):
    """
    Decorator to perform type checking on the C{dwProcessId} parameter.

    @warning: This is only useful for debugging the debugger itself,
        otherwise the code should be commented out.

    @see: U{http://www.canonical.org/~kragen/isinstance/}
    """
    return f
##    def d(self, dwProcessId, *argv, **argd):
##        if isinstance(dwProcessId, Process):
##            msg = "Expected process ID, got Process instead"
##            raise TypeError, msg
##        if dwProcessId < 0:
##            msg = "Invalid process ID: %r" % dwProcessId
##            raise ValueError, msg
##        return f(self, dwProcessId, *argv, **argd)
##    d.__doc__ = f.__doc__
##    return d

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
    """

    def __init__(self):
        super(ProcessContainer, self).__init__(self)
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
##        if self.__processDict.has_key(dwProcessId):
##            msg = "Process already exists: %d" % dwProcessId
##            raise KeyError, msg
        self.__processDict[dwProcessId] = aProcess

    @processidparam
    def __del_process(self, dwProcessId):
##        if not self.__processDict.has_key(dwProcessId):
##            msg = "Unknown process ID %d" % dwProcessId
##            raise KeyError, msg
        del self.__processDict[dwProcessId]

    @processidparam
    def has_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.
        
        @rtype:  bool
        @return: C{True} if the snapshot contains a
            L{Process} object with the given global ID.
        """
        return self.__processDict.has_key(dwProcessId)

    @processidparam
    def get_process(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Global ID of the process to look for.
        
        @rtype:  L{Process}
        @return: Process object with the given global ID.
        """
        if not self.__processDict.has_key(dwProcessId):
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
        return win32.CommandLineToArgv(lpCmdLine)

    def start_process(self, lpCmdLine,
            bConsole    = False,
            bDebug      = False,
            bFollow     = False,
            bSuspended  = False
        ):
        'Starts a new process for debugging.'
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
        processInformation = win32.CreateProcess(win32.NULL, lpCmdLine,
                                             dwCreationFlags = dwCreationFlags)
        hProcess = ProcessHandle(processInformation.hProcess, bOwnership=True)
        hThread  = ThreadHandle (processInformation.hThread,  bOwnership=True)
        aProcess = Process(processInformation.dwProcessId, hProcess)
        aThread  = Thread (processInformation.dwThreadId,  hThread)
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
        dead_pids  = set( self.get_process_ids() )
        found_tids = set()

        # Take a snapshot of all processes and threads
        dwFlags   = win32.TH32CS_SNAPPROCESS | win32.TH32CS_SNAPTHREAD
        hSnapshot = win32.CreateToolhelp32Snapshot(dwFlags)
        try:

            # Add all the processes
            pe = win32.Process32First(hSnapshot)
            while pe is not None:
                dwProcessId = pe.th32ProcessID
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
        dead_pids = set( self.get_process_ids() )
        hSnapshot = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPPROCESS)
        try:
            pe = win32.Process32First(hSnapshot)
            while pe is not None:
                dwProcessId = pe.th32ProcessID
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
        new_pid_list = win32.EnumProcesses()
        old_pid_list = self.get_process_ids()
        for pid in new_pid_list:
            if not self.has_process(pid):
                aProcess = Process(pid)
                self.__add_process(aProcess)
        new_pid_list = set(new_pid_list)
        for pid in old_pid_list:
            if pid not in new_pid_list:
                self.__del_process(pid)

    def clear_dead_processes(self):
        """
        Remove Process objects from the snapshot
        referring to processes no longer running.
        """
        for pid in self.get_process_ids():
            aProcess = self.get_process(pid)
            if not aProcess.is_alive():
                self.__del_process(aProcess)

    def clear_unattached_processes(self):
        """
        Remove Process objects from the snapshot
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
        Remove all L{Process}, L{Thread} and L{Module} objects in this snapshot.
        """
        self.__processDict = dict()

    def clear(self):
        """
        Clear this snapshot.
        
        @see: L{clear_processes}
        """
        self.clear_processes()

#------------------------------------------------------------------------------

    # Docs for these methods are taken from the ThreadContainer class.

    @threadidparam
    def has_thread(self, dwThreadId):
        for aProcess in self.iter_processes():
            if aProcess.has_thread(dwThreadId):
                return True
        return False

    @threadidparam
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

    @dllbaseparam
    def find_modules_by_base(self, lpBaseOfDll):
        """
        @rtype:  list( L{Module} )
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
        @rtype:  list( L{Module} )
        @return: List of Module objects that best match the given filename.
        """
        found = list()
        for aProcess in self.iter_processes():
            aModule = aProcess.get_module_from_name(fileName)
            if aModule is not None:
                found.append( (aProcess, aModule) )
        return found

    def find_modules_by_address(self, address):
        """
        @rtype:  list( L{Module} )
        @return: List of Module objects that best match the given address.
        """
        found = list()
        for aProcess in self.iter_processes():
            aModule = aProcess.get_module_from_address(address)
            if aModule is not None:
                found.append( (aProcess, aModule) )
        return found

    def find_processes_by_filename(self, filename):
        """
        @rtype:  list( L{Process} )
        @return: List of processes matching the given main module filename.
        """
        found    = list()
        filename = filename.lower()
        if FileHandle.path_is_absolute(filename):
            for aProcess in self.iter_processes():
                imagename = aProcess.get_filename()
                if imagename and imagename.lower() == filename:
                    found.append( (aProcess, imagename) )
        else:
            for aProcess in self.iter_processes():
                imagename = aProcess.get_filename()
                if imagename:
                    imagename = FileHandle.pathname_to_filename(imagename)
                    if imagename.lower() == filename:
                        found.append( (aProcess, imagename) )
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

# TODO
# + Add the ability to enumerate exported functions.

class Module (object):
    """
    Interface with a DLL library loaded in the context of another process.
    
    @group Properties:
        get_base, get_filename, get_name
    @group Symbols:
        get_label, resolve
    @group Handle:
        get_handle, open_handle, close_handle
    
    @type unknown: str
    @cvar unknown: Suggested tag for unknown modules.
    
    @type lpBaseOfDll: int
    @ivar lpBaseOfDll: Base of DLL module. Use L{get_base} instead.
    
    @type hFile: L{FileHandle}
    @ivar hFile: Handle to the module file. Use L{get_handle} instead.
    
    @type fileName: str
    @ivar fileName: Module filename. Use L{get_filename} instead.
    """

    unknown = '<unknown>'

    def __init__(self, lpBaseOfDll = win32.NULL, hFile = None, fileName = None):
        """
        @type  lpBaseOfDll: str
        @param lpBaseOfDll: Remote base address for module.
        
        @type  hFile: L{FileHandle}
        @param hFile: Handle to the module file.
        
        @type  fileName: str
        @param fileName: Module filename.
        """
        super(Module, self).__init__(self)
        self.lpBaseOfDll    = lpBaseOfDll
        self.hFile          = hFile
        self.fileName       = fileName

    def get_base(self):
        """
        @rtype:  int
        @return: Base address of the module.
        """
        return self.lpBaseOfDll

    def get_filename(self):
        """
        @rtype:  str
        @return: Module filename.
            Returns C{None} if unknown.
        """
        if self.fileName is None:
            if self.hFile not in (None, win32.INVALID_HANDLE_VALUE):
                self.fileName = self.hFile.get_filename()
        return self.fileName

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
            filename = FileHandle.pathname_to_filename(pathname)
            if filename:
                filename = filename.lower()
                filepart, extpart = FileHandle.split_extension(filename)
                if filepart and extpart and extpart == '.dll':
                    modName = filepart
                else:
                    modName = filename
            else:
                modName = pathname
        else:
            modName = "0x%x" % self.get_base()
        return modName

    def open_handle(self):
        """
        Opens a new handle to the module.
        """

        if not self.get_filename():
            msg = "Cannot retrieve filename for module at 0x%.08x"
            msg = msg % self.get_base()
            raise Exception, msg

        hFile = win32.CreateFile(self.get_filename(),
                                           dwShareMode = win32.FILE_SHARE_READ,
                                 dwCreationDisposition = win32.OPEN_EXISTING)
        hFile = FileHandle(hFile, bOwnership = True)
        try:
            self.close_handle()
        finally:
            self.hFile = hFile

    def close_handle(self):
        """
        Closes the handle to the module.
        """
        try:
            if self.hFile not in (None, win32.INVALID_HANDLE_VALUE) and \
                         not isinstance(self.hFile, Handle):
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
        return SymbolOperations.create_label(self.get_name(), function, offset)

    # TODO
    # A better solution would be to map a view of the file,
    # parse the PE header and get all the exported symbols.
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

#==============================================================================

class Thread (ThreadDebugOperations):
    """
    Interface to a thread in another process.
    
    @group Properties:
        get_tid, get_pid, get_exit_code,
        is_alive,
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
        code. Otherwise it's None.

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
        super(Thread, self).__init__(self)
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
        @return: Thread name, or None if the thread is nameless.
        """
        return self.name

    def set_name(self, name = None):
        """
        @type  name: str
        @param name: Thread name, or None if the thread is nameless.
        """
        self.name = name

#------------------------------------------------------------------------------

    def open_handle(self, dwDesiredAccess = win32.PROCESS_ALL_ACCESS):
        """
        Opens a new handle to the thread.
        """
        hThread = win32.OpenThread(dwDesiredAccess, win32.FALSE, self.dwThreadId)
        hThread = ThreadHandle(hThread, bOwnership = True)
        try:
            self.close_handle()
        finally:
            self.hThread = hThread

    def close_handle(self):
        """
        Closes the handle to the thread.
        """
        try:
            if self.hThread not in (None, win32.INVALID_HANDLE_VALUE) and \
                         not isinstance(self.hThread, Handle):
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
        @return: Thread exit code, or STILL_ACTIVE if it's still alive.
        """
        return win32.GetExitCodeThread(self.get_handle())

#------------------------------------------------------------------------------

    # TODO
    # A registers cache could be implemented here.
    def get_context(self, ContextFlags = win32.CONTEXT_ALL):
        """
        @rtype:  dict( str S{->} int )
        @return: Dictionary mapping register names to their values.
        
        @see: L{set_context}
        """
        return win32.GetThreadContext(self.get_handle(), ContextFlags)

    def set_context(self, context):
        """
        Sets the values of the registers.
        
        @see: L{get_context}
        
        @type  context:  dict( str S{->} int )
        @param context: Dictionary mapping register names to their values.
        """
        win32.SetThreadContext(self.get_handle(), context)

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
        kill, wait, inject_code, inject_dll
    
    @group Debugging:
        debug_break
    
    @group Processes snapshot:
        scan, clear
    
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
        super(Process, self).__init__()
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
        hProcess = ProcessHandle(hProcess, True)
        try:
            self.close_handle()
        finally:
            self.hProcess = hProcess

    def close_handle(self):
        """
        Closes the handle to the process.
        """
        try:
            if self.hProcess not in (None, win32.INVALID_HANDLE_VALUE) and \
                             not isinstance(self.hProcess, Handle):
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

    # Ambiguous, we have two implementations of __iter__():
    #     ThreadContainer.__contains__()
    #     ModuleContainer.__contains__()
    def __contains__(self, anObject):
        return ThreadContainer.__contains__(self, anObject)
    __contains__.__doc__ = ThreadContainer.__contains__.__doc__

    # Ambiguous, we have two implementations of __iter__():
    #     ThreadContainer.__iter__()
    #     ModuleContainer.__iter__()
    def __iter__(self):
        return ThreadContainer.__iter__(self)
    __iter__.__doc__ = ThreadContainer.__iter__.__doc__

    # Ambiguous, we have two implementations of __len__():
    #     ThreadContainer.__len__()
    #     ModuleContainer.__len__()
    def __len__(self):
        return ThreadContainer.__len__(self)
    __len__.__doc__ = ThreadContainer.__len__.__doc__

    # (Oh, the delights of Python's multiple inheritance...)

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
        TerminateProcess(self.get_handle(), dwExitCode)

    def debug_break(self):
        """
        Triggers the system breakpoint in the process.
        
        @raise WindowsError: On error an exception is raised.
        """
        win32.DebugBreakProcess(self.get_handle())

    def is_debugged(self):
        """
        @rtype:  bool
        @return: C{True} if the process is being debugged.
        """
        return win32.CheckRemoteDebuggerPresent(self.get_handle())

    def is_alive(self):
        """
        @rtype:  bool
        @return: C{True} if the process is currently running.
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
        @return: Process exit code, or STILL_ACTIVE if it's still alive.
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
    def inject_dll(self, dllname, procname = None, lpParameter = 0, dwTimeout = None):
        """
        Injects a DLL into the process memory.
        
        @see: L{inject_code}
        
        @type  dllname: str
        @param dllname: Name of the DLL module to load.
        
        @type  procname: str
        @param procname: (Optional) Procedure to call when the DLL is loaded.
        
        @type  lpParameter: int
        @param lpParameter: (Optional) Parameter to the C{procname} procedure.
        
        @type  dwTimeout: int
        @param dwTimeout: (Optional) Timeout value in milliseconds.
        """

        # Resolve kernel32.dll
        aModule = self.get_module_from_name('kernel32.dll')
        if aModule is None:
            self.scan_modules()
            aModule = self.get_module_from_name('kernel32.dll')
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
        set_kill_on_exit_mode, request_debug_privileges,
        enable_step_on_branch_mode
    """

##    def __init__(self):
##        super(System, self).__init__()

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
##            traceback.print_exc()
##            print
        return False

    def set_kill_on_exit_mode(self, bKillOnExit = False):
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
        except AttributeError:
            pass
        except WindowsError, e:
            pass
##            traceback.print_exc()
##            print
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
