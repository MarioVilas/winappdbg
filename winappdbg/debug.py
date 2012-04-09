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

"""
Debugging.

@group Debugging:
    Debug

@group Warnings:
    MixedBitsWarning
"""

__revision__ = "$Id$"

__all__ = [ 'Debug', 'MixedBitsWarning' ]

import win32
from system import System
from process import Process
from thread import Thread
from module import Module
from breakpoint import _BreakpointContainer, CodeBreakpoint
from event import EventHandler, EventDispatcher, EventFactory, ExitProcessEvent
from interactive import ConsoleDebugger

import warnings
##import traceback

#==============================================================================

# If you set this warning to be considered as an error,
# you can stop the debugger from attaching to WOW64 processes.
class MixedBitsWarning (RuntimeWarning):
    """
    Mixture of 32 and 64 bits is considered experimental.
    Use at your own risk!
    """
    pass

#==============================================================================

# TODO
# * Add memory read and write operations, similar to those in the Process
#   class, but hiding the presence of the code breakpoints.
# * Add a method to get the memory map of a process, but hiding the presence
#   of the page breakpoints.
# * Maybe the previous two features should be implemented at the Process class
#   instead, but how to communicate with the Debug object without creating
#   circular references? Perhaps the "overrides" could be set using private
#   members (so users won't see them), but then there's the problem of the
#   users being able to access the snapshot (i.e. clear it), which is why it's
#   not such a great idea to use the snapshot to store data that really belongs
#   to the Debug class.

class Debug (EventDispatcher, _BreakpointContainer):
    """
    The main debugger class.

    @group Debugging:
        attach, detach, detach_from_all, execv, execl, kill, kill_all, clear,
        get_debugee_count, get_debugee_pids,
        is_debugee, is_debugee_attached, is_debugee_started, in_hostile_mode

    @group Debugging loop:
        interactive, loop, stop, next, wait, dispatch, cont

    @type system: L{System}
    @ivar system: A System snapshot that is automatically updated for
        processes being debugged. Processes not being debugged in this snapshot
        may be outdated.
    """

    # Automatically set to True the first time a Debug object is instanced.
    _debug_static_init = False

    def __init__(self, eventHandler = None,               bKillOnExit = False,
                                                         bHostileCode = False):
        """
        Debugger object.

        @type  eventHandler: L{EventHandler}
        @param eventHandler:
            (Optional, recommended) Custom event handler object.

        @type  bKillOnExit: bool
        @param bKillOnExit: (Optional) Kill on exit mode.
            If C{True} debugged processes are killed when the debugger is
            stopped. If C{False} when the debugger stops it detaches from all
            debugged processes and leaves them running (default).

        @type  bHostileCode: bool
        @param bHostileCode: (Optional) Hostile code mode.
            Set to C{True} to take some basic precautions against anti-debug
            tricks. Disabled by default.

        @warn: When hostile mode is enabled, some things may not work as
            expected! This is because the anti-anti debug tricks may disrupt
            the behavior of the Win32 debugging APIs or WinAppDbg itself.

        @note: The L{eventHandler} parameter may be any callable Python object
            (for example a function, or an instance method).
            However you'll probably find it more convenient to use an instance
            of a subclass of L{EventHandler} here.

        @raise WindowsError: Raises an exception on error.
        """
        EventDispatcher.__init__(self, eventHandler)
        _BreakpointContainer.__init__(self)

        self.system                         = System()
        self.lastEvent                      = None
        self.__bKillOnExit                  = bKillOnExit
        self.__bHostileCode                 = bHostileCode
        self.__breakOnEP                    = set()     # set of pids
        self.__attachedDebugees             = set()     # set of pids
        self.__startedDebugees              = set()     # set of pids

        if not self._debug_static_init:
            self._debug_static_init = True

            # Request debug privileges for the current process.
            # Only do this once, and only after instancing a Debug object,
            # so passive debuggers don't get detected because of this.
            self.system.request_debug_privileges(bIgnoreExceptions = False)

            # Try to fix the symbol store path if it wasn't set.
            # But don't enable symbol downloading by default, since it may
            # degrade performance severely.
            self.system.fix_symbol_store_path(remote = False, force = False)

##    # It's hard not to create circular references,
##    # and if we have a destructor, we can end up leaking everything.
##    # It's best to code the debugging loop properly to always
##    # stop the debugger before going out of scope.
##    def __del__(self):
##        try:
##            self.stop()
##        except Exception, e:
##            pass
####            traceback.print_exc()
####            print

    def __enter__(self):
        """
        Compatibility with the "C{with}" Python statement.
        """
        return self

    def __exit__(self, type, value, traceback):
        """
        Compatibility with the "C{with}" Python statement.
        """
        try:
            self.stop()
        except Exception, e:
            pass

    def __len__(self):
        """
        @rtype:  int
        @return: Number of processes being debugged.
        """
        return self.get_debugee_count()

    # TODO: maybe custom __bool__ to break out of loop() ?
    # it already does work (because of __len__) but it'd be
    # useful to do it from the event handler anyway

#------------------------------------------------------------------------------

    def attach(self, dwProcessId):
        """
        Attaches to an existing process for debugging.

        @see: L{detach}, L{execv}, L{execl}

        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to attach to.

        @rtype:  L{Process}
        @return: A new Process object. Normally you don't need to use it now,
            it's best to interact with the process from the event handler.

        @raise WindowsError: Raises an exception on error.
        """

        # The process has to be registered with the debugger,
        # otherwise the list of processes may be empty, and the
        # debugger loop will quit too soon. When the create process
        # event arrives, the process handle is replaced.
        if not self.system.has_process(dwProcessId):
            aProcess = Process(dwProcessId)
            self.system._add_process(aProcess)
        else:
            aProcess = self.system.get_process(dwProcessId)

        # Warn when mixing 32 and 64 bits.
        # This also allows the user to stop attaching altogether,
        # depending on how the warnings are configured.
        if (System.wow64 and not aProcess.is_wow64()) or \
                                (System.bits == 64 and aProcess.is_wow64()):
            msg = "Mixture of 32 and 64 bits is considered experimental." \
                  " Use at your own risk!"
            warnings.warn(msg, MixedBitsWarning)

        # Attach to the process.
        win32.DebugActiveProcess(dwProcessId)
        self.__attachedDebugees.add(dwProcessId)

        # XXX HACK
        # Scan the process threads and loaded modules.
        # This is prefered because the thread and library events do not
        # properly give some information, like the filename for each module.
        aProcess.scan_threads()
        aProcess.scan_modules()

        return aProcess

    def __cleanup_process(self, dwProcessId, bIgnoreExceptions = False):
        """
        Perform the necessary cleanup of a process about to be killed or
        detached from.

        This private method is called by L{kill} and L{detach}.

        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to kill.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when killing the process.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """

        # Erase all breakpoints in the process.
        try:
            self.erase_process_breakpoints(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # Stop tracing all threads in the process.
        try:
            self.stop_tracing_process(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # The process is no longer a debugee.
        try:
            if dwProcessId in self.__attachedDebugees:
                self.__attachedDebugees.remove(dwProcessId)
            if dwProcessId in self.__startedDebugees:
                self.__startedDebugees.remove(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # Clear and remove the process from the snapshot.
        # If the user wants to do something with it after detaching
        # a new Process instance must be created.
        try:
            self.system.get_process(dwProcessId).clear()
        except Exception:
            if not bIgnoreExceptions:
                raise
        try:
            self.system._del_process(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise

        # If the last debugging event is related to this process, forget it.
        try:
            if self.lastEvent and self.lastEvent.get_pid() == dwProcessId:
                self.lastEvent = None
        except Exception:
            if not bIgnoreExceptions:
                raise

    def kill(self, dwProcessId, bIgnoreExceptions = False):
        """
        Kills a process currently being debugged.

        @see: L{detach}

        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to kill.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when killing the process.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """

        # Keep a reference to the process. We'll need it later.
        try:
            aProcess = self.system.get_process(dwProcessId)
        except KeyError:
            aProcess = Process(dwProcessId)

        # Cleanup all data referring to the process.
        self.__cleanup_process(dwProcessId,
                               bIgnoreExceptions = bIgnoreExceptions)

        # Kill the process.
        try:
            aProcess.kill()
        except Exception:
             if not bIgnoreExceptions:
                raise

        # Cleanup what remains of the process data.
        aProcess.clear()

    def kill_all(self, bIgnoreExceptions = False):
        """
        Kills from all processes currently being debugged.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when killing each process. C{False} to stop and raise an
            exception when encountering an error.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """
        for pid in self.get_debugee_pids():
            self.kill(pid, bIgnoreExceptions = bIgnoreExceptions)

    def detach(self, dwProcessId, bIgnoreExceptions = False):
        """
        Detaches from a process currently being debugged.

        @note: On Windows 2000 and below the process is killed.

        @see: L{attach}, L{detach_from_all}

        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to detach from.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching. C{False} to stop and raise an exception when
            encountering an error.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """

        # Keep a reference to the process. We'll need it later.
        try:
            aProcess = self.system.get_process(dwProcessId)
        except KeyError:
            aProcess = Process(dwProcessId)

        # Determine if there is support for detaching.
        # This check should only fail on Windows 2000 and older.
        try:
            win32.DebugActiveProcessStop
            can_detach = True
        except AttributeError:
            can_detach = False

        # Continue the last event before detaching.
        # XXX not sure about this...
        try:
            if can_detach and self.lastEvent and \
                                    self.lastEvent.get_pid() == dwProcessId:
                self.cont(self.lastEvent)
        except Exception:
             if not bIgnoreExceptions:
                raise

        # Cleanup all data referring to the process.
        self.__cleanup_process(dwProcessId,
                               bIgnoreExceptions = bIgnoreExceptions)

        try:
            # Detach from the process.
            # On Windows 2000 and before, kill the process.
            if can_detach:
                try:
                    win32.DebugActiveProcessStop(dwProcessId)
                except Exception:
                     if not bIgnoreExceptions:
                        raise
            else:
                try:
                    aProcess.kill()
                except Exception:
                     if not bIgnoreExceptions:
                        raise

        finally:

            # Cleanup what remains of the process data.
            aProcess.clear()

    def detach_from_all(self, bIgnoreExceptions = False):
        """
        Detaches from all processes currently being debugged.

        @note: To better handle last debugging event, call L{stop} instead.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """
        for pid in self.get_debugee_pids():
            self.detach(pid, bIgnoreExceptions = bIgnoreExceptions)

    def execv(self, argv, **kwargs):
        """
        Starts a new process for debugging.

        This method uses a list of arguments. To use a command line string
        instead, use L{execl}.

        @see: L{attach}, L{detach}

        @type  argv: list( str... )
        @param argv: List of command line arguments to pass to the debugee.
            The first element must be the debugee executable filename.

        @type    bBreakOnEntryPoint: bool
        @keyword bBreakOnEntryPoint: C{True} to automatically set a breakpoint
            at the program entry point.

        @type    bConsole: bool
        @keyword bConsole: True to inherit the console of the debugger.
            Defaults to C{False}.

        @type    bFollow: bool
        @keyword bFollow: C{True} to automatically attach to child processes.
            Defaults to C{False}.

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
        @return: A new Process object. Normally you don't need to use it now,
            it's best to interact with the process from the event handler.

        @raise WindowsError: Raises an exception on error.
        """
        lpCmdLine = self.system.argv_to_cmdline(argv)
        return self.execl(lpCmdLine, **kwargs)

    def execl(self, lpCmdLine, **kwargs):
        """
        Starts a new process for debugging.

        This method uses a command line string. To use a list of arguments
        instead, use L{execv}.

        @see: L{attach}, L{detach}

        @type  lpCmdLine: str
        @param lpCmdLine: Command line string to execute.
            The first token must be the debugee executable filename.
            Tokens with spaces must be enclosed in double quotes.
            Tokens including double quote characters must be escaped with a
            backslash.

        @type    bBreakOnEntryPoint: bool
        @keyword bBreakOnEntryPoint: C{True} to automatically set a breakpoint
            at the program entry point. Defaults to C{False}.

        @type    bConsole: bool
        @keyword bConsole: True to inherit the console of the debugger.
            Defaults to C{False}.

        @type    bFollow: bool
        @keyword bFollow: C{True} to automatically attach to child processes.
            Defaults to C{False}.

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
        @return: A new Process object. Normally you don't need to use it now,
            it's best to interact with the process from the event handler.

        @raise WindowsError: Raises an exception on error.
        """
        kwargs['bDebug'] = True
        bBreakOnEntryPoint = kwargs.pop('bBreakOnEntryPoint', False)
        aProcess = None
        try:
            aProcess = self.system.start_process(lpCmdLine, **kwargs)
            dwProcessId = aProcess.get_pid()
            self.__startedDebugees.add(dwProcessId)
            if bBreakOnEntryPoint:
                self.__breakOnEP.add(dwProcessId)
            return aProcess
        except:
            try:
                if aProcess is not None:
                    aProcess.kill()
            except Exception:
                pass
            raise

#------------------------------------------------------------------------------

    def wait(self, dwMilliseconds = None):
        """
        Waits for the next debug event.

        @see: L{cont}, L{dispatch}, L{loop}

        @type  dwMilliseconds: int
        @param dwMilliseconds: (Optional) Timeout in milliseconds.
            Use C{INFINITE} or C{None} for no timeout.

        @rtype:  L{Event}
        @return: An event that occured in one of the debugees.

        @raise WindowsError: Raises an exception on error.
        """

        # Wait for the next debug event.
        raw   = win32.WaitForDebugEvent(dwMilliseconds)
        event = EventFactory.get(self, raw)

        # Remember it.
        self.lastEvent = event

        # Return it.
        return event

    def dispatch(self, event = None):
        """
        Calls the debug event notify callbacks.

        @see: L{cont}, L{loop}, L{wait}

        @type  event: L{Event}
        @param event: (Optional) Event object returned by L{wait}.

        @raise WindowsError: Raises an exception on error.
        """

        # If no event object was given, use the last event.
        if event is None:
            event = self.lastEvent

        # Ignore dummy events.
        if not event:
            return

        # Determine the default behaviour for this event.
        code = event.get_event_code()
        if code == win32.EXCEPTION_DEBUG_EVENT:

            # At this point, by default some exception types are swallowed by
            # the debugger, because we don't know yet if it was caused by the
            # debugger itself or the debugged process.
            #
            # Later on (see breakpoint.py) if we determined the exception was
            # not caused directly by the debugger itself, we set the default
            # back to passing the exception to the debugee.
            #
            # The "invalid handle" exception is also swallowed by the debugger
            # because it's not normally generated by the debugee. But in
            # hostile mode we want to pass it to the debugee, as it may be the
            # result of an anti-debug trick. In that case it's best to disable
            # bad handles detection with Microsoft's gflags.exe utility. See:
            # http://msdn.microsoft.com/en-us/library/windows/hardware/ff549557(v=vs.85).aspx

            exc_code = event.get_exception_code()
            if exc_code in (
                    win32.EXCEPTION_BREAKPOINT,
                    win32.EXCEPTION_WX86_BREAKPOINT,
                    win32.EXCEPTION_SINGLE_STEP,
                    win32.EXCEPTION_GUARD_PAGE,
                ):
                event.continueStatus = win32.DBG_CONTINUE
            elif exc_code == win32.EXCEPTION_INVALID_HANDLE:
                if self.__bHostileCode:
                    event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
                else:
                    event.continueStatus = win32.DBG_CONTINUE
            else:
                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

        elif code == win32.RIP_EVENT and \
                   event.get_rip_type() == win32.SLE_ERROR:

            # RIP events that signal fatal events should kill the process.
            event.continueStatus = win32.DBG_TERMINATE_PROCESS

        else:

            # Other events need this continue code.
            # Sometimes other codes can be used and are ignored, sometimes not.
            # For example, when using the DBG_EXCEPTION_NOT_HANDLED code,
            # debug strings are sent twice (!)

            event.continueStatus = win32.DBG_CONTINUE

        # Dispatch the debug event.
        return EventDispatcher.dispatch(self, event)

    def cont(self, event = None):
        """
        Resumes execution after processing a debug event.

        @see: dispatch(), loop(), wait()

        @type  event: L{Event}
        @param event: (Optional) Event object returned by L{wait}.

        @raise WindowsError: Raises an exception on error.
        """

        # If no event object was given, use the last event.
        if event is None:
            event = self.lastEvent

        # Ignore dummy events.
        if not event:
            return

        # Get the event continue status information.
        dwProcessId      = event.get_pid()
        dwThreadId       = event.get_tid()
        dwContinueStatus = event.continueStatus

        # Check if the process is still being debugged.
        if self.is_debugee(dwProcessId):

            # Try to flush the instruction cache.
            try:
                if self.system.has_process(dwProcessId):
                    aProcess = self.system.get_process(dwProcessId)
                else:
                    aProcess = Process(dwProcessId)
                aProcess.flush_instruction_cache()
            except WindowsError:
                pass

            # XXX TODO
            #
            # Try to execute the UnhandledExceptionFilter for second chance
            # exceptions, at least when in hostile mode (in normal mode it
            # would be breaking compatibility, as users may actually expect
            # second chance exceptions to be raised again).
            #
            # Reportedly in Windows 7 (maybe in Vista too) this seems to be
            # happening already. In XP and below the UnhandledExceptionFilter
            # was never called for processes being debugged.

            # Continue execution of the debugee.
            win32.ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)

        # If the event is the last event, forget it.
        if event is self.lastEvent:
            self.lastEvent = None

    def stop(self, bIgnoreExceptions = True):
        """
        Stops debugging all processes.

        If the kill on exit mode is on, debugged processes are killed when the
        debugger is stopped. Otherwise when the debugger stops it detaches from
        all debugged processes and leaves them running (default). For more
        details see: L{__init__}

        @note: This method is better than L{detach_from_all} because it can
            gracefully handle the last debugging event before detaching.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.
        """
        # I wish I knew a more pythonic way of doing this :(
        has_event = False
        try:
            event = self.lastEvent
            self.lastEvent = None
            has_event = bool(event)
        except Exception:
            if not bIgnoreExceptions:
                raise
        if has_event:
            try:
                pid = event.get_pid()
                self.disable_process_breakpoints(pid)
            except Exception:
                if not bIgnoreExceptions:
                    raise
            try:
                tid = event.get_tid()
                self.disable_thread_breakpoints(tid)
            except Exception:
                if not bIgnoreExceptions:
                    raise
            try:
                event.continueDebugEvent = win32.DBG_CONTINUE
                self.cont(event)
            except Exception:
                if not bIgnoreExceptions:
                    raise
        try:
            if self.__bKillOnExit:
                self.kill_all(bIgnoreExceptions)
            else:
                self.detach_from_all(bIgnoreExceptions)
        except Exception:
            if not bIgnoreExceptions:
                raise
        try:
            self.system.clear()
        except Exception:
            if not bIgnoreExceptions:
                raise

    def next(self):
        """
        Handles the next debug event.

        @see: L{cont}, L{dispatch}, L{wait}, L{stop}

        @raise WindowsError: Raises an exception on error.

            If the wait operation causes an error, debugging is stopped
            (meaning all debugees are either killed or detached from).

            If the event dispatching causes an error, the event is still
            continued before returning. This may happen, for example, if the
            event handler raises an exception nobody catches.
        """
        try:
            event = self.wait()
        except Exception:
            self.stop()
            raise
        try:
            self.dispatch()
        finally:
            self.cont()

    def loop(self):
        """
        Simple debugging loop.

        This debugging loop is meant to be useful for most simple scripts.
        It iterates as long as there is at least one debugee, or an exception
        is raised. Multiple calls are allowed.

        This is a trivial example script::
            import sys
            debug = Debug()
            try:
                debug.execv( sys.argv [ 1 : ] )
                debug.loop()
            finally:
                debug.stop()

        @see: L{next}, L{stop}

            U{http://msdn.microsoft.com/en-us/library/ms681675(VS.85).aspx}

        @raise WindowsError: Raises an exception on error.

            If the wait operation causes an error, debugging is stopped
            (meaning all debugees are either killed or detached from).

            If the event dispatching causes an error, the event is still
            continued before returning. This may happen, for example, if the
            event handler raises an exception nobody catches.
        """
        while self:
            self.next()

    def get_debugee_count(self):
        """
        @rtype:  int
        @return: Number of processes being debugged.
        """
        return len(self.__attachedDebugees) + len(self.__startedDebugees)

    def get_debugee_pids(self):
        """
        @rtype:  list( int... )
        @return: Global IDs of processes being debugged.
        """
        return list(self.__attachedDebugees) + list(self.__startedDebugees)

    def is_debugee(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process is being debugged
            by this L{Debug} instance.
        """
        return self.is_debugee_attached(dwProcessId) or \
               self.is_debugee_started(dwProcessId)

    def is_debugee_started(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process was started for debugging by this
            L{Debug} instance.
        """
        return dwProcessId in self.__startedDebugees

    def is_debugee_attached(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process is attached to this
            L{Debug} instance.
        """
        return dwProcessId in self.__attachedDebugees

    def in_hostile_mode(self):
        """
        Determine if we're in hostile mode (anti-anti-debug).

        @rtype:  bool
        @return: C{True} if this C{Debug} instance was started in hostile mode,
            C{False} otherwise.
        """
        return self.__bHostileCode

#------------------------------------------------------------------------------

    def clear(self):
        """
        Detach from all processes and clean up internal structures.

        @see: L{System}

        @raise WindowsError: Raises an exception on error.
        """
        self.erase_all_breakpoints()
        self.detach_from_all()
        self.system.clear()

#------------------------------------------------------------------------------

    def interactive(self, bConfirmQuit = True):
        """
        Start an interactive debugging session.

        @type  bConfirmQuit: bool
        @param bConfirmQuit: Set to C{True} to ask the user for confirmation
            before closing the session, C{False} otherwise.

        @warn: This will temporarily disable the user-defined event handler!

        This method returns when the user closes the session.
        """
        print "Interactive debugging session started."
        print "Use the \"help\" command to list all available commands."
        print "Use the \"quit\" command to close this session."
        print
        console = ConsoleDebugger()
        console.confirm_quit = bConfirmQuit
        console.load_history()
        try:
            console.start_using_debugger(self)
            console.loop()
        finally:
            console.stop_using_debugger()
            console.save_history()
        print
        print "Interactive debugging session closed."

#------------------------------------------------------------------------------

    def _notify_create_process(self, event):
        """
        Notify the creation of a new process.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{CreateProcessEvent}
        @param event: Create process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
        if dwProcessId not in self.__attachedDebugees:
            if dwProcessId not in self.__startedDebugees:
                self.__startedDebugees.add(dwProcessId)

        retval = self.system._notify_create_process(event)

        # Set a breakpoint on the program's entry point if requested.
        # Try not to use the Event object's entry point value, as in some cases
        # it may be wrong. See: http://pferrie.host22.com/misc/lowlevel3.htm
        if dwProcessId in self.__breakOnEP:
            try:
                lpEntryPoint = event.get_process().get_entry_point()
            except Exception:
                lpEntryPoint = event.get_start_address()

            # It'd be best to use a hardware breakpoint instead, at least in
            # hostile mode. But since the main thread's context gets smashed
            # by the loader, I haven't found a way to make it work yet.
            self.break_at(dwProcessId, lpEntryPoint)

        # Defeat isDebuggerPresent by patching PEB->BeingDebugged.
        # When we do this, some debugging APIs cease to work as expected.
        # For example, the system breakpoint isn't hit when we attach.
        # For that reason we need to define a code breakpoint at the
        # code location where a new thread is spawned by the debugging
        # APIs, ntdll!DbgUiRemoteBreakin.
        if self.__bHostileCode:
            aProcess = self.event.get_process()
            try:
                hProcess = aProcess.get_handle(win32.PROCESS_QUERY_INFORMATION)
                pbi = win32.NtQueryInformationProcess(
                                       hProcess, win32.ProcessBasicInformation)
                ptr = pbi.PebBaseAddress + 2
                if aProcess.peek(ptr, 1) == '\x01':
                    aProcess.poke(ptr, '\x00')
            except WindowsError:
                pass

        return retval

    def _notify_create_thread(self, event):
        """
        Notify the creation of a new thread.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{CreateThreadEvent}
        @param event: Create thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        return event.get_process()._notify_create_thread(event)

    def _notify_load_dll(self, event):
        """
        Notify the load of a new module.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{LoadDLLEvent}
        @param event: Load DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """

        # Pass the event to the breakpoint container.
        bCallHandler = _BreakpointContainer._notify_load_dll(self, event)

        # Get the process where the DLL was loaded.
        aProcess = event.get_process()

        # Pass the event to the process.
        bCallHandler = aProcess._notify_load_dll(event) and bCallHandler

        # Anti-anti-debugging tricks on ntdll.dll.
        if self.__bHostileCode:
            aModule = event.get_module()
            if aModule.match_name('ntdll.dll'):

                # Since we've overwritten the PEB to hide
                # ourselves, we no longer have the system
                # breakpoint when attaching to the process.
                # Set a breakpoint at ntdll!DbgUiRemoteBreakin
                # instead (that's where the debug API spawns
                # it's auxiliary threads). This also defeats
                # a simple anti-debugging trick: the hostile
                # process could have overwritten the int3
                # instruction at the system breakpoint.
                self.break_at(aProcess.get_pid(),
                        aProcess.resolve_label('ntdll!DbgUiRemoteBreakin'))

        return bCallHandler

    def _notify_exit_process(self, event):
        """
        Notify the termination of a process.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
        try:
            self.__attachedDebugees.remove(dwProcessId)
        except KeyError:
            pass
        try:
            self.__startedDebugees.remove(dwProcessId)
        except KeyError:
            pass
        try:
            self.__breakOnEP.remove(dwProcessId)
        except KeyError:
            pass

        bCallHandler = _BreakpointContainer._notify_exit_process(self, event)
        bCallHandler = self.system._notify_exit_process(event) and bCallHandler
        return bCallHandler

    def _notify_exit_thread(self, event):
        """
        Notify the termination of a thread.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{ExitThreadEvent}
        @param event: Exit thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        bCallHandler = _BreakpointContainer._notify_exit_thread(self, event)
        bCallHandler = bCallHandler and \
                                event.get_process()._notify_exit_thread(event)
        return bCallHandler

    def _notify_unload_dll(self, event):
        """
        Notify the unload of a module.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{UnloadDLLEvent}
        @param event: Unload DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        bCallHandler = _BreakpointContainer._notify_unload_dll(self, event)
        bCallHandler = bCallHandler and \
                                event.get_process()._notify_unload_dll(event)

    def _notify_rip(self, event):
        """
        Notify of a RIP event.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{RIPEvent}
        @param event: RIP event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        event.debug.detach( event.get_pid() )
        return True

    def _notify_debug_control_c(self, event):
        """
        Notify of a Debug Ctrl-C exception.

        @warning: This method is meant to be used internally by the debugger.

        @note: This exception is only raised when a debugger is attached, and
            applications are not supposed to handle it, so we need to handle it
            ourselves or the application may crash.

        @see: U{http://msdn.microsoft.com/en-us/library/aa363082(VS.85).aspx}

        @type  event: L{ExceptionEvent}
        @param event: Debug Ctrl-C exception event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        if event.is_first_chance():
            event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        return True

    def _notify_ms_vc_exception(self, event):
        """
        Notify of a Microsoft Visual C exception.

        @warning: This method is meant to be used internally by the debugger.

        @note: This allows the debugger to understand the
            Microsoft Visual C thread naming convention.

        @see: U{http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx}

        @type  event: L{ExceptionEvent}
        @param event: Microsoft Visual C exception event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwType = event.get_exception_information(0)
        if dwType == 0x1000:
            pszName     = event.get_exception_information(1)
            dwThreadId  = event.get_exception_information(2)
            dwFlags     = event.get_exception_information(3)

            aProcess = event.get_process()
            szName   = aProcess.peek_string(pszName, fUnicode = False)
            if szName:

                if dwThreadId == -1:
                    dwThreadId = event.get_tid()

                if aProcess.has_thread(dwThreadId):
                    aThread = aProcess.get_thread(dwThreadId)
                else:
                    aThread = Thread(dwThreadId)
                    aProcess._add_thread(aThread)

##                if aThread.get_name() is None:
##                    aThread.set_name(szName)
                aThread.set_name(szName)

        return True
