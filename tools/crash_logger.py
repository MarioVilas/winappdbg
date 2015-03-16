#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Crash logger
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

from __future__ import with_statement

__revision__ = "$Id$"

__all__ =   [
                'LoggingEventHandler',
            ]

import winappdbg
from winappdbg import *

import re
import os
import sys
import time
import traceback

try:
    import cerealizer
    cerealizer.freeze_configuration()
except ImportError:
    pass

# XXX TODO
# Use the "signal" module to avoid having to deal with unexpected
# KeyboardInterrupt exceptions everywhere. Ideally there should be a way to
# implement some form of "critical sections" (I'm using the term loosely here,
# meaning "sections that can't be interrupted by the user"), something like
# this: a global flag to enable and disable raising KeyboardInterrupt, and a
# couple functions to set it. The function that enables back KeyboardInterrupt
# should check for a queued interruption request. Some experimenting is needed
# to see how well this would behave on a Windows environment.

#==============================================================================

# XXX TODO
# * Capture stderr from the debugees?
# * Unless the full memory snapshot was requested, the debugger could return
#   DEBUG_CONTINUE and store the crash info in the database in background,
#   while the debugee tries to handle the exception.

class LoggingEventHandler(EventHandler):
    """
    Event handler that logs all events to standard output.
    It also remembers crashes, bugs or otherwise interesting events.

    @type crashCollector: class
    @cvar crashCollector:
        Crash collector class. Tipically L{Crash} or a custom subclass of it.

        Most users don't ever need to change this.
        See: U{http://winappdbg.sourceforge.net/Signature.html}
    """

    # Default crash collector is our good old Crash class.
    crashCollector = Crash

    def __init__(self, options, currentConfig = None):

        # Copy the user-defined options.
        self.options = options

        # Copy the configuration used in this fuzzing session.
        self.currentConfig = currentConfig

        # Create the logger object.
        self.logger = Logger(options.logfile, options.verbose)

        # Create the crash container.
        self.knownCrashes = self._new_crash_container()

        # Create the cache of resolved labels.
        self.labelsCache = dict()                   # pid -> label -> address

        # Create the map of target services and their process IDs.
        self.pidToServices = dict()                 # pid -> set(service...)

        # Create the set of services marked for restart.
        self.srvToRestart = set()

        # Call the base class constructor.
        super(LoggingEventHandler, self).__init__()

    def _new_crash_container(self):
        url = self.options.database
        if not url:
            return DummyCrashContainer(
                                allowRepeatedKeys = self.options.duplicates)
        if url.startswith('dbm://'):
            url = url[6:]
            return CrashContainer(url,
                                  allowRepeatedKeys = self.options.duplicates)
        return CrashDictionary(url,
                               allowRepeatedKeys = self.options.duplicates)

    # Add the crash to the database.
    def _add_crash(self, event, bFullReport = None, bLogEvent = True):

        # Unless forced either way, full reports are generated for exceptions.
        if bFullReport is None:
            bFullReport = event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT

        # Generate a crash object.
        crash = self.crashCollector(event)
        crash.addNote('Config: %s' % self.currentConfig)

        # Determine if the crash was previously known.
        # If we're allowing duplicates, treat all crashes as new.
        bNew = self.options.duplicates or crash not in self.knownCrashes

        # Add the crash object to the container.
        if bNew:
            crash.fetch_extra_data(event, self.options.memory)
            self.knownCrashes.add(crash)

        # Log the crash event.
        if bLogEvent and self.logger.is_enabled():
            if bFullReport and bNew:
                msg = crash.fullReport(bShowNotes = False)
            else:
                msg = crash.briefReport()
            self.logger.log_event(event, msg)

        # The first element of the tuple is the Crash object.
        # The second element is True if the crash is new, False otherwise.
        return crash, bNew

    # Determine if this is an event we must take action on.
    def _is_action_event(self, event):
        return self.options.action and \
               self._is_event_in_list( event, self.options.action_events )

    # Determine if this is a crash event.
    def _is_crash_event(self, event):
        return self._is_event_in_list( event, self.options.crash_events )

    # Common implementation of _is_action_event() and _is_crash_event().
    def _is_event_in_list(self, event, event_list):
        return \
            ('event' in event_list) or \
            ('exception' in event_list and \
                (event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and \
                (event.is_last_chance() or self.options.firstchance))) or \
            (event.eventMethod in event_list)

    # Actions to take for events.
    def _action(self, event, crash = None):

        # Pause if requested.
        if self.options.pause:
            raw_input("Press enter to continue...")

        try:

            # Run the configured commands after finding a crash if requested.
            self._run_action_commands(event, crash)

        finally:

            # Enter interactive mode if requested.
            if self.options.interactive:
                event.debug.interactive(bConfirmQuit = False)

    # Most events are processed here. Others have specific quirks on when to
    # consider them actionable or crashes.
    def _default_event_processing(self, event, bFullReport = None,
                                                 bLogEvent = False):
        crash = None
        bNew  = True
        try:
            if self._is_crash_event(event):
                crash, bNew = self._add_crash(event, bFullReport, bLogEvent)
        finally:
            if bNew and self._is_action_event(event):
                self._action(event, crash)

    # Run the configured commands after finding a crash.
    # Wait until each command completes before executing the next.
    # To avoid waiting, use the "start" command.
    def _run_action_commands(self, event, crash = None):
        for action in self.options.action:
            if '%' in action:
                if not crash:
                    crash = self.crashCollector(event)
                action = self._replace_action_variables(action, crash)
            action = "cmd.exe /c " + action
            system  = System()
            process = system.start_process(action, bConsole = True)
            process.wait()

    # Make the variable replacements in an action command line string.
    def _replace_action_variables(self, action, crash):

        # %COUNT% - Number of crashes currently stored in the database
        if '%COUNT%' in action:
            action = action.replace('%COUNT%', str(len(self.knownCrashes)) )

        # %EXCEPTIONCODE% - Exception code in hexa
        if '%EXCEPTIONCODE%' in action:
            if crash.exceptionCode:
                exceptionCode = HexDump.address(crash.exceptionCode)
            else:
                exceptionCode = HexDump.address(0)
            action = action.replace('%EXCEPTIONCODE%', exceptionCode)

        # %EVENTCODE% - Event code in hexa
        if '%EVENTCODE%' in action:
            action = action.replace('%EVENTCODE%',
                                            HexDump.address(crash.eventCode) )

        # %EXCEPTION% - Exception name, human readable
        if '%EXCEPTION%' in action:
            if crash.exceptionName:
                exceptionName = crash.exceptionName
            else:
                exceptionName = 'Not an exception'
            action = action.replace('%EXCEPTION%', exceptionName)

        # %EVENT% - Event name, human readable
        if '%EVENT%' in action:
            action = action.replace('%EVENT%', crash.eventName)

        # %PC% - Contents of EIP, in hexa
        if '%PC%' in action:
            action = action.replace('%PC%', HexDump.address(crash.pc) )

        # %SP% - Contents of ESP, in hexa
        if '%SP%' in action:
            action = action.replace('%SP%', HexDump.address(crash.sp) )

        # %FP% - Contents of EBP, in hexa
        if '%FP%' in action:
            action = action.replace('%FP%', HexDump.address(crash.fp) )

        # %WHERE% - Location of the event (a label or address)
        if '%WHERE%' in action:
            if crash.labelPC:
                try:
                    labelPC = str(crash.labelPC)
                except UnicodeError:
                    labelPC = HexDump.address(crash.pc)
            else:
                labelPC = HexDump.address(crash.pc)
            action = action.replace('%WHERE%', labelPC)

        return action

    # Get the location of the code that triggered the event.
    def _get_location(self, event, address):
        label = event.get_process().get_label_at_address(address)
        if label:
            return label
        return HexDump.address(address)

    # Log an exception as a single line of text.
    def _log_exception(self, event):
        what    = event.get_exception_description()
        address = event.get_exception_address()
        where   = self._get_location(event, address)
        if event.is_first_chance():
            chance = 'first'
        else:
            chance = 'second'
        msg = "%s (%s chance) at %s" % (what, chance, where)
        self.logger.log_event(event, msg)

    # Set all breakpoints that can be set
    # at each create process or load dll event.
    def _set_breakpoints(self, event):
        method = event.debug.break_at
        bplist = self.options.break_at
        self._set_breakpoints_from_list(event, bplist, method)
        method = event.debug.stalk_at
        bplist = self.options.stalk_at
        self._set_breakpoints_from_list(event, bplist, method)

    # Set a list of breakppoints using the given method.
    def _set_breakpoints_from_list(self, event, bplist, method):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()
        for label in bplist:
            if dwProcessId not in self.labelsCache:
                self.labelsCache[dwProcessId] = dict()
            # XXX FIXME
            # We may have a problem here for some ambiguous labels...
            if label not in self.labelsCache[dwProcessId]:
                try:
                    address = aModule.resolve_label(label)
                except ValueError, e:
                    address = None
                except RuntimeError, e:
                    address = None
                except WindowsError, e:
                    address = None
                if address is not None:
                    self.labelsCache[dwProcessId][label] = address
                    try:
                        method(dwProcessId, address)
                    except RuntimeError:
                        pass
                    except WindowsError:
                        pass

#-- Events --------------------------------------------------------------------

    # Handle all events not handled by the following methods.
    def event(self, event):
        self._default_event_processing(event, bLogEvent = True)

    # Handle the create process events.
    def create_process(self, event):
        try:
            try:

                # Log the event.
                if self.logger.is_enabled():
                    lpStartAddress = event.get_start_address()
                    szFilename = event.get_filename()
                    if not szFilename:
                        szFilename = Module.unknown
                    if lpStartAddress:
                        where = HexDump.address(lpStartAddress)
                        msg = "Process %s started, entry point at %s"
                        msg = msg % (szFilename, where)
                    else:
                        msg = "Attached to process %s" % szFilename
                    self.logger.log_event(event, msg)

            finally:

                # Process the event.
                self._default_event_processing(event)

        finally:

            # Set user-defined breakpoints for this process.
            self._set_breakpoints(event)

    # Handle the create thread events.
    def create_thread(self, event):
        try:

            # Log the event.
            if self.logger.is_enabled():
                lpStartAddress = event.get_start_address()
                if lpStartAddress:
                    where = self._get_location(event, lpStartAddress)
                    msg   = "Thread started, entry point at %s" % where
                else:
                    msg   = "Attached to thread"
                self.logger.log_event(event, msg)

        finally:

            # Process the event.
            self._default_event_processing(event)

    # Handle the load dll events.
    def load_dll(self, event):
        try:
            try:

                # Log the event.
                if self.logger.is_enabled():
                    aModule     = event.get_module()
                    lpBaseOfDll = aModule.get_base()
                    fileName    = aModule.get_filename()
                    if not fileName:
                        fileName = "a new module"
                    msg = "Loaded %s at %s"
                    msg = msg % (fileName, HexDump.address(lpBaseOfDll))
                    self.logger.log_event(event, msg)

            finally:

                # Process the event.
                self._default_event_processing(event)

        finally:

            # Set user-defined breakpoints for this module.
            self._set_breakpoints(event)

    # Handle the exit process events.
    def exit_process(self, event):
        try:

            # Log the event.
            msg = "Process terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        finally:
            try:

                # Process the event.
                self._default_event_processing(event)

            finally:
                try:

                    # Clear the labels cache for this process.
                    dwProcessId = event.get_pid()
                    if dwProcessId in self.labelsCache:
                        del self.labelsCache[dwProcessId]

                finally:

                    # Restart if requested.
                    if self.options.restart:
                        dwProcessId = event.get_pid()
                        aProcess = event.get_process()

                        # Find out which services were running here.
                        # FIXME: make this more efficient!
                        currentServices = set([ d.ServiceName.lower() for d in aProcess.get_services() ])
                        debuggedServices = set(self.options.service)
                        debuggedServices.intersection_update(currentServices)

                        # We have services dying here, mark them for restart.
                        # They are restarted later at the debug loop.
                        if debuggedServices:
                            self.srvToRestart.update(currentServices)

                        # Now check if this process had hosted any of our
                        # target services before. If the service is stopped
                        # externally we won't know it here, so we need to
                        # keep this information beforehand.
                        targetServices = self.pidToServices.pop(dwProcessId, set())
                        if targetServices:
                            self.srvToRestart.update(targetServices)

                        # No services here, restart the process directly.
                        if not debuggedServices and not targetServices:
                            cmdline = aProcess.get_command_line()
                            event.debug.execl(cmdline)

    # Handle the exit thread events.
    def exit_thread(self, event):
        try:

            # Log the event.
            msg = "Thread terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        finally:

            # Process the event.
            self._default_event_processing(event, bLogEvent = False)

    # Handle the unload dll events.
    def unload_dll(self, event):

        # XXX FIXME
        # We should be updating the labels cache here,
        # otherwise we might lose the breakpoints if
        # the dll gets unloaded and then loaded again.

        try:

            # Log the event.
            if self.logger.is_enabled():
                aModule     = event.get_module()
                lpBaseOfDll = aModule.get_base()
                fileName    = aModule.get_filename()
                if not fileName:
                    fileName = 'a module'
                msg = "Unloaded %s at %s"
                msg = msg % (fileName, HexDump.address(lpBaseOfDll))
                self.logger.log_event(event, msg)

        finally:

            # Process the event.
            self._default_event_processing(event)

    # Handle the debug output string events.
    def output_string(self, event):
        try:

            # Echo the debug strings.
            if self.options.echo:
                win32.OutputDebugString( event.get_debug_string() )

        finally:

            # Process the event.
            self._default_event_processing(event, bLogEvent = True)

    # Handle the RIP events.
    def rip(self, event):
        try:

            # Log the event.
            if self.logger.is_enabled():
                errorCode = event.get_rip_error()
                errorType = event.get_rip_type()
                if errorType == 0:
                    msg = "RIP error at thread %d, code %x"
                elif errorType == SLE_ERROR:
                    msg = "RIP fatal error at thread %d, code %x"
                elif errorType == SLE_MINORERROR:
                    msg = "RIP minor error at thread %d, code %x"
                elif errorType == SLE_WARNING:
                    msg = "RIP warning at thread %d, code %x"
                else:
                    msg = "RIP error type %d, code %%x" % errorType
                self.logger.log_event(event, msg % errorCode)

        finally:

            # Process the event.
            self._default_event_processing(event)

#-- Exceptions ----------------------------------------------------------------

    # Kill the process if it's a second chance exception.
    # Otherwise we'd get stuck in an infinite loop.
    def _post_exception(self, event):
        if hasattr(event, 'is_last_chance') and event.is_last_chance():
##            try:
##                event.get_thread().set_pc(
##                  event.get_process().resolve_symbol('kernel32!ExitProcess')
##                )
##            except Exception:
                event.get_process().kill()

    # Handle all exceptions not handled by the following methods.
    def exception(self, event):
        try:

            # This is almost identical to the default processing.
            # The difference is how logging is handled.
            crash = None
            bNew  = True
            try:
                if self._is_crash_event(event):
                    crash, bNew = self._add_crash(event, bLogEvent = True)
                elif self.logger.is_enabled():
                    self._log_exception(event)
            finally:
                if bNew and self._is_action_event(event):
                    self._action(event, crash)

        finally:

            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    # Some exceptions are ignored by default.
    # You can explicitly enable them again in the config file.
    def _exception_ignored_by_default(self, event, exc_name):
        try:

            # This is almost identical to the exception() method.
            # The difference is the logic to determine if it's a crash.
            crash = None
            bNew  = True
            try:
                if self._is_crash_event(event) and \
                            exc_name in self.options.events:
                    crash, bNew = self._add_crash(event, bLogEvent = True)
                elif self.logger.is_enabled():
                    self._log_exception(event)
            finally:
                if bNew and self._is_action_event(event):
                    self._action(event, crash)

        finally:

            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    # Unknown (most likely C++) exceptions are not crashes,
    # unless explicitly overriden in the config file.
    def unknown_exception(self, event):
        self._exception_ignored_by_default(event, 'unknown_exception')

    # Microsoft Visual C exceptions are not crashes,
    # unless explicitly overriden in the config file.
    def ms_vc_exception(self, event):
        self._exception_ignored_by_default(event, 'ms_vc_exception')

    # Breakpoint events.
    def breakpoint(self, event):
        try:

            # Determine if it's the first chance exception event.
            bFirstChance = event.is_first_chance()

            # Step over breakpoints.
            # This includes both user-defined and hardcoded in the binary.
            if bFirstChance:
                event.continueStatus = win32.DBG_EXCEPTION_HANDLED

            # Determine if the breakpoint is ours.
            bOurs = hasattr(event, 'breakpoint') and event.breakpoint

            # If it's not ours, determine if it's a system breakpoint.
            # If it's ours we don't care.
            bSystem = False
            if not bOurs:

                # WOW64 breakpoints.
                bWow64 = event.get_exception_code() == \
                                            win32.EXCEPTION_WX86_BREAKPOINT

                # Other system breakpoints.
                bSystem = bWow64 or \
                      event.get_process().is_system_defined_breakpoint(
                                                event.get_exception_address())

            # Our breakpoints are always actionable, but only crashes if
            # explicitly stated. System breakpoints are not actionable nor
            # crashes unless explicitly stated, or overriden by the 'break_at'
            # option (in that case they become "our" breakpoints). Otherwise
            # use the same criteria as for all debug events.
            crash = None
            bNew  = True
            try:

                # Determine if it's a crash event.
                bIsCrash = False
                if bOurs or bSystem:
                    if bWow64:
                        bIsCrash = 'wow64_breakpoint' in \
                                                   self.options.crash_events
                    else:
                        bIsCrash = 'breakpoint' in self.options.crash_events
                else:
                    bIsCrash = self._is_crash_event(event)

                # Add it as a crash if so. Always log the brief report.
                if bIsCrash:
                    crash, bNew = self._add_crash(event, bFullReport = False)

            finally:

                # Must the crash be treated as new?
                if bNew:

                    # Determine if we must take action.
                    bAction = False
                    if bOurs:
                        bAction = True
                    elif bSystem:
                        if bWow64:
                            bAction = 'wow64_breakpoint' in \
                                                      self.options.crash_events
                        else:
                            bAction = 'breakpoint' in self.options.crash_events
                    else:
                        bAction = self._is_action_event(event)

                    # If so, take action.
                    if bAction:
                        self._action(event, crash)

        finally:

            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    # WOW64 breakpoints handled by the same code as normal breakpoints.
    def wow64_breakpoint(self, event):
        self.breakpoint(event)

#==============================================================================

class CrashLogger (object):

    # Options object with its default settings.
    class Options (object):
        def __init__(self):

            # Targets
            self.attach         = list()
            self.console        = list()
            self.windowed       = list()
            self.service        = list()

            # List options
            self.action         = list()
            self.break_at       = list()
            self.stalk_at       = list()

            # Tracing options
            self.pause          = False
            self.interactive    = False
            self.time_limit     = 0
            self.echo           = False
            self.action_events  = ['exception', 'output_string']
            self.crash_events   = ['exception', 'output_string']

            # Debugging options
            self.autodetach     = True
            self.hostile        = False
            self.follow         = True
            self.restart        = False

            # Output options
            self.verbose        = True
            self.ignore_errors  = False
            self.logfile        = None
            self.database       = None
            self.duplicates     = True
            self.firstchance    = False
            self.memory         = 0

    # Read the configuration file
    def read_config_file(self, config):

        # Initial options object with default values
        options = self.Options()

        # Keep track of duplicated options
        opt_history = set()

        # Regular expression to split the command and the arguments
        regexp = re.compile(r'(\S+)\s+(.*)')

        # Open the config file
        with open(config, 'rU') as fd:
            number = 0
            while 1:

                # Read a line
                line = fd.readline()
                if not line: break
                number += 1

                # Strip the extra whitespace
                line = line.strip()

                # If it's a comment line or a blank line, discard it
                if not line or line.startswith('#'):
                    continue

                # Split the option and its arguments
                match = regexp.match(line)
                if not match:
                    msg = "cannot parse line %d of config file %s"
                    msg = msg % (number, config)
                    raise RuntimeError(msg)
                key, value = match.groups()

                # Targets
                if   key == 'attach':
                    if value:
                        options.attach.append(value)
                elif key == 'console':
                    if value:
                        options.console.append(value)
                elif key == 'windowed':
                    if value:
                        options.windowed.append(value)
                elif key == 'service':
                    if value:
                        options.service.append(value)

                # List options
                elif key == 'break_at':
                    options.break_at.extend(self._parse_list(value))
                elif key == 'stalk_at':
                    options.stalk_at.extend(self._parse_list(value))
                elif key == 'action':
                    options.action.append(value)

                # Switch options
                else:

                    # Warn about duplicated options
                    if key in opt_history:
                        print "Warning: duplicated option %s in line %d" \
                              " of config file %s" % (key, number, config)
                        print
                    else:
                        opt_history.add(key)

                    # Output options
                    if key == 'verbose':
                        options.verbose = self._parse_boolean(value)
                    elif key == 'logfile':
                        options.logfile = value
                    elif key == 'database':
                        options.database = value
                    elif key == 'duplicates':
                        options.duplicates = self._parse_boolean(value)
                    elif key == 'firstchance':
                        options.firstchance = self._parse_boolean(value)
                    elif key == 'memory':
                        options.memory = int(value)
                    elif key == 'ignore_python_errors':
                        options.ignore_errors = self._parse_boolean(value)

                    # Debugging options
                    elif key == 'hostile':
                        options.hostile = self._parse_boolean(value)
                    elif key == 'follow':
                        options.follow = self._parse_boolean(value)
                    elif key == 'autodetach':
                        options.autodetach = self._parse_boolean(value)
                    elif key == 'restart':
                        options.restart = self._parse_boolean(value)

                    # Tracing options
                    elif key == 'pause':
                        options.pause = self._parse_boolean(value)
                    elif key == 'interactive':
                        options.interactive = self._parse_boolean(value)
                    elif key == 'time_limit':
                        options.time_limit = int(value)
                    elif key == 'echo':
                        options.echo = self._parse_boolean(value)
                    elif key == 'action_events':
                        options.action_events = self._parse_list(value)
                    elif key == 'crash_events':
                        options.crash_events = self._parse_list(value)

                    # Unknown option
                    else:
                        msg = ("unknown option %s in line %d"
                               " of config file %s") % (key, number, config)
                        raise RuntimeError(msg)

        # Return the options object
        return options

    def parse_targets(self, options):

        # Get the list of attach targets
        system = System()
        system.request_debug_privileges()
        system.scan_processes()
        attach_targets = list()
        for token in options.attach:
            if not token:
                continue
            try:
                dwProcessId = HexInput.integer(token)
            except ValueError:
                dwProcessId = None
            if dwProcessId is not None:
                if not system.has_process(dwProcessId):
                    raise ValueError("can't find process %d" % dwProcessId)
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError, e:
                    raise ValueError("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append(dwProcessId)
            else:
                matched = system.find_processes_by_filename(token)
                if not matched:
                    raise ValueError("can't find process %s" % token)
                for process, name in matched:
                    dwProcessId = process.get_pid()
                    try:
                        process = Process(dwProcessId)
                        process.open_handle()
                        process.close_handle()
                    except WindowsError, e:
                        raise ValueError("can't open process %d: %s" % (dwProcessId, e))
                    attach_targets.append(dwProcessId)
        options.attach = attach_targets

        # Get the list of console programs to execute
        console_targets = list()
        for token in options.console:
            if not token:
                continue
            vector = System.cmdline_to_argv(token)
            filename = vector[0]
            if not os.path.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError, e:
                    raise ValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            token = System.argv_to_cmdline(vector)
            console_targets.append(token)
        options.console = console_targets

        # Get the list of windowed programs to execute
        windowed_targets = list()
        for token in options.windowed:
            if not token:
                continue
            vector = System.cmdline_to_argv(token)
            filename = vector[0]
            if not os.path.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError, e:
                    raise ValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            token = System.argv_to_cmdline(vector)
            windowed_targets.append(token)
        options.windowed = windowed_targets

        # Get the list of services to attach to
        service_targets = list()
        for token in options.service:
            if not token:
                continue
            try:
                status = System.get_service(token)
            except WindowsError:
                try:
                    token  = System.get_service_from_display_name(token)
                    status = System.get_service(token)
                except WindowsError, e:
                    raise ValueError("error searching for service %s: %s" % (token, str(e)))
            if not hasattr(status, 'ProcessId'):
                raise ValueError("service targets not supported by the current platform")
            service_targets.append(token.lower())
        options.service = service_targets

        # If no targets were set at all, show an error message
        if not options.attach and not options.console and not options.windowed and not options.service:
           raise ValueError("no targets found!")

    def parse_options(self, options):

        # Warn or fail about inconsistent use of DBM databases
        if options.database and options.database.startswith('dbm://'):
            if options.memory and options.memory > 1:
                print "Warning: using options 'dbm' and 'memory' in combination can have a severe"
                print "  performance penalty."
                print
            if options.duplicates:
                if options.verbose:
                    print "Warning: inconsistent use of 'duplicates'"
                    print "  DBM databases do not allow duplicate entries with the same key."
                    print "  This means that when the same crash is found more than once it will be logged"
                    print "  to standard output each time, but will only be saved once into the database."
                    print
                else:
                    msg  = "inconsistent use of 'duplicates': "
                    msg += "DBM databases do not allow duplicate entries with the same key"
                    raise ValueError(msg)

        # Warn about inconsistent use of time_limit
        if options.time_limit and options.autodetach \
                                    and (options.windowed or options.console):
            count = len(options.windowed) + len(options.console)
            print
            print "Warning: inconsistent use of 'time_limit'"
            if count == 1:
                print "  An execution time limit was set, but the launched process won't be killed."
            else:
                print "  An execution time limit was set, but %d launched processes won't be killed." % count
            print "  Set 'autodetach' to false to make sure debugees are killed on exit."
            print "  Alternatively use 'attach' instead of launching new processes."
            print

        # Warn about inconsistent use of pause and interactive
        if options.pause and options.interactive:
            print "Warning: the 'pause' option is ignored when 'interactive' is set."
            print

    def _parse_list(self, value):
        tokens = set()
        for token in value.lower().split(','):
            token = token.strip()
            tokens.add(token)
        return tokens

    def _parse_boolean(self, value):
        value = value.strip().lower()
        if value == 'true' or value == 'yes' or value == 'y':
            return True
        if value == 'false' or value == 'no' or value == 'n':
            return False
        return bool(int(value))

    # Run from the command line
    def run_from_cmdline(self, args):

        # Show the banner
        print "WinAppDbg crash logger"
        print "by Mario Vilas (mvilas at gmail.com)"
        print winappdbg.version
        print

        # TODO: use optparse for this!
        # TODO: move crash_report.py here
        # TODO: implement a GUI

        try:

            # Help message
            if len(args) >= 2 and args[1].strip().lower() in ('-h', '--help', '/?'):
                self.show_help_banner()

            # Debugger mode
            elif len(args) == 2:
                config = args[1]
                options = self.read_config_file(config)
                self.parse_targets(options)
                self.parse_options(options)
                self.run(config, options)

            # JIT debugger mode
            elif len(args) == 4 and args[1].strip().lower() == '--jit':
                config = args[2]
                options = self.read_config_file(config)
                self.parse_options(options)
                options.attach.append(args[3])
                self.parse_targets(options)
                self.run(config, options)

            # Install as JIT debugger
            elif len(args) == 3 and args[1].strip().lower() == '--install':
                self.install_as_jit(args[2])

            # Uninstall as JIT debugger
            elif len(args) == 2 and args[1].strip().lower() == '--uninstall':
                self.uninstall_as_jit()

            # On error show the help message
            else:
                self.show_help_banner()

        # Catch errors and show them on screen
        except Exception, e:
            print "Runtime error: %s" % str(e)
            traceback.print_exc()
            return

    def install_as_jit(self, config):

        # Calculate the command line to run in JIT mode
        # TODO maybe fix this so it works with py2exe?
        interpreter = os.path.abspath(sys.executable)
        script = os.path.abspath(__file__)
        config = os.path.abspath(config)
        argv = [interpreter, script, '--jit', config, '%ld']
        cmdline = System.argv_to_cmdline(argv)

        # Test the config file
        options = self.read_config_file(config)
        self.parse_options(options)

        # Show the previous JIT debugger
        # TODO check if it's us already
        # TODO maybe keep a backup?
        previous = System.get_postmortem_debugger()
        print "Previous JIT debugger was: %s" % previous

        # Install as JIT debugger
        System.set_postmortem_debugger(cmdline)

    def uninstall_as_jit(self):

        # Remove the current JIT debugger
        # TODO check if it's us or some other debugger
        # TODO maybe restore the previous one?
        System.remove_postmortem_debugger()

    def show_help_banner(self):
        script = os.path.split(__file__)[1]
        print "Usage:"
        print "\t%s <configuration file>" % script
        print
        print "See example.cfg for details on the config file format."

    # Run the crash logger
    def run(self, config, options):

        # Create the event handler
        oldCrashCount = 0
        eventHandler  = LoggingEventHandler(options, config)
        logger        = eventHandler.logger

        # Log the time we begin this run
        if options.verbose:
            logger.log_text("Crash logger started, %s" % time.ctime())
            logger.log_text("Configuration: %s" % config)

        # Run
        try:
            self._run(eventHandler, options)

        # Log the time we finish this run
        finally:
            if options.verbose:
                logger.log_text("Crash logger stopped, %s" % time.ctime())

    def _run(self, eventHandler, options):

        # Create the debug object
        with Debug(eventHandler, bHostileCode = options.hostile) as debug:

            # Run the crash logger using this debug object
            try:
                self._start_or_attach(debug, options, eventHandler)
                try:
                    self._debugging_loop(debug, options, eventHandler)
                except Exception:
                    if not options.verbose:
                        raise
                    return

            # Kill all debugees on exit if requested
            finally:
                if not options.autodetach:
                    debug.kill_all(bIgnoreExceptions = True)

    def _start_or_attach(self, debug, options, eventHandler):
        logger = eventHandler.logger

        # Start or attach to the targets
        try:
            for pid in options.attach:
                debug.attach(pid)
            for cmdline in options.console:
                debug.execl(cmdline, bConsole = True,
                                     bFollow  = options.follow)
            for cmdline in options.windowed:
                debug.execl(cmdline, bConsole = False,
                                     bFollow  = options.follow)
            for service in options.service:
                status = System.get_service(service)
                if not status.ProcessId:
                    status = self._start_service(service, logger)
                debug.attach(status.ProcessId)
                try:
                    eventHandler.pidToServices[status.ProcessId].add(service)
                except KeyError:
                    srvSet = set()
                    srvSet.add(service)
                    eventHandler.pidToServices[status.ProcessId] = srvSet

        # If the 'autodetach' was set to False,
        # make sure the debugees die if the debugger dies unexpectedly
        finally:
            if not options.autodetach:
                debug.system.set_kill_on_exit_mode(True)

    @staticmethod
    def _start_service(service, logger):

        # Start the service.
        status = System.get_service(service)
        try:
            name = System.get_service_display_name(service)
        except WindowsError:
            name = service
        print "Starting service \"%s\"..." % name
        # TODO: maybe add support for starting services with arguments?
        System.start_service(service)

        # Wait for it to start.
        timeout = 20
        status = System.get_service(service)
        while status.CurrentState == win32.SERVICE_START_PENDING:
            timeout -= 1
            if timeout <= 0:
                logger.log_text("Error: timed out.")
                msg = "Timed out waiting for service \"%s\" to start"
                raise Exception(msg % name)
            time.sleep(0.5)
            status = System.get_service(service)

        # Done.
        logger.log_text("Service \"%s\" started successfully." % name)
        return status

    # Main debugging loop
    def _debugging_loop(self, debug, options, eventHandler):

        # Get the logger.
        logger = eventHandler.logger

        # If there's a time limit, calculate how much is it.
        timedOut = False
        if options.time_limit:
            maxTime = time.time() + options.time_limit

        # Loop until there are no more debuggees.
        while debug.get_debugee_count() > 0:

            # Wait for debug events, with an optional timeout.
            while 1:
                if options.time_limit:
                    timedOut = time.time() > maxTime
                    if timedOut:
                        break
                try:
                    debug.wait(100)
                    break
                except WindowsError, e:
                    if e.winerror not in (win32.ERROR_SEM_TIMEOUT,
                                          win32.WAIT_TIMEOUT):
                        logger.log_exc()
                        raise   # don't ignore this error
                except Exception:
                    logger.log_exc()
                    raise   # don't ignore this error
            if timedOut:
                logger.log_text("Execution time limit reached")
                break

            # Dispatch the debug event and continue execution.
            try:
                try:
                    debug.dispatch()
                finally:
                    debug.cont()
            except Exception:
                logger.log_exc()
                if not options.ignore_errors:
                    raise

            # Restart services marked for restart by the event handler.
            # Also attach to those services we want to debug.
            try:
                while eventHandler.srvToRestart:
                    service = eventHandler.srvToRestart.pop()
                    try:
                        descriptor = self._start_service(service, logger)
                        if service in options.service:
                            try:
                                debug.attach(descriptor.ProcessId)
                                try:
                                    eventHandler.pidToServices[descriptor.ProcessId].add(service)
                                except KeyError:
                                    srvSet = set()
                                    srvSet.add(service)
                                    eventHandler.pidToServices[descriptor.ProcessId] = srvSet
                            except Exception:
                                logger.log_exc()
                                if not options.ignore_errors:
                                    raise
                    except Exception:
                        logger.log_exc()
                        if not options.ignore_errors:
                            raise
            except Exception:
                logger.log_exc()
                if not options.ignore_errors:
                    raise

def main(argv):
    try:
        cl = CrashLogger()
        return cl.run_from_cmdline(argv)
    except KeyboardInterrupt:
        print "Interrupted by the user!"

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
