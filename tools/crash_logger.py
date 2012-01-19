#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Crash logger
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

__revision__ = "$Id$"

__all__ =   [
                'LoggingEventHandler',
            ]

import winappdbg
from winappdbg import *

import os
import sys
import time
import traceback
import xml.dom
import xml.dom.minidom

try:
    import cerealizer
    cerealizer.freeze_configuration()
except ImportError:
    pass

try:
    import psyco
    from psyco.classes import *
except ImportError:
    psyobj = object

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
    """

    def __init__(self, options, currentConfig = None):

        # Copy the user-defined options.
        self.options = options

        # Copy the configuration used in this fuzzing session.
        self.currentConfig = currentConfig

        # Create the logger object.
        self.logger = Logger(options.logfile, options.verbose)

        # Create the crash container.
        if not options.nodb:
            if options.dbm:
                self.knownCrashes = CrashContainer( options.dbm )
            elif options.sqlite:
                self.knownCrashes = CrashTable( options.sqlite,
                                    allowRepeatedKeys = options.duplicates )
            elif options.mssql:
                self.knownCrashes = CrashTableMSSQL( options.mssql,
                                    allowRepeatedKeys = options.duplicates )
            else:
                self.knownCrashes = DummyCrashContainer( \
                                    allowRepeatedKeys = options.duplicates )
        else:
            self.knownCrashes = DummyCrashContainer( \
                                    allowRepeatedKeys = options.duplicates )

        # Create the cache of resolved labels.
        self.labelsCache = dict()                   # pid -> label -> address

        # Call the base class constructor.
        super(LoggingEventHandler, self).__init__()

    def __add_crash(self, event, bFullReport = False):

        # Generate a crash object.
        crash = Crash(event)
        crash.addNote('Config: %s' % self.currentConfig)

        # Determine if the crash was previously known.
        bNew = self.options.duplicates or crash not in self.knownCrashes

        # Add the crash object to the container.
        if bNew:
            crash.fetch_extra_data(event, self.options.memory)
            self.knownCrashes.add(crash)

        # Log the event to standard output.
        try:
            if self.options.verbose:
                if bFullReport and bNew:
                    msg = crash.fullReport(bShowNotes = False)
                else:
                    msg = crash.briefReport()
                self.logger.log_event(event, msg)

        # Take action if requested and the crash is new.
        finally:
            if bNew and self.__action_requested(event):
                self.__action(event, crash)

    # Determine if an action is requested for this event.
    def __action_requested(self, event):
        return \
            ('event' in self.options.events) or \
            ('exception' in self.options.events and \
                (event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and \
                (event.is_last_chance() or self.options.firstchance))) or \
            (event.eventMethod in self.options.events)

    # Actions to take for "interesting" events.
    def __action(self, event, crash = None):
        try:

            # Run the given command if any.
            if self.options.action:
                self.__run_command(event, crash)

        finally:

            # Enter interactive mode if requested.
            if self.options.interactive:
                event.debug.interactive(bConfirmQuit = False)

            # Pause if requested.
            if self.options.pause:
                raw_input("Press enter to continue...")

    # Run the given command, if any.
    # Wait until the command completes.
    # To avoid waiting, use the "start" command.
    def __run_command(self, event, crash = None):
        action = System.argv_to_cmdline(self.options.action)
        if '%' in action:
            if not crash:
                crash = Crash(event)
            # %COUNT% - Number of crashes currently stored in the database.
            # %EXCEPTIONCODE% - Exception code in hexa
            # %EVENTCODE% - Event code in hexa
            # %EXCEPTION% - Exception name, human readable
            # %EVENT% - Event name, human readable
            # %PC% - Contents of EIP, in hexa
            # %SP% - Contents of ESP, in hexa
            # %FP% - Contents of EBP, in hexa
            # %WHERE% - Location of the event (a label or address)
            action = action.replace('%COUNT%',          str(len(self.knownCrashes)) )
            action = action.replace('%EXCEPTIONCODE%',  HexDump.address(crash.exceptionCode) )
            action = action.replace('%EVENTCODE%',      HexDump.address(crash.eventCode) )
            action = action.replace('%EXCEPTION%',      str(crash.exceptionName) )
            action = action.replace('%EVENT%',          str(crash.eventName) )
            action = action.replace('%PC%',             HexDump.address(crash.pc) )
            action = action.replace('%SP%',             HexDump.address(crash.sp) )
            action = action.replace('%FP%',             HexDump.address(crash.fp) )
            action = action.replace('%WHERE%',          str(crash.labelPC) )
        action = "cmd.exe /c %s" % action
        system  = System()
        process = system.start_process(action, bConsole = True)
        process.wait()

    # Get the location of the code that triggered the event.
    def __get_location(self, event, address):
        label = event.get_process().get_label_at_address(address)
        if label:
            return label
        return HexDump.address(address)

    # Log an exception as a single line of text.
    def __log_exception(self, event):
        what    = event.get_exception_description()
        address = event.get_exception_address()
        where   = self.__get_location(event, address)
        if event.is_first_chance():
            chance = 'first'
        else:
            chance = 'second'
        msg = "%s (%s chance) at %s" % (what, chance, where)
        self.logger.log_event(event, msg)

    # Set all breakpoints that can be set
    # at each create process or load dll event.
    def __set_breakpoints(self, event):
        method = event.debug.break_at
        bplist = self.options.break_at
        self.__set_breakpoints_from_list(event, bplist, method)
        method = event.debug.stalk_at
        bplist = self.options.stalk_at
        self.__set_breakpoints_from_list(event, bplist, method)

    # Set a list of breakppoints using the given method.
    def __set_breakpoints_from_list(self, event, bplist, method):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()
        for label in bplist:
            if dwProcessId not in self.labelsCache:
                self.labelsCache[dwProcessId] = dict()
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
        self.__add_crash(event, bFullReport = True)

    # Handle the create process events.
    def create_process(self, event):

        # Set user-defined breakpoints for this process.
        try:
            self.__set_breakpoints(event)

        # Log the event to standard output.
        finally:
            if self.options.verbose:
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

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

    # Handle the create thread events.
    def create_thread(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            lpStartAddress = event.get_start_address()
            if lpStartAddress:
                where = self.__get_location(event, lpStartAddress)
                msg   = "Thread started, entry point at %s" % where
            else:
                msg   = "Attached to thread"
            self.logger.log_event(event, msg)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

    # Handle the load dll events.
    def load_dll(self, event):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()

        # Set user-defined breakpoints for this module.
        try:
            self.__set_breakpoints(event)

        # Log the event to standard output.
        finally:
            lpBaseOfDll = aModule.get_base()
            fileName    = aModule.get_filename()
            if self.options.verbose:
                if not fileName:
                    fileName = "a new module"
                msg = "Loaded %s at %s"
                msg = msg % (fileName, HexDump.address(lpBaseOfDll))
                self.logger.log_event(event, msg)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

    # Handle the exit process events.
    def exit_process(self, event):

        # Clear the labels cache for this process.
        dwProcessId = event.get_pid()
        if dwProcessId in self.labelsCache:
            del self.labelsCache[dwProcessId]

        # Log the event to standard output.
        if self.options.verbose:
            msg = "Process terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

        # Restart if requested.
        if self.options.restart:
            event.debug.execl( event.get_process().get_command_line() )

    # Handle the exit thread events.
    def exit_thread(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            msg = "Thread terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

    # Handle the unload dll events.
    def unload_dll(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            aModule     = event.get_module()
            lpBaseOfDll = aModule.get_base()
            fileName    = aModule.get_filename()
            if not fileName:
                fileName = 'a module'
            msg = "Unloaded %s at %s"
            msg = msg % (fileName, HexDump.address(lpBaseOfDll))
            self.logger.log_event(event, msg)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

    # Handle the debug output string events.
    def output_string(self, event):
        if self.options.echo:
            win32.OutputDebugString( event.get_debug_string() )
        self.__add_crash(event)

    # Handle the RIP events.
    def rip(self, event):

        # Log the event to standard output.
        if self.options.verbose:
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

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

#-- Exceptions ----------------------------------------------------------------

    # Kill the process if it's a second chance exception.
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
            if event.is_last_chance() or self.options.firstchance:
                self.__add_crash(event, bFullReport = True)
            elif self.options.verbose:
                self.__log_exception(event)
        finally:
            self._post_exception(event.debug.lastEvent)

    # Unknown (most likely C++) exceptions are not crashes.
    # Comment out this code if needed...
    def unknown_exception(self, event):
        try:

            # Log the event to standard output.
            if self.options.verbose:
                self.__log_exception(event)

            # Take action if requested.
            if self.__action_requested(event):
                self.__action(event)

        finally:
            self._post_exception(event.debug.lastEvent)

    # Microsoft Visual C exceptions are not crashes.
    # Comment out this code if needed...
    def ms_vc_exception(self, event):
        try:

            # Log the event to standard output.
            if self.options.verbose:
                self.__log_exception(event)

            # Take action if requested.
            if self.__action_requested(event):
                self.__action(event)

        finally:
            self._post_exception(event.debug.lastEvent)

    # Breakpoint events are not crashes when they're ours,
    # or when they were triggered by known system-defined breakpoints.
    # Comment out this code if needed...
    def breakpoint(self, event):
        try:

            # Determine if it's the first chance exception event.
            bFirstChance = event.is_first_chance()

            # Step over breakpoints.
            # This includes both user-defined and hardcoded in the binary.
            if bFirstChance:
                event.continueStatus = win32.DBG_EXCEPTION_HANDLED

            # Get the address where the exception occured.
            address = event.get_exception_address()

            # Determine if the breakpoint is ours.
            bOurs = hasattr(event, 'breakpoint') and event.breakpoint

            # Determine if the breakpoint is WOW64 breakpoint.
            bWow64 = event.get_exception_code() == win32.EXCEPTION_WX86_BREAKPOINT

            # Determine if the breakpoint is a system defined breakpoint.
            bSystem = bWow64 or (not bOurs and \
                      event.get_process().is_system_defined_breakpoint(address))

            # Add the crash if this is an unexpected breakpoint event.
            # It may be signaling a C/C++ assert() failure.
            if (not bOurs and not bSystem) or not bFirstChance:
                self.__add_crash(event, bFullReport = False)

            # If it's not a crash, log and take action as appropriate.
            else:
                try:

                    # Log the event to standard output.
                    if self.options.verbose:
                        where   = self.__get_location(event, address)
                        if bOurs:
                            msg = "Breakpoint hit (%s)" % where
                        elif bWow64:
                            msg = "WOW64 breakpoint hit (%s)" % where
                        elif bSystem:
                            msg = "System breakpoint hit (%s)" % where
                        else:
                            msg = "Assertion failed (%s)" % where
                        self.logger.log_event(event, msg)

                finally:

                    # Take action if requested or the breakpoint is ours.
                    # Always ignore system defined breakpoints.
                    # To force the action on system defined breakpoints,
                    # redefine them with the 'break_at' option.
                    if bOurs or (not bSystem and self.__action_requested(event)):
                        self.__action(event)

        finally:
            self._post_exception(event.debug.lastEvent)

    # WOW64 breakpoints are treated the same way as normal breakpoints.
    # Change this code if needed...
    def wow64_breakpoint(self, event):
        self.breakpoint(event)

#==============================================================================

class CrashLogger (psyobj):

    # Options object with its default settings.
    class Options (psyobj):
        def __init__(self):

            # Targets
            self.attach         = list()
            self.console        = list()
            self.windowed       = list()

            # Tracing options
            self.break_at       = None
            self.stalk_at       = None
            self.pause          = False
            self.restart        = False
            self.time_limit     = 0
            self.echo           = False
            self.events         = 'exception'
            self.action         = None
            self.interactive    = False

            # Debugging options
            self.autodetach     = True
            self.hostile        = False
            self.follow         = True

            # Output options
            self.verbose        = True
            self.ignore_errors  = False
            self.logfile        = None
            self.duplicates     = True
            self.firstchance    = False
            self.memory         = 0
            self.nodb           = False
            self.dbm            = None
            self.sqlite         = None
            self.mssql          = None

    # Read the configuration file
    def read_config_file(self, config, ignoreTargets = False):

        # Initial options object with default values
        options = self.Options()

        # Keep track of duplicated tags
        tags = set()

        # Read the config file into a DOM object
        dom = None
        try:
            dom = xml.dom.minidom.parse(config)
            configuration = dom.getElementsByTagName('configuration')
            if configuration.length != 1:
                raise xml.dom.SyntaxErr()

            # Parse each node and read the settings
            for node in configuration.item(0).childNodes:
                if node.nodeType != xml.dom.Node.ELEMENT_NODE:
                    continue
                key, value = self._parse_xml_tag(node)

                # Targets
                if   key == 'attach':
                    if value and not ignoreTargets:
                        options.attach.append(value)
                elif key == 'console':
                    if value and not ignoreTargets:
                        options.console.append(value)
                elif key == 'windowed':
                    if value and not ignoreTargets:
                        options.windowed.append(value)

                # Options
                else:

                    # Warn about duplicated options
                    if key in tags:
                        print "Warning: " \
                              "duplicated option tag in config file: %s" % key
                    else:
                        tags.add(key)

                    # Tracing options
                    if   key == 'break_at':
                        options.break_at = value
                    elif key == 'stalk_at':
                        options.stalk_at = value
                    elif key == 'pause':
                        options.pause = self._parse_boolean(value)
                    elif key == 'restart':
                        options.restart = self._parse_boolean(value)
                    elif key == 'time_limit':
                        options.time_limit = int(value)
                    elif key == 'echo':
                        options.echo = self._parse_boolean(value)
                    elif key == 'events':
                        options.events = value
                    elif key == 'action':
                        options.action = value
                    elif key == 'interactive':
                        options.interactive = self._parse_boolean(value)

                    # Debugging options
                    elif key == 'autodetach':
                        options.autodetach = self._parse_boolean(value)
                    elif key == 'hostile':
                        options.hostile = self._parse_boolean(value)
                    elif key == 'follow':
                        options.follow = self._parse_boolean(value)

                    # Output options
                    elif key == 'verbose':
                        options.verbose = self._parse_boolean(value)
                    elif key == 'ignore_python_errors':
                        options.ignore_errors = self._parse_boolean(value)
                    elif key == 'logfile':
                        options.logfile = value
                    elif key == 'duplicates':
                        options.duplicates = self._parse_boolean(value)
                    elif key == 'firstchance':
                        options.firstchance = self._parse_boolean(value)
                    elif key == 'memory':
                        options.memory = int(value)
                    elif key == 'nodb':
                        options.nodb = self._parse_boolean(value)
                    elif key == 'dbm':
                        options.dbm = value
                    elif key == 'sqlite':
                        options.sqlite = value
                    elif key == 'odbc':
                        options.odbc = value

                    # Unknown tag
                    else:
                        raise xml.dom.NotSupportedErr(key)

        # Destroy the DOM object
        finally:
            if dom is not None:
                dom.unlink()

        # Validate the settings
        if not ignoreTargets:
            self.validate_targets(options)
        self.validate_options(options)

        # Return the options object
        return options

    def _parse_xml_tag(self, node):
        key = node.nodeName
        value = node.nodeValue
        if key is None:
            raise xml.dom.SyntaxErr()
        if value is None:
            if len(node.childNodes) == 0:
                try:
                    value = node.attributes['value'].value
                except AttributeError:
                    value = None
                except KeyError:
                    value = None
            else:
                if len(node.childNodes) > 1:
                    raise xml.dom.HierarchyRequestErr()
                text = node.childNodes[0]
                if text.nodeType != xml.dom.Node.TEXT_NODE:
                    raise xml.dom.SyntaxErr()
                value = text.nodeValue
                if value is None:
                    raise xml.dom.SyntaxErr()
        elif node.hasChildNodes():
            raise xml.dom.HierarchyRequestErr()
        return key, value

    def validate_targets(self, options):

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

        # If no targets were set at all, show an error message
        if not options.attach and not options.console and not options.windowed:
           raise ValueError("no targets found!")

    def validate_options(self, options):

        # Get the list of breakpoints to set
        if options.break_at:
            if not os.path.exists(options.break_at):
                raise ValueError("breakpoint list file not found: %s" % options.break_at)
            try:
                options.break_at = HexInput.string_list_file(options.break_at)
            except ValueError, e:
                parser.error(str(e))
        else:
            options.break_at = list()

        # Get the list of one-shot breakpoints to set
        if options.stalk_at:
            if not os.path.exists(options.stalk_at):
                raise ValueError("one-shot breakpoint list file not found: %s" % options.stalk_at)
            options.stalk_at = HexInput.string_list_file(options.stalk_at)
        else:
            options.stalk_at = list()

        # Parse the list of events to monitor
        options.events = self._parse_events(options.events)

        # Warn or fail about inconsistent use of output switches
        if options.nodb:
            if options.dbm or options.sqlite or options.mssql:
                print "Warning: strange use of output options"
                print "  No database will be generated. Are you sure this is what you wanted?"
                print
        elif options.dbm:
            if options.memory > 1:
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
            elif options.sqlite or options.mssql:
               raise ValueError("cannot generate more than one database per session")
        elif options.sqlite and options.mssql:
            raise ValueError("cannot generate more than one database per session")

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

    def _parse_events(self, value):
        events = set()
        for event_name in value.lower().split(','):
            event_name = event_name.strip()
            events.add(event_name)
        return events

    def _parse_boolean(self, value):
        value = value.strip().lower()
        if value == 'true':
            return True
        if value == 'false':
            return False
        return bool(int(value))

    # Run from the command line
    def run_from_cmdline(self, args):

        # Show the banner
        print "WinAppDbg crash logger"
        print "by Mario Vilas (mvilas at gmail.com)"
        print winappdbg.version
        print

        try:

            # Help message
            if len(args) >= 2 and args[1].strip().lower() in ('-h', '--help', '/?'):
                self.show_help_banner()

            # GUI mode
            elif len(args) == 0:
                # XXX TODO
                self.show_help_banner()

            # Debugger mode
            elif len(args) == 2:
                config = args[1]
                options = self.read_config_file(config)
                self.run(config, options)

            # JIT debugger mode
            elif len(args) == 4 and args[1].strip().lower() == '--jit':
                config = args[2]
                options = self.read_config_file(config, ignoreTargets=True)
                options.attach.append(args[3])
                self.validate_targets(options)
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
        # TODO fix this so it works with py2exe
        interpreter = os.path.abspath(sys.executable)
        script = os.path.abspath(__file__)
        config = os.path.abspath(config)
        argv = [interpreter, script, '--jit', config, '%ld']
        cmdline = System.argv_to_cmdline(argv)

        # Test the config file
        self.read_config_file(config, ignoreTargets=True)

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
        print "See the online help to learn about the configuration file format:"
        print "\thttp://winappdbg.sourceforge.net/Tools.html#crash-logger"

    # Run the crash logger
    def run(self, config, options):

        # Create the event handler
        oldCrashCount = 0
        eventHandler  = LoggingEventHandler(options, config)
        eventHandler.logger.log_text("Crash logger started, %s" % time.ctime())
        eventHandler.logger.log_text("Configuration: %s" % config)

        # Create the debug object
        debug = Debug(eventHandler, bHostileCode = options.hostile)
        try:

            # Attach to the targets
            try:
                for pid in options.attach:
                    debug.attach(pid)
                for cmdline in options.console:
                    debug.execl(cmdline, bConsole = True,
                                         bFollow  = options.follow)
                for cmdline in options.windowed:
                    debug.execl(cmdline, bConsole = False,
                                         bFollow  = options.follow)

            # If the 'autodetach' was set to False,
            # make sure the debugees die if the debugger dies unexpectedly
            finally:
                if not options.autodetach and debug.get_debugee_count() > 0:
                    debug.system.set_kill_on_exit_mode(True)

            # Main debugging loop
            timedOut = False
            if options.time_limit:
                maxTime = time.time() + options.time_limit
            while debug.get_debugee_count() > 0:
                while 1:
                    if options.time_limit:
                        timedOut = time.time() > maxTime
                        if timedOut:
                            break
                    try:
                        debug.wait(100)
                        break
                    except WindowsError, e:
                        if win32.winerror(e) not in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
                            eventHandler.logger.log_exc()
                            raise   # don't ignore this error
                    except Exception:
                        eventHandler.logger.log_exc()
                        raise   # don't ignore this error
                if timedOut:
                    eventHandler.logger.log_text("Execution time limit reached")
                    break
                try:
                    try:
                        debug.dispatch()
                    finally:
                        debug.cont()
                except Exception:
                    eventHandler.logger.log_exc()
                    if not options.ignore_errors:
                        raise
        finally:
            if not options.autodetach:
                debug.kill_all(bIgnoreExceptions = True)
            debug.stop()
            if options.verbose:
                eventHandler.logger.log_text("Crash logger stopped, %s" % time.ctime())

def main(argv):
    try:
        return CrashLogger().run_from_cmdline(argv)
    except KeyboardInterrupt:
        print "Interrupted by the user!"

if __name__ == '__main__':
    try:
        psyco.bind(main)
    except NameError:
        pass
    main(sys.argv)
