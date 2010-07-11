#!~/.wine/drive_c/Python25/python.exe

# Crash logger
# Copyright (c) 2009-2010, Mario Vilas
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
import optparse
import traceback

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

# Python 2.x compatibility
try:
    raw_input
except NameError:
    raw_input = input

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
            elif options.odbc:
                self.knownCrashes = CrashTableODBC( options.odbc,
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

        # Run the given command if any.
        try:
            if self.options.action:
                self.__run_command(event, crash)

        # Pause if requested.
        finally:
            if self.options.pause:
                input("Press enter to continue...")

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
                except ValueError:
                    address = None
                except RuntimeError:
                    address = None
                except WindowsError:
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
        if event.is_last_chance():
            try:
                event.get_thread().set_pc(
                    event.get_process().resolve_symbol('kernel32!ExitProcess')
                )
            except Exception:
                event.get_process().kill()

    # Handle all exceptions not handled by the following methods.
    def exception(self, event):
        if event.is_last_chance() or self.options.firstchance:
            self.__add_crash(event, bFullReport = True)
        elif self.options.verbose:
            self.__log_exception(event)
        self._post_exception(event)

    # Unknown (most likely C++) exceptions are not crashes.
    # Comment out this code if needed...
    def unknown_exception(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            self.__log_exception(event)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

        self._post_exception(event)

    # Microsoft Visual C exceptions are not crashes.
    # Comment out this code if needed...
    def ms_vc_exception(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            self.__log_exception(event)

        # Take action if requested.
        if self.__action_requested(event):
            self.__action(event)

        self._post_exception(event)

##    # First chance single step events are not crashes.
##    # Comment out this code if needed...
##    def single_step(self, event):
##
##        # If it's a last chance exception, it's a crash.
##        if event.is_last_chance():
##            self.__add_crash(event, bFullReport = True)
##        else:
##
##            # Continue without setting the trap flag.
##            event.continueStatus = win32.DBG_EXCEPTION_HANDLED
##
##            # Log the event to standard output.
##            if self.options.verbose:
##                address = event.get_exception_address()
##                where   = self.__get_location(event, address)
##                msg     = "Single step event at %s" % where
##                self.logger.log_event(event, msg)
##
##            # Take action if requested.
##            if self.__action_requested(event):
##                self.__action(event)
##
##        self._post_exception(event)

    # Breakpoint events are not crashes when they're ours,
    # or when they were triggered by known system-defined breakpoints.
    # Comment out this code if needed...
    def breakpoint(self, event):

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
                # redefine them with the --break command line option.
                if bOurs or (not bSystem and self.__action_requested(event)):
                    self.__action(event)

        self._post_exception(event)

    # WOW64 breakpoints are treated the same way as normal breakpoints.
    # Change this code if needed...
    def wow64_breakpoint(self, event):
        self.breakpoint(event)

#==============================================================================

class CrashLogger (object):

    defaults = {

            # Commands
            'attach'      : list(),
            'console'     : list(),
            'windowed'    : list(),

            # Tracing options
            'break_at'    : None,
            'stalk_at'    : None,
            'pause'       : False,
            'restart'     : False,
            'time_limit'  : 0,
            'echo'        : False,
            'events'      : 'exception',
            'action'      : None,

            # Debugging options
            'autodetach'  : True,
            'hostile'     : False,
            'follow'      : True,

            # Output options
            'verbose'     : True,
            'logfile'     : None,
            'duplicates'  : True,
            'firstchance' : False,
            'memory'      : 0,
            'nodb'        : False,
            'dbm'         : None,
            'sqlite'      : None,
            'odbc'        : None,
    }

    # Parse the configuration file.
    def parse_config_file(self, config_file, section = None):
        parser = configparser.SafeConfigParser(self.defaults)
        parser.read(config_file)
        options = object()
        for key, value in self.defaults:
            setattr(options, key, value)
        self._parse_config_file_section(options, parser)
        if section:
            self._parse_config_file_section(options, parser, section)
        self._warn_inconsistent_options(options)
        self._validate_options(options)
        return (parser, options)

    def _parse_boolean(self, value):
        value = value.strip().lower()
        if value == 'true':
            return True
        if value == 'false':
            return False
        return bool(int(value))

    def _parse_events(self, value):
        events = set()
        for event_name in value.lower().split(','):
            event_name = event_name.strip()
            events.add(event_name)
        return events

    # Parse a section of the configuration file.
    def _parse_config_file_section(self, options, parser, section = None):
        if not section:
            section = 'DEFAULT'
        for key, value in parser.items(section):
            try:

                # Commands
                if   key == 'attach':
                    options.attach.append(value)
                elif key == 'console':
                    options.attach.console(value)
                elif key == 'windowed':
                    options.attach.windowed(value)

                # Tracing options
                elif key == 'break_at':
                    options.break_at = value
                elif key == 'stalk_at':
                    options.stalk_at = value
                elif key == 'pause':
                    options.pause = self.__parse_boolean(value)
                elif key == 'restart':
                    options.restart = self.__parse_boolean(value)
                elif key == 'time_limit':
                    options.time_limit = int(value)
                elif key == 'echo':
                    options.echo = self.__parse_boolean(value)
                elif key == 'events':
                    options.events = value
                elif key == 'action':
                    options.action = value

                # Debugging options
                elif key == 'autodetach':
                    options.autodetach = self.__parse_boolean(value)
                elif key == 'hostile':
                    options.hostile = self.__parse_boolean(value)
                elif key == 'follow':
                    options.follow = self.__parse_boolean(value)

                # Output options
                elif key == 'verbose':
                    options.verbose = self.__parse_boolean(value)
                elif key == 'logfile':
                    options.logfile = value
                elif key == 'duplicates':
                    options.duplicates = self.__parse_boolean(value)
                elif key == 'firstchance':
                    options.firstchance = self.__parse_boolean(value)
                elif key == 'memory':
                    options.memory = int(value)
                elif key == 'nodb':
                    options.nodb = self.__parse_boolean(value)
                elif key == 'dbm':
                    options.dbm = value
                elif key == 'sqlite':
                    options.sqlite = value
                elif key == 'odbc':
                    options.odbc = value

                # Unknown option
                else:
                    raise optparse.OptionValueError("unknown option")

            except Exception:
                e = sys.exc_info()[1]
                raise optparse.OptionValueError("error in option %s: %s" % (key, str(e)))

    def _warn_inconsistent_options(self, options):

        # Warn or fail about inconsistent use of output switches
        if options.nodb:
            if options.dbm or options.sqlite or options.odbc:
                print("Warning: strange use of output switches")
                print("  No database will be generated. Are you sure this is what you wanted?")
                print("")
        elif options.dbm:
            if options.memory > 1:
                print("Warning: using --dbm and --memory-snapshot in combination can have a severe")
                print("  performance penalty.")
                print("")
            if options.duplicates:
                if options.verbose:
                    print("Warning: inconsistent use of --allow-duplicates")
                    print("  DBM databases do not allow duplicate entries with the same key.")
                    print("  This means that when the same crash is found more than once it will be logged")
                    print("  to standard output each time, but will only be saved once into the database.")
                    print("")
                else:
                    msg  = "inconsistent use of --allow-duplicates: "
                    msg += "DBM databases do not allow duplicate entries with the same key"
                    raise optparse.OptionValueError(msg)
            elif options.sqlite or options.odbc:
               raise optparse.OptionValueError("cannot generate more than one database per session")
        elif options.sqlite and options.odbc:
            raise optparse.OptionValueError("cannot generate more than one database per session")

        # Warn about inconsistent use of --time-limit
        if options.time_limit and options.autodetach \
                                    and (options.windowed or options.console):
            count = len(options.windowed) + len(options.console)
            print("")
            print("Warning: inconsistent use of --time-limit")
            if count == 1:
                print("  An execution time limit was set, but the launched process won't be killed.")
            else:
                print("  An execution time limit was set, but %d launched processes won't be killed." % count)
            print("  Use the --kill option to make sure debugees are killed on exit.")
            print("  Alternatively use --attach instead of launching new processes.")
            print("")

    def _validate_options(self, options):

        # Get the list of attach targets
        system = System()
        system.request_debug_privileges()
        system.scan_processes()
        attach_targets = list()
        for token in options.attach:
            try:
                dwProcessId = HexInput.integer(token)
            except ValueError:
                dwProcessId = None
            if dwProcessId is not None:
                if not system.has_process(dwProcessId):
                    raise optparse.OptionValueError("can't find process %d" % dwProcessId)
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError:
                    e = sys.exc_info()[1]
                    raise optparse.OptionValueError("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append(dwProcessId)
            else:
                matched = system.find_processes_by_filename(token)
                if not matched:
                    raise optparse.OptionValueError("can't find process %s" % token)
                for process, name in matched:
                    dwProcessId = process.get_pid()
                    try:
                        process = Process(dwProcessId)
                        process.open_handle()
                        process.close_handle()
                    except WindowsError:
                        e = sys.exc_info()[1]
                        raise optparse.OptionValueError("can't open process %d: %s" % (dwProcessId, e))
                    attach_targets.append(dwProcessId)
        options.attach = attach_targets

        # Get the list of console programs to execute
        console_targets = list()
        for vector in options.console:
            if not vector:
                raise optparse.OptionValueError("bad use of --console")
            filename = vector[0]
            if not os.path.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError:
                    e = sys.exc_info()[1]
                    raise optparse.OptionValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            console_targets.append(vector)
        options.console = console_targets

        # Get the list of windowed programs to execute
        windowed_targets = list()
        for vector in options.windowed:
            if not vector:
                raise optparse.OptionValueError("bad use of --windowed")
            filename = vector[0]
            if not os.path.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError:
                    e = sys.exc_info()[1]
                    raise optparse.OptionValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            windowed_targets.append(vector)
        options.windowed = windowed_targets

        # If no targets were set at all, show an error message
        if not options.attach and not options.console and not options.windowed:
           raise optparse.OptionValueError("no targets found!")

        # Get the list of breakpoints to set
        if options.break_at:
            if not os.path.exists(options.break_at):
                raise optparse.OptionValueError("breakpoint list file not found: %s" % options.break_at)
            try:
                options.break_at = HexInput.string_list_file(options.break_at)
            except ValueError:
                e = sys.exc_info()[1]
                parser.error(str(e))
        else:
            options.break_at = list()

        # Get the list of one-shot breakpoints to set
        if options.stalk_at:
            if not os.path.exists(options.stalk_at):
                raise optparse.OptionValueError("one-shot breakpoint list file not found: %s" % options.stalk_at)
            options.stalk_at = HexInput.string_list_file(options.stalk_at)
        else:
            options.stalk_at = list()

        # Parse the list of events to monitor
        options.events = self._parse_events(options.events)

    # Parse the command line
    def parse_cmdline(self, argv):

        # Help message and version string
        version = (
                  "WinAppDbg crash logger\n"
                  "by Mario Vilas (mvilas at gmail.com)\n"
                  "%s\n"
                  ) % winappdbg.version
        usage = (
                "\n"
                "\n"
                "  Create a new process (parameters for the target must be escaped):\n"
                "    %prog [options] -c <executable> [parameters for the target]\n"
                "    %prog [options] -w <executable> [parameters for the target]\n"
                "\n"
                "  Attach to a running process (by filename):\n"
                "    %prog [options] -a <executable>\n"
                "\n"
                "  Attach to a running process (by ID):\n"
                "    %prog [options] -a <process id>"
                )
    ##    formatter = optparse.IndentedHelpFormatter()
    ##    formatter = optparse.TitledHelpFormatter()
        parser = optparse.OptionParser(
                                        usage=usage,
                                        version=version,
    ##                                    formatter=formatter,
                                      )
        parser.add_option("-i", "--ignore-errors", action="store_true", default=False,
                          help="Ignore Python exceptions")

        # Commands
        commands = optparse.OptionGroup(parser, "Commands")
        commands.add_option("-a", "--attach", action="callback", type="string",
                            metavar="PROCESS", callback=self.callback_execute_target,
                            help="Attach to a running process")
        commands.add_option("-c", "--console", action="callback", type="string",
                            metavar="CMDLINE", callback=self.callback_execute_target,
                            help="Create a new console process [default]")
        commands.add_option("-w", "--windowed", action="callback", type="string",
                            metavar="CMDLINE", callback=self.callback_execute_target,
                            help="Create a new windowed process")
        parser.add_option_group(commands)

        # Tracing options
        tracing = optparse.OptionGroup(parser, "Tracing options")
        tracing.add_option("-b", "--break-at", metavar="FILE",
                           help="Set code breakpoints from list file")
        tracing.add_option("-s", "--stalk-at", metavar="FILE",
                           help="Set one-shot code breakpoints from list file")
        tracing.add_option("-p", "--pause", action="store_true",
                           help="Pause on each new crash found")
        tracing.add_option("-r", "--restart", action="store_true",
                           help="Restart debugees when they finish executing (be careful when using --follow)")
        tracing.add_option("-k", "--kill", action="store_false", dest="autodetach",
                           help="Same as --dont-autodetach")
        tracing.add_option("-t", "--time-limit", action="store", type="int", metavar="SECONDS",
                          help="Limit the execution time of the debugees, use 0 for no limit")
        tracing.add_option("--echo", action="store_true",
                           help="Repeat debug strings")
        tracing.add_option("--events", metavar="LIST",
                           help="Comma separated list of events to monitor")
        tracing.add_option("--action", metavar="COMMAND", action="append",
                           help="Run the given command on each new crash found")
        parser.add_option_group(tracing)

        # Debugging options
        debugging = optparse.OptionGroup(parser, "Debugging options")
        debugging.add_option("--autodetach", action="store_true",
                      help="automatically detach from debugees on exit [default]")
        debugging.add_option("--follow", action="store_true",
                      help="automatically attach to child processes [default]")
        debugging.add_option("--trusted", action="store_false",
                                                                dest="hostile",
                      help="treat debugees as trusted code [default]")
        debugging.add_option("--dont-autodetach", action="store_false",
                                                             dest="autodetach",
                      help="don't automatically detach from debugees on exit")
        debugging.add_option("--dont-follow", action="store_false",
                                                                 dest="follow",
                      help="don't automatically attach to child processes")
        debugging.add_option("--hostile", action="store_true",
                      help="treat debugees as hostile code")
        parser.add_option_group(debugging)

        # Output options
        # TODO
        # * autogenerate a default crash dump filename from the executable file
        output = optparse.OptionGroup(parser, "Output options")
        output.add_option("-v", "--verbose", action="store_true", dest="verbose",
                          help="Log events to standard output [default]")
        output.add_option("-q", "--quiet", action="store_false", dest="verbose",
                          help="Do not log events to standard output")
        output.add_option("--log", metavar="FILE", dest="logfile",
                          help="Log events to text file")
        output.add_option("--allow-duplicates", action="store_true",
                          dest="duplicates",
                          help="Stop on all crashes [default]")
        output.add_option("--ignore-duplicates", action="store_false",
                          dest="duplicates",
                          help="Stop only on newly found crashes")
        output.add_option("--allow-first-chance", action="store_true",
                          dest="firstchance",
                          help="Stop on first and second chance exceptions")
        output.add_option("--ignore-first-chance", action="store_false",
                          dest="firstchance",
                          help="Stop only on second chance exceptions [default]")
        output.add_option("--no-memory", action="store_const", const=0, dest="memory",
                          help="Don't save the memory state for each crash [default]")
        output.add_option("--memory-map", action="store_const", const=1, dest="memory",
                          help="Save the memory map for each crash")
        output.add_option("--memory-snapshot", action="store_const", const=3, dest="memory",
                          help="Save the entire memory contents for each crash")
        output.add_option("--nodb", action="store_true",
                          help="Do not save a crash dump file [default]")
        output.add_option("--dbm", metavar="FILE",
                          help="Save crash dumps to this DBM database")
        output.add_option("--sqlite", metavar="FILE",
                          help="Save crash dumps to this SQLite database")
        output.add_option("--odbc", metavar="CONNSTR",
                          help="Save crash dumps to an SQL database using this connection string")
        output.add_option("-f", "--file", metavar="FILE", dest="dbm",
                          help="Same as --dbm, deprecated")
        parser.add_option_group(output)

        # Defaults
        parser.set_defaults(**self.defaults)

        # Parse and validate the command line options
        if len(argv) == 1:
            argv = argv + [ '--help' ]
        (options, args) = parser.parse_args(argv)
        args = args[1:]
        if not options.windowed and not options.console and not options.attach:
            if not args:
                parser.error("missing target application(s)")
            options.console = [ args ]
        elif args:
            # this should no longer happen, see callback_execute_target()
            parser.error("don't know what to do with extra parameters: %s" % args)
        try:
            self._warn_inconsistent_options(options)
            self._validate_options(options)
        except optparse.OptParseError:
            e = sys.exc_info()[1]
            parser.error(str(e))

        # Return the parsed command line options and arguments
        return (parser, options, args)

    # Callback to parse -a, -c and -w command line switches
    @staticmethod
    def callback_execute_target(option, opt_str, value, parser):

        # Get the destination variable name.
        dest_name = option.dest
        if dest_name is None:
            dest_name = option.get_opt_string().replace('-', '')

        # Get the destination list to append.
        # Create a new list if needed.
        destination = getattr(parser.values, dest_name, None)
        if destination is None:
            destination = list()
            setattr(parser.values, dest_name, destination)

        # If a value is received from optparse, put it back in the list of
        # arguments to be consumed.
        #
        # From what I gather by examining the examples in the documentation
        # this wasn't even supposed to happen. (!)
        #
        # I suspect is happening because I had to force the argument type for
        # the command line switch definition as a workaround for another bug
        # (the metavariable wasn't being shown in the help message).
        #
        if value is not None:
            parser.rargs.insert(0, value)

        # Get the value from the command line arguments.
        value = []
        for arg in parser.rargs:

            # Stop on --foo like options but not on -- alone.
            if arg[:2] == "--" and len(arg) > 2:
                break

            # Stop on -a like options but not on - alone.
            if arg[:1] == "-" and len(arg) > 1:
                break

            value.append(arg)

        # Delete the command line arguments we consumed
        # so they're not parsed again.
        del parser.rargs[:len(value)]

        # Append the value to the destination list.
        destination.append(value)

    # Run from the command line
    def run_from_cmdline(self, args):
        try:
            config = System.argv_to_cmdline(args)
            (_, options, args) = self.parse_cmdline(args)
            self.run(config, options, args)
        except Exception:
            e = sys.exc_info()[1]
            print("Runtime error: %s" % str(e))
            traceback.print_exc()
            return

    # Run from a config file
    def run_from_config_file(self, config):
        try:
            (_, options) = self.parse_config_file(config)
            self.run(config, options, args)
        except Exception:
            e = sys.exc_info()[1]
            print("Runtime error: %s" % str(e))
            traceback.print_exc()
            return

    # Run the crash logger
    def run(self, config, options, args):

        # Create the event handler
        oldCrashCount = 0
        eventHandler  = LoggingEventHandler(options, config)
        eventHandler.logger.log_text("Crash logger started, %s" % time.ctime())
        eventHandler.logger.log_text("Configuration: %s" % config)

        # Create the debug object
        debug = Debug(eventHandler,
                        bKillOnExit  = not options.autodetach,
                        bHostileCode = options.hostile)
        try:

            # Attach to the targets
            for pid in options.attach:
                debug.attach(pid)
            for argv in options.console:
                debug.execv(argv, bConsole = True,  bFollow = options.follow)
            for argv in options.windowed:
                debug.execv(argv, bConsole = False, bFollow = options.follow)

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
                        event = debug.wait(100)
                        break
                    except WindowsError:
                        e = sys.exc_info()[1]
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
                        debug.dispatch(event)
                    finally:
                        debug.cont(event)
                except Exception:
                    eventHandler.logger.log_exc()
                    if not options.ignore_errors:
                        raise
        finally:
            if options.verbose:
                eventHandler.logger.log_text("Crash logger stopped, %s" % time.ctime())

def main(argv):
    try:
        return CrashLogger().run_from_cmdline(argv)
    except KeyboardInterrupt:
        print("Interrupted by the user!")

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
