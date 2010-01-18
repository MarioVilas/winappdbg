#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# sehtest: Bruteforce valid addresses for an SEH overwrite buffer overflow
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

__revision__ = "$Id$"

import os
import sys
import optparse

import winappdbg
from winappdbg import win32
from winappdbg import Debug, EventHandler, System, Process, MemoryAddresses
from winappdbg import DataAddressIterator, ExecutableAddressIterator
from winappdbg import HexInput, HexDump, CrashDump, Logger

#------------------------------------------------------------------------------

class Test( object ):

    protect_conversions = {
        win32.PAGE_EXECUTE_READWRITE:   win32.PAGE_EXECUTE_READ,
        win32.PAGE_EXECUTE_WRITECOPY:   win32.PAGE_EXECUTE_READ,
        win32.PAGE_READWRITE:           win32.PAGE_READONLY,
        win32.PAGE_WRITECOPY:           win32.PAGE_READONLY,
    }

    def __init__(self, options, logger):
        self.options        = options
        self.logger         = logger
        self.testing        = None  # True if we're bruteforcing, False if we're waiting
        self.debug          = None  # Debug object
        self.pid            = None  # ID of process to bruteforce
        self.tid            = None  # ID of thread to bruteforce
        self.process        = None  # Process to bruteforce
        self.thread         = None  # Thread to bruteforce
        self.target_iter    = None  # Iterator of target addresses to bruteforce
        self.context        = None  # Original thread context
        self.memory         = None  # Dynamic memory snapshot: page -> (content, protect, tainted)
        self.orig_seh_first = None  # Original SEH chain pointer
        self.orig_seh_block = None  # Original SEH block contents
        self.new_seh_first  = None  # New SEH chain pointer, for bruteforcing
        self.new_seh_ptr    = None  # Pointer to pointer to exception handler
        self.current_target = None  # Exception handler address being tested

    def exception(self, event):
        print event.get_tid(), event.get_exception_name(), hex(event.get_fault_address())

        if event.get_tid() != self.tid:
            event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
            return

        # First exception event received, initialize
        if self.testing is None:
            self.testing = False
            self.debug   = event.debug
            self.pid     = event.get_pid()
            self.tid     = event.get_tid()
            self.process = event.get_process()
            self.thread  = event.get_thread()

        # Waiting for the SEH to be overwritten
        if not self.testing:
            if event.is_first_chance():
                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
                self.findAttackerExceptionHandler()
                if self.testing:
                    self.suspendOtherThreads()
                    self.setupTargetAddressIterator()
                    self.setupExceptionHandlerChain()
                    self.setupSnapshot()        # must be taken LAST!
            else:
                event.continueStatus = win32.DBG_TERMINATE_PROCESS
                self.thread.set_pc( self.process.resolve_label('kernel32!ExitProcess') )
                return

        # Bruteforcing all valid SEH locations
        if self.testing:
            if event.is_last_chance():
##                event.continueStatus = win32.DBG_EXCEPTION_HANDLED
##                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
                event.continueStatus = win32.DBG_CONTINUE
            else:
                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
                self.nextExceptionHandler()

##                event.continueStatus = win32.DBG_CONTINUE
##                if event.get_exception_code() == win32.EXCEPTION_ACCESS_VIOLATION and \
##                    event.get_fault_type() == win32.EXCEPTION_WRITE_FAULT and \
##                    self.updateSnapshot(event.get_fault_address()):
##                        event.continueStatus = win32.DBG_CONTINUE
####                        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
##                else:
##                    self.nextExceptionHandler()

    def breakpoint(self, event):
        print event.get_exception_name()
        if hasattr(event, 'bp'):
            print "Found: %s" % HexDump.address(self.current_target)
            self.nextExceptionHandler()

    def nextExceptionHandler(self):
        self.removeBreakpoint(self.current_target)
        self.restoreSnapshot()
        try:
            self.current_target = self.target_iter.next()
        except StopIteration:
            self.cleanupSnapshot()  # inverse order, see Test.exception
            self.restoreExceptionHandlerChain()
            self.resumeOtherThreads()
            self.testing        = None
            self.pid            = None
            self.tid            = None
            self.process        = None
            self.thread         = None
            self.target_iter    = None
            raise
        self.setupExceptionHandlerChain()
        self.process.write_pointer(self.new_seh_ptr, self.current_target)
        self.setBreakpoint(self.current_target)

    def removeBreakpoint(self, address):
        if address is not None:
            self.debug.dont_stalk_at(self.process.get_pid(), address)

    def setBreakpoint(self, address):
##        self.updateSnapshot(address)
##        self.thread.set_tf()
        self.debug.stalk_at(self.process.get_pid(), address)
##        self.debug.stalk_at(self.process.get_pid(), address, self.testme)

##    def testme(self, event):
##        print "TEST ME!!!!!!!!"
##        raise KeyboardInterrupt

    def setupTargetAddressIterator(self):
        self.target_iter = ExecutableAddressIterator(self.process.get_memory_map())

    def setupSnapshot(self):
        self.context = self.thread.get_context()
        forbidden = set()
        forbidden.add( MemoryAddresses.align_address_to_page_start( self.process.get_peb_address() ) )
        for thread in self.process.iter_threads():
            forbidden.add( MemoryAddresses.align_address_to_page_start( thread.get_teb_address() ) )
        self.memory  = dict()
        for mbi in self.process.get_memory_map():
            if mbi.is_writeable():
                for page in xrange(mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize, System.pageSize):
                    if page in forbidden:
                        continue
##                    self.process.mprotect(page, System.pageSize, self.protect_conversions[mbi.Protect])
##                    self.memory[page] = (None, mbi.Protect, False)
                    self.memory[page] = self.process.read(page, System.pageSize)

##    def updateSnapshot(self, address):
##        page = MemoryAddresses.align_address_to_page_start(address)
##        if self.memory.has_key(page):
##            (contents, protect, tainted) = self.memory[page]
##            tainted = True
##            if contents is None:
##                contents = self.process.read(page, System.pageSize)
##            self.process.mprotect(page, System.pageSize, protect)
##            self.memory[page] = (contents, protect, tainted)
##            print "Updated snapshot! Page %x" % page
##            return True
##        return False

    def restoreSnapshot(self):
        print "ANTES", self.thread.get_pc()
        self.thread.set_context(self.context)
        print "DESPUES", self.thread.get_pc()
##        raise KeyboardInterrupt

        for page, contents in self.memory.iteritems():
            self.process.write(page, contents)

##        for page in self.memory.keys():
##            (contents, protect, tainted) = self.memory[page]
##            if tainted:
##                tainted = False
##                self.process.write(page, contents)
##                self.process.mprotect(page, System.pageSize, self.protect_conversions[protect])
##                self.memory[page] = (contents, protect, tainted)

    def cleanupSnapshot(self):
        self.restoreSnapshot() # probably redundant, but keep it for robustness
##        for page in self.memory.keys():
##            (_, protect, _) = self.memory[page]
##            self.process.mprotect(page, System.pageSize, protect)
        self.memory = None

    def findAttackerExceptionHandler(self):
        attacker_seh = self.options.seh
        sizeof_pvoid = win32.sizeof(win32.PVOID)
        pfirst   = self.thread.get_seh_chain_pointer()
        pcurrent = pfirst
        while pcurrent != 0xFFFFFFFF:
            try:
                pnext = self.process.read_pointer(pcurrent)
                pseh  = self.process.read_pointer(pcurrent + sizeof_pvoid)
            except WindowsError:
                break
            if pseh == attacker_seh:
                self.testing        = True
                self.orig_seh_first = pfirst
                self.orig_seh_block = (pnext, pseh)
                self.new_seh_first  = pcurrent
                self.new_seh_ptr    = pcurrent + sizeof_pvoid
                break
            pcurrent = pnext

    def setupExceptionHandlerChain(self):
        if self.orig_seh_first != self.new_seh_first:
            self.thread.set_seh_chain_pointer(self.new_seh_first)
        if self.orig_seh_block[0] != 0xFFFFFFFF:
            self.process.write_pointer(self.new_seh_first, 0xFFFFFFFF)

    def restoreExceptionHandlerChain(self):
        self.process.write_pointer(self.new_seh_ptr, orig_seh_block[1])
        if self.orig_seh_block[0] != 0xFFFFFFFF:
            self.process.write_pointer(self.orig_seh_first, orig_seh_block[0])
        if self.orig_seh_first != self.new_seh_first:
            self.thread.set_seh_chain_pointer(self.orig_seh_first)
        self.orig_seh_first = None
        self.orig_seh_block = None
        self.new_seh_first  = None
        self.new_seh_ptr    = None

    def suspendOtherThreads(self):
        current_tid = self.thread.get_tid()
        for thread in self.process.iter_threads():
            if thread.get_tid() != current_tid:
                thread.suspend()

    def resumeOtherThreads(self):
        current_tid = self.thread.get_tid()
        for thread in self.process.iter_threads():
            if thread.get_tid() != current_tid:
                thread.resume()


class Handler( EventHandler ):

    def __init__(self, options):
        super(Handler, self).__init__()
        self.options = options
        self.test    = dict()   # pid -> Test
        self.logger  = Logger()

    def __forward_call(self, event, method_name):
##        try:
            pid = event.get_pid()
            if not self.test.has_key(pid):
                self.test[pid] = test = Test(self.options, self.logger)
            else:
                test = self.test[pid]
            method = getattr(test, method_name)
            try:
                method(event)
            except StopIteration:
                del self.test[pid]
                event.debug.detach(pid)
##        except Exception:
##            self.logger.log_exc()

    def exception(self, event):
        self.__forward_call(event, 'exception')

    def breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        pc = event.get_exception_address()
        if not event.get_process().is_system_defined_breakpoint(pc):
            print "EEEESAAAA", hex(pc), event.get_process().get_label_at_address(pc)
            self.__forward_call(event, 'breakpoint')

##    def single_step(self, event):
##        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
##        event.get_thread().set_tf()
##        print event.get_exception_name(), HexDump.address(event.get_exception_address())

    def wow64_breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED

    def debug_control_c(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED

    def invalid_handle(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED

    def possible_deadlock(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED

#------------------------------------------------------------------------------

def main( argv ):

    # Parse the command line arguments
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = Handler(options)

    # Create the debug object
    debug = Debug(eventHandler, bKillOnExit = not options.autodetach)
    try:

        # Attach to the targets
        for dwProcessId in options.attach:
            debug.attach(dwProcessId)
        for lpCmdLine in options.console:
            debug.execl(lpCmdLine, bConsole = True,  bFollow = options.follow)
        for lpCmdLine in options.windowed:
            debug.execl(lpCmdLine, bConsole = False, bFollow = options.follow)

        # Run the debug loop
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()

#------------------------------------------------------------------------------

def parse_cmdline( argv ):

    # Help message and version string
    version = (
              "Bruteforce valid addresses for an SEH overwrite buffer overflow\n"
              "by Mario Vilas (mvilas at gmail.com)\n"
              "%s\n"
              ) % winappdbg.version
    usage = (
            "\n"
            "\n"
            "  Create a new process (parameters for the target must be escaped):\n"
            "    %prog [options] -c <executable> [parameters for the target]\n"
            "    %prog [options] -e <executable> [parameters for the target]\n"
            "\n"
            "  Attach to a running process (by filename):\n"
            "    %prog [options] -a <executable>\n"
            "\n"
            "  Attach to a running process (by ID):\n"
            "    %prog [options] -a <process id>"
            )
    parser = optparse.OptionParser(
                                    usage=usage,
                                    version=version,
                                  )

    # Commands
    commands = optparse.OptionGroup(parser, "Commands")
    commands.add_option("-a", "--attach", action="append",
                        help="Attach to a running process")
    commands.add_option("-w", "--windowed", action="append",
                        help="Create a new windowed process")
    commands.add_option("-c", "--console", action="append",
                        help="Create a new console process [default]")
    parser.add_option_group(commands)

    # SEH test options
    sehtest = optparse.OptionGroup(parser, "SEH Test options")
    sehtest.add_option("--seh", metavar="ADDRESS",
                       help="address of SEH handler function to hijack [default: 0x41414141]")
    parser.add_option_group(sehtest)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
    debugging.add_option("--autodetach", action="store_true",
                  help="automatically detach from debugees on exit [default]")
    debugging.add_option("--follow", action="store_true",
                  help="automatically attach to child processes [default]")
    debugging.add_option("--dont-autodetach", action="store_false",
                                                         dest="autodetach",
                  help="don't automatically detach from debugees on exit")
    debugging.add_option("--dont-follow", action="store_false",
                                                             dest="follow",
                  help="don't automatically attach to child processes")
    parser.add_option_group(debugging)

    # Defaults
    parser.set_defaults(
        autodetach  = True,
        follow      = True,
        windowed    = list(),
        console     = list(),
        attach      = list(),
        verbose     = True,
        seh         = '0x41414141',
    )

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
    (options, args) = parser.parse_args(argv)
    args = args[1:]
    if not options.windowed and not options.console and not options.attach:
        options.console = [ System.argv_to_cmdline(args) ]
    else:
        if args:
            parser.error("don't know what to do with extra parameters: %s" % args)

    # Validate the SEH test options
    try:
        options.seh = HexInput.address(options.seh)
    except ValueError:
        parser.error("invalid address for --seh: %s" % options.seh)

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
                parser.error("can't find process %d" % dwProcessId)
            try:
                process = Process(dwProcessId)
                process.open_handle()
                process.close_handle()
            except WindowsError, e:
                parser.error("can't open process %d: %s" % (dwProcessId, e))
            attach_targets.append(dwProcessId)
        else:
            matched = system.find_processes_by_filename(token)
            if not matched:
                parser.error("can't find process %s" % token)
            for process, name in matched:
                dwProcessId = process.get_pid()
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError, e:
                    parser.error("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append( process.get_pid() )
    options.attach = attach_targets

    # Get the list of console programs to execute
    console_targets = list()
    for token in options.console:
        vector = system.cmdline_to_argv(token)
        if not vector:
            parser.error("bad use of --console")
        filename = vector[0]
        if not os.path.exists(filename):
            try:
                filename = win32.SearchPath(None, filename, '.exe')[0]
            except WindowsError, e:
                parser.error("error searching for %s: %s" % (filename, str(e)))
            vector[0] = filename
            token     = system.argv_to_cmdline(vector)
        console_targets.append(token)
    options.console = console_targets

    # Get the list of windowed programs to execute
    windowed_targets = list()
    for token in options.windowed:
        vector = system.cmdline_to_argv(token)
        if not vector:
            parser.error("bad use of --windowed")
        filename = vector[0]
        if not os.path.exists(filename):
            try:
                filename = win32.SearchPath(None, filename, '.exe')[0]
            except WindowsError, e:
                parser.error("error searching for %s: %s" % (filename, str(e)))
            vector[0] = filename
            token     = system.argv_to_cmdline(vector)
        windowed_targets.append(token)
    options.windowed = windowed_targets

    # If no targets were set at all, show an error message
    if not options.attach and not options.console and not options.windowed:
        parser.error("no targets found!")

    return options

#------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
