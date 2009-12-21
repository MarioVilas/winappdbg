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

# XXX TODO
# * log Python exceptions instead of stopping everything!
# * filter out syscalls not issued from within the exception handling code in
#   ntdll.dll (to avoid unwanted side effects)

class Test( object ):
    def __init__(self, options, logger):
        self.options = options
        self.logger  = logger
        self.testing = False
        self.seh     = None
        self.orig    = None
        self.last    = None
        self.context = None
        self.memory  = None

    def exception(self, event):
##        event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
##        event.continueStatus = win32.DBG_CONTINUE
        if not self.testing:
            self.logExceptionEvent(event)
            if event.is_last_chance():
                event.continueStatus = win32.DBG_TERMINATE_PROCESS
            else:
                self.checkExceptionChain(event)
        else:
            if event.is_last_chance():
                event.continueStatus = win32.DBG_EXCEPTION_HANDLED
            else:
                if not self.checkProtectedPage(event):
                    self.nextExceptionHandler(event)

    def checkProtectedPage(self, event):
        if event.get_exception_code() == win32.EXCEPTION_ACCESS_VIOLATION:
##            address = event.get_exception_address() # Oops! This returns EIP
            address = event.get_fault_address()
            address = MemoryAddresses.align_address_to_page_start(address)
            if self.saved_pages.has_key(address):
                if self.saved_pages[address] is None:
                    pageSize = System.pageSize
                    process  = event.get_process()
                    data     = process.read(address, pageSize)
                    self.saved_pages[address] = data
                    for mbi in self.memory:
                        if address in mbi:
                            process.mprotect(address, pageSize, mbi.Protect)
                            return True
        return False

    def protectPages(self, event):
        self.saved_pages = dict()
        pageSize = System.pageSize
        process  = event.get_process()
        for mbi in self.memory:
            if mbi.is_writeable():
                if mbi.is_executable():
                    flNewProtect = win32.PAGE_EXECUTE_READ
                else:
                    flNewProtect = win32.PAGE_READONLY
                try:
                    process.mprotect(mbi.BaseAddress, mbi.RegionSize, flNewProtect)
                except WindowsError:
##                    msg = "  Skipped memory region: %.8x - %.8x - %s"
##                    msg = msg % (mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize,
##                        process.get_mapped_filenames([mbi]).get(mbi.BaseAddress))
##                    print msg
                    continue
                for address in xrange(mbi.BaseAddress,
                                      mbi.BaseAddress + mbi.RegionSize,
                                      pageSize):
                    self.saved_pages[address] = None

    def unprotectPages(self, event):
        pageSize = System.pageSize
        process  = event.get_process()
        for mbi in self.memory:
            if mbi.is_writeable():
                for address in xrange(mbi.BaseAddress,
                                      mbi.BaseAddress + mbi.RegionSize,
                                      pageSize):
                    data = self.saved_pages.get(address, None)
                    if data is not None:
                        process.write(address, data)
                process.mprotect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect)
        self.saved_pages = dict()

    # XXX TODO
    # This would be more efficient with a dictionary of SavedPage objects!
    def restorePages(self, event):
        pageSize = System.pageSize
        process  = event.get_process()
        for mbi in self.memory:
            if mbi.is_writeable():
                dirty = False
                for address in xrange(mbi.BaseAddress,
                                      mbi.BaseAddress + mbi.RegionSize,
                                      pageSize):
                    if self.saved_pages.has_key(address):
                        data = self.saved_pages[address]
                        if data is not None:
                            process.write(address, data)
                            self.saved_pages[address] = None
                            dirty = True
                if dirty:
                    if mbi.is_executable():
                        flNewProtect = win32.PAGE_EXECUTE_READ
                    else:
                        flNewProtect = win32.PAGE_READONLY
                    process.mprotect(mbi.BaseAddress, mbi.RegionSize, flNewProtect)

    def logExceptionEvent(self, event):
        what  = event.get_exception_name()
        where = HexDump.address( event.get_exception_address() )
        if event.is_first_chance():
            chance = 'first'
        else:
            chance = 'second'
        msg   = "Caught %s (%s chance) at %s" % (what, chance, where)
        self.logger.log_event(event, msg)

    def checkExceptionChain(self, event):

        # XXX TODO
        # + Add a list of exceptions to ignore
        # + Option to ignore first chance exceptions
        # + Option to fail on missing SEH chain

        thread  = event.get_thread()
        process = event.get_process()
        target  = self.options.seh
        if target:
            chain = thread.get_seh_chain()
            if chain:
                index = 0
                for (_, address) in chain:
                    if address == target:
                        if index > 0:
                            self.seh = chain[index - 1][0]
                        else:
                            self.seh = thread.get_seh_chain_pointer()
                        break
                    index += 1
            else:
                self.seh = thread.get_seh_chain_pointer()
        else:
            self.seh = thread.get_seh_chain_pointer()

        if self.seh:
            self.startBruteforcing(event)

    def startBruteforcing(self, event):
        thread  = event.get_thread()
        process = event.get_process()
        msg = "Target SEH found at %s, preparing to bruteforce..."
        msg = msg % HexDump.address(self.seh)
        self.logger.log_text(msg)
        self.testing  = True
        self.orig     = process.read_pointer(self.seh + 4)
        self.context  = thread.get_context()
        self.orig_fs0 = thread.get_seh_chain_pointer()
        self.memory   = process.get_memory_map()
        self.iterator = ExecutableAddressIterator(self.memory)
        self.protectPages(event)
        self.showBruteforceBanner(event)
        self.nextExceptionHandler(event)

    def showBruteforceBanner(self, event):
        count = 0
        first = 0
        last  = 0
        for mbi in self.memory:
            if mbi.is_executable():
                count = count + mbi.RegionSize
                address = mbi.BaseAddress
                if first == 0:
                    first = address
                if last < address:
                    last = address
        msg   = "Bruteforcing %d addresses (%s-%s)..."
        first = HexDump.address(first)
        last  = HexDump.address(last)
        self.logger.log_text(msg % (count, first, last))

    def nextExceptionHandler(self, event):
        debug   = event.debug
        process = event.get_process()
        thread  = event.get_thread()
        pid     = process.get_pid()

        thread.set_context(self.context)
        thread.set_seh_chain_pointer(self.orig_fs0)
        self.restorePages(event)

        try:
            address = self.iterator.next()
        except StopIteration:
            self.unprotectPages(event)
            process.write_pointer(self.seh + 4, self.orig)
            event.debug.detach(pid)
            raise

        if self.last:
            debug.dont_stalk_at(pid, self.last)
##        self.logger.log_text("Trying %s" % HexDump.address(address))
        process.write_pointer(self.seh + 4, address)
        debug.stalk_at(pid, address, self.foundValidHandler)
        self.last = address

    def foundValidHandler(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        self.logExceptionEvent(event)
        address = HexDump.address( event.get_exception_address() )
        self.logger.log_text("Found %s" % address)
        self.nextExceptionHandler(event)

class Handler( EventHandler ):

    def __init__(self, options):
        super(Handler, self).__init__()
        self.options = options
        self.test    = dict()   # pid -> Test
        self.logger  = Logger()

    def exception(self, event):
##        try:
            pid = event.get_pid()
            if not self.test.has_key(pid):
                self.test[pid] = test = Test(self.options, self.logger)
            else:
                test = self.test[pid]
            try:
                test.exception(event)
            except StopIteration:
                del self.test[pid]
##        except Exception:
##            self.logger.log_exc()

    def breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED

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
##    formatter = optparse.IndentedHelpFormatter()
##    formatter = optparse.TitledHelpFormatter()
    parser = optparse.OptionParser(
                                    usage=usage,
                                    version=version,
##                                    formatter=formatter,
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
