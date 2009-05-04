#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his command line debugger on which this one is inspired.

# Command line debugger using WinAppDbg
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
import traceback

from cmd import Cmd

import winappdbg
from winappdbg import win32

try:
    import readline
    import atexit
except ImportError:
    pass

#==============================================================================

# FIXME
# * fix the control-c handling, currently it crashes the python interpreter

class ConsoleInput (object):

    history_file = '.pdebug'

    register_names = (
        'eax', 'ebx', 'ecx', 'edx',
        'esi', 'edi', 'ebp', 'esp',
        'eip',
    )
    segment_names         = ( 'cs', 'ds', 'es', 'fs', 'gs' )
    register_alias_16     = { 'ax':'Eax', 'bx':'Ebx', 'cx':'Ecx', 'dx':'Edx' }
    register_alias_8_low  = { 'al':'Eax', 'bl':'Ebx', 'cl':'Ecx', 'dl':'Edx' }
    register_alias_8_high = { 'ah':'Eax', 'bh':'Ebx', 'ch':'Ecx', 'dh':'Edx' }

    jump_instructions = (
        'jmp', 'jecxz', 'jcxz',
        'ja', 'jnbe', 'jae', 'jnb', 'jb', 'jnae', 'jbe', 'jna', 'jc', 'je',
        'jz', 'jnc', 'jne', 'jnz', 'jnp', 'jpo', 'jp', 'jpe', 'jg', 'jnle',
        'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng', 'jno', 'jns', 'jo', 'js'
    )

    call_instructions = ( 'call', 'ret', 'retn' )
    loop_instructions = ( 'loop', 'loopz', 'loopnz', 'loope', 'loopne' )

    control_flow_instructions = call_instructions + loop_instructions + \
                                jump_instructions

#------------------------------------------------------------------------------
# Control-C handling

##    def control_c_break(self, dwCtrlType = win32.CTRL_C_EVENT):
##        if dwCtrlType in (win32.CTRL_C_EVENT, win32.CTRL_BREAK_EVENT):
##            try:
##                print "User requested debug break."
##                for process in self.lastEvent.debug.system:
##                    try:
##                        process.debug_break()
##                    except Exception:
##                        pass
##            except Exception:
##                pass
##            return win32.TRUE
##        return win32.FALSE
##
##    def set_control_c_handler(self):
##        win32.SetConsoleCtrlHandler(self.control_c_break, True)
##
##    def remove_control_c_handler(self):
##        try:
##            win32.SetConsoleCtrlHandler(self.control_c_break, False)
##        except WindowsError:
##            pass

#------------------------------------------------------------------------------
# History file

    def load_history(self):
        folder = os.environ.get('USERPROFILE', '')
        if not folder:
            folder = os.environ.get('HOME', '')
        if not folder:
            folder = os.path.split(sys.argv[0])[1]
        if not folder:
            folder = os.path.curdir
        self.history_file = os.path.join(folder, self.history_file)
        try:
            readline.read_history_file(self.history_file)
        except NameError:
            pass
        except IOError:
            pass
        try:
            atexit.register(self.save_history)
        except NameError:
            pass

    def save_history(self):
        try:
            readline.write_history_file(self.history_file)
        except NameError:
            pass
        except IOError:
            pass

#------------------------------------------------------------------------------
# Input

    def join_tokens(self, token_list):
        return self.lastEvent.debug.system.argv_to_cmdline(token_list)

    def split_tokens(self, arg, min_count = 0, max_count = None):
        token_list = self.lastEvent.debug.system.cmdline_to_argv(arg)
        if len(token_list) < min_count:
            raise CmdError, "missing parameters."
        if max_count and len(token_list) > max_count:
            raise CmdError, "too many parameters."
        return token_list

    def input_thread(self, token):
        targets = self.input_thread_list( [token] )
        if len(targets) == 0:
            raise CmdError, "missing thread name or ID"
        if len(targets) > 1:
            msg = "more than one thread with that name:\n"
            for tid in targets:
                msg += "\t%d\n" % tid
            msg = msg[:-len("\n")]
            raise CmdError, msg
        return targets[0]

    def input_thread_list(self, token_list):
        targets = set()
        system  = self.lastEvent.debug.system
        integer = winappdbg.HexInput.integer
        for token in token_list:
            try:
                tid = integer(token)
                if not system.has_thread(tid):
                    raise CmdError, "thread not found (%d)" % tid
                targets.add(tid)
            except ValueError:
                found = set()
                for process in system.iter_processes():
                    found.update( system.find_threads_by_name(token) )
                if not found:
                    raise CmdError, "thread not found (%s)" % token
                for thread in found:
                    targets.add( thread.get_tid() )
        targets = list(targets)
        targets.sort()
        return targets

    def input_process(self, token):
        targets = self.input_process_list( [token] )
        if len(targets) == 0:
            raise CmdError, "missing process name or ID"
        if len(targets) > 1:
            msg = "more than one process with that name:\n"
            for pid in targets:
                msg += "\t%d\n" % pid
            msg = msg[:-len("\n")]
            raise CmdError, msg
        return targets[0]

    def input_process_list(self, token_list):
        targets = set()
        system  = self.lastEvent.debug.system
        integer = winappdbg.HexInput.integer
        for token in token_list:
            try:
                pid = integer(token)
                if not system.has_process(pid):
                    raise CmdError, "process not found (%d)" % pid
                targets.add(pid)
            except ValueError:
                found = system.find_processes_by_filename(token)
                if not found:
                    raise CmdError, "process not found (%s)" % token
                for (process, _) in found:
                    targets.add( process.get_pid() )
        targets = list(targets)
        targets.sort()
        return targets

##    def input_optional_process_list(self, token_list):
##        targets = self.input_process_list( token_list )
##        if not targets:
##            targets = self.lastEvent.debug.get_debugee_pids()
##            targets.sort()
##        return targets

    def input_command_line(self, command_line):
        argv  = self.lastEvent.debug.system.cmdline_to_argv(command_line)
        fname = argv[0]
        if not os.path.exists(fname):
            try:
                fname, _ = win32.SearchPath(None, fname, '.exe')
            except WindowsError:
                raise CmdError, "file not found: %s" % fname
            argv[0] = fname
            command_line = self.lastEvent.debug.system.argv_to_cmdline(argv)
        return command_line

    def input_address(self, token, pid = None, tid = None):
        address = self.input_register(token, tid)
        if address is None:
            try:
                address = winappdbg.HexInput.integer(token)
            except ValueError:
                try:
                    address = winappdbg.HexInput.integer('0x%s' % token)
                except ValueError:
                    if pid is None or pid == self.lastEvent.get_pid():
                        process = self.lastEvent.get_process()
                    else:
                        try:
                            process = self.lastEvent.debug.system.get_process(pid)
                        except KeyError:
                            raise CmdError, "process not found (%d)" % pid
                    try:
                        address = process.resolve_label(token)
                    except Exception, e:
                        raise CmdError, "unknown address (%s)" % token
        return address

    def input_address_range(self, token, pid = None, tid = None):
        if '-' in token:
            try:
                token_1, token_2 = token.split('-')
            except Exception:
                raise CmdError, "bad address range: %s" % token
            address = self.input_address(token_1, pid, tid)
            size    = self.input_address(token_2, pid, tid) - address
        else:
            address = self.input_address(token, pid, tid)
            size    = None
        return address, size

    def input_any_breakpoint(self, token_list):
        if len(token_list) > 1:
            try:
                pid = self.input_process(token_list[1])
                tid = None
            except CmdError:
                try:
                    tid = self.input_thread(token_list[1])
                    pid = None
                except CmdError:
                    msg = "can't find process or thread (%s)" % token_list[1]
                    raise CmdError, msg
        else:
            pid = self.lastEvent.get_pid()
            tid = self.lastEvent.get_tid()
        address, size = self.input_address_range(token_list[0], pid)
        return pid, tid, address, size

    def input_address_and_process(self, token_list, tid = None):
        if len(token_list) > 1:
            pid = self.input_process(token_list[1])
        else:
            pid = self.lastEvent.get_pid()
        address = self.input_address(token_list[0], pid, tid)
        return pid, address

    def input_address_range_and_process(self, token_list, tid = None):
        if len(token_list) > 1:
            pid = self.input_process(token_list[1])
        else:
            pid = self.lastEvent.get_pid()
        address, size = self.input_address_range(token_list[0], pid, tid)
        return pid, address, size

    def input_register(self, token, tid = None):
        if tid is None:
            thread = self.lastEvent.get_thread()
        else:
            thread = self.lastEvent.debug.system.get_thread(tid)
        ctx = thread.get_context()
        
        token = token.lower()
        
        if token in self.register_names:
            return ctx.get( token.title() )             # eax -> Eax
         
        if token in self.segment_names:
            return ctx.get( 'Seg%s' % token.title() )   # cs -> SegCs
        
        if token in self.register_alias_16.keys():
            return ctx.get( self.register_alias_16[token] ) & 0x0000FFFF
        
        if token in self.register_alias_8_low.keys():
            return ctx.get( self.register_alias_8_low[token] ) & 0x000000FF
        
        if token in self.register_alias_8_high.keys():
            return \
               (ctx.get( self.register_alias_8_high[token] ) & 0x0000FF00) >> 8
        
        return None

#==============================================================================

class ConsoleOutput (object):

#------------------------------------------------------------------------------
# Output

    def print_banner(self):
        print "WinAppDbg console debugger"
        print "by Mario Vilas (mvilas at gmail.com)"
        print

    def print_module_load(self, event):
        mod  = event.get_module()
        base = mod.get_base()
        name = mod.get_filename()
        if not name:
            name = ''
        print "Loaded module (%.08x) %s" % (base, name)

    def print_module_unload(self, event):
        mod  = event.get_module()
        base = mod.get_base()
        name = mod.get_filename()
        if not name:
            name = ''
        print "Unloaded module (%.08x) %s" % (base, name)

    def print_process_start(self, event):
        pid   = event.get_pid()
        start = event.get_start_address()
        start = event.get_process().get_label_at_address(start)
        print "Started process %d at %s" % (pid, start)

    def print_thread_start(self, event):
        tid   = event.get_tid()
        start = event.get_start_address()
        start = event.get_process().get_label_at_address(start)
        print "Started thread %d at %s" % (tid, start)

    def print_process_end(self, event):
        pid  = event.get_pid()
        code = event.get_exit_code()
        print "Process %d terminated, exit code %d" % (pid, code)

    def print_thread_end(self, event):
        tid  = event.get_tid()
        code = event.get_exit_code()
        print "Thread %d terminated, exit code %d" % (tid, code)

    def print_debug_string(self, event):
        tid    = event.get_tid()
        string = event.get_debug_string()
        print "Thread %d says: %r" % (tid, string)

    def print_event(self, event):
        code = winappdbg.HexDump.address( event.get_event_code() )
        name = event.get_event_name()
        desc = event.get_event_description()
        if code in desc:
            print
            print "%s: %s" % (name, desc)
        else:
            print
            print "%s (%s): %s" % (name, code, desc)
        self.print_location(event)

    def print_exception(self, event):
        address = winappdbg.HexDump.address( event.get_exception_address() )
        code    = winappdbg.HexDump.address( event.get_exception_code() )
        desc    = event.get_exception_description()
        if event.is_first_chance():
            chance = 'first'
        else:
            chance = 'second'
        if code in desc:
            msg = "%s at address %s (%s chance)" % (desc, address, chance)
        else:
            msg = "%s (%s) at address %s (%s chance)" % (desc, code, address, chance)
        print
        print msg
        self.print_location(event)

    def print_location(self, event):
        process = event.get_process()
        thread  = event.get_thread()
        pc      = thread.get_pc()
        ctx     = thread.get_context()
        label   = process.get_label_at_address(pc)
        disasm  = process.disassemble(pc, 15)
        print winappdbg.CrashDump.dump_registers(ctx),
        print "%s:" % label
        print winappdbg.CrashDump.dump_code_line(disasm[0], pc)

#==============================================================================

class CmdError (Exception):
    pass

class ConsoleCommands (Cmd):

#------------------------------------------------------------------------------
# Command prompt input

    def prompt_user(self):
        while not self.debuggerExit:
            try:
                self.cmdloop()
                break
            except CmdError, e:
                print "Error: %s" % str(e)
            except Exception, e:
                traceback.print_exc(e)
##                self.debuggerExit = True

    def ask_user(self, msg, prompt = "Are you sure? (y/N): "):
        print msg
        answer = raw_input(prompt)
        answer = answer.strip()[:1].lower()
        return answer == 'y'

    def autocomplete(self, cmd):
        completed = self.completenames(cmd)
        if len(completed) == 1:
            cmd = completed[0]
        return cmd

#------------------------------------------------------------------------------
# Overrides to Cmd methods

    def get_names(self):
        names = Cmd.get_names(self)
        names = list(set(names))
        names.sort()
        return names

    def parseline(self, line):
        cmd, arg, line = Cmd.parseline(self, line)
        if cmd:
            cmd = self.autocomplete(cmd)
        return cmd, arg, line

##    def emptyline(self):
##        pass

#------------------------------------------------------------------------------
# Hooked Cmd methods

    def preloop(self):
        self.last_disasm_target  = 'eip'
        self.last_display_target = 'eip'

    def postcmd(self, stop, line):
        return stop or self.debuggerExit

#------------------------------------------------------------------------------
# Commands

    def do_help(self, arg):
        """
        Help! I need somebody...
        Help! Not just anybody...
        Help! You know, I need someone...
        Heeelp!
        """
        if arg:
            arg = self.autocomplete(arg)
        return Cmd.do_help(self, arg)

##    def do_shell(self, arg):
##        """
##        shell <command> - execute the given shell command
##        """
##        win32.ShellExecute(arg)

    def do_quit(self, arg):
        """
        quit - detach from all processes and quit
        """
        if arg:
            raise CmdError, "too many arguments"
        self.debuggerExit = True
        return True

    def do_attach(self, arg):
        """
        attach <target> [target...] - attach to the given process(es)
        """
        targets = self.input_process_list( self.split_tokens(arg) )
        if not targets:
            print "Error: missing parameters"
        else:
            debug = self.lastEvent.debug
            for pid in targets:
                try:
                    debug.attach(pid)
                    print "Attached to process (%d)" % pid
                except Exception, e:
                    print "Error: can't attach to process (%d)" % pid

    def do_detach(self, arg):
        """
        detach - detach from the current process
        detach <target> [target...] - detach from the given process(es)
        """
        debug   = self.lastEvent.debug
        targets = self.input_process_list( self.split_tokens(arg) )
        if not targets:
            targets = [ self.lastEvent.get_pid() ]
        for pid in targets:
            try:
                debug.detach(pid)
                print "Detached from process (%d)" % pid
            except Exception, e:
                print "Error: can't detach from process (%d)" % pid

    def do_start(self, arg):
        """
        start <target> [arguments...] - run a program for debugging 
        """
        cmdline = self.input_command_line(arg)
        try:
            process = self.lastEvent.debug.execl(arg,
                                                bConsole = False,
                                                 bFollow = self.options.follow)
            print "Spawned process (%d)" % process.get_pid()
        except Exception, e:
            raise CmdError, "can't execute"

    def do_startc(self, arg):
        """
        startc <target> [arguments...] - run a console program for debugging 
        """
        cmdline = self.input_command_line(arg)
        try:
            process = self.lastEvent.debug.execl(arg,
                                                bConsole = True,
                                                 bFollow = self.options.follow)
            print "Spawned process (%d)" % process.get_pid()
        except Exception, e:
            raise CmdError, "can't execute"

    def do_continue(self, arg):
        """
        continue - continue execution of the debugees
        """
        if arg:
            raise CmdError, "too many arguments"
        self.prompt = '> '
        if self.lastEvent.debug.get_debugee_count() > 0:
            return True

    do_go = do_continue

    def do_refresh(self, arg):
        """
        refresh - refresh the list of running processes and threads
        """
        if arg:
            raise CmdError, "too many arguments"
        self.lastEvent.debug.system.scan()

    def do_processlist(self, arg):
        """
        pl - show the processes being debugged
        processlist - show the processes being debugged
        """
        if arg:
            raise CmdError, "too many arguments"
        system = self.lastEvent.debug.system
        for pid in self.lastEvent.debug.get_debugees_pids():
            if   pid == 0:
                filename = "System Idle Process"
            elif pid == 4:
                filename = "System"
            else:
                filename = system.get_filename()
                filename = winappdbg.FileHandle.pathname_to_filename(filename)
            print "%-12d: %s" % (pid, filename)

    do_pl = do_processlist

    def do_threadlist(self, arg):
        """
        tl - show the threads being debugged
        threadlist - show the threads being debugged
        """
        if arg:
            raise CmdError, "too many arguments"
        system = self.lastEvent.debug.system
        for pid in self.lastEvent.debug.get_debugees_pids():
            process = system.get_process(pid)
            for thread in process.iter_threads():
                tid  = thread.get_tid()
                name = thread.get_name()
                print "%-12d %s" % (tid, name)

    do_tl = do_threadlist

    def do_kill(self, arg):
        """
        kp - kill the current process
        kill - kill the current process
        """
        if arg:
            raise CmdError, "too many arguments"
        if self.ask_user("You are about to kill the current process."):
            process = self.lastEvent.get_process()
            try:
                process.kill()
                print "Killed process (%d)" % self.lastEvent.get_pid()
            except Exception, e:
                print "Couldn't kill process (%d)" % self.lastEvent.get_pid()

    def do_killthread(self, arg):
        """
        kt - kill the current thread
        killthread - kill the current thread
        """
        if arg:
            raise CmdError, "too many arguments"
        if self.ask_user("You are about to kill the current thread."):
            thread = self.lastEvent.get_thread()
            try:
                thread.kill()
                print "Killed thread (%d)" % self.lastEvent.get_tid()
            except Exception, e:
                print "Couldn't kill thread (%d)" % self.lastEvent.get_tid()

    do_kt = do_killthread

    def do_break(self, arg):
        """
        break - force a debug break in all debugees
        break <process> [process...] - force a debug break
        """
        debug   = self.lastEvent.debug
        system  = debug.system
        targets = self.input_process_list( self.split_tokens(arg) )
        if not targets:
            targets = debug.get_debugee_pids()
            targets.sort()
        current = self.lastEvent.get_pid()
        for pid in targets:
            if pid != current and debug.is_debugee(pid):
                process = system.get_process(pid)
                try:
                    process.debug_break()
                except WindowsError, e:
                    print "Can't force a debug break on process (%d)"

    def do_step(self, arg):
        """
        p - step on the current assembly instruction
        next - step on the current assembly instruction
        step - step on the current assembly instruction
        """
        if arg:     # XXX this check is to be removed
            raise CmdError, "too many arguments"
        pid     = self.lastEvent.get_pid()
        thread  = self.lastEvent.get_thread()
        pc      = thread.get_pc()
        code    = thread.disassemble(pc, 16)[0]
        size    = code[1]
        opcode  = code[2].lower()
        if ' ' in opcode:
            opcode  = opcode[ : opcode.find(' ') ]
        if opcode in self.jump_instructions or opcode in ('int', 'ret', 'retn'):
            return self.do_trace(arg)
        address = pc + size
        print hex(pc), hex(address), size
        self.lastEvent.debug.stalk_at(pid, address)
        return True

    do_p = do_step
    do_next = do_step

    def do_trace(self, arg):
        """
        t - trace at the current assembly instruction
        trace - trace at the current assembly instruction
        """
        if arg:     # XXX this check is to be removed
            raise CmdError, "too many arguments"
        thread = self.lastEvent.get_thread().set_tf()
        return True

    do_t = do_trace

    def do_bp(self, arg):
        """
        bp <address> [process] - set a code breakpoint
        """
        token_list = self.split_tokens(arg, 1, 2)
        pid, address = self.input_address_and_process(token_list)
        self.lastEvent.debug.break_at(pid, address)

    def do_ba(self, arg):
        """
        ba <a|w|e> <1|2|4|8> <address> [thread] - set hardware breakpoint
        """
        debug = self.lastEvent.debug
        token_list = self.split_tokens(arg, 3, 4)
        access  = token_list[0].lower()
        size    = token_list[1]
        address = token_list[2]
        if   access == 'a':
            access = debug.BP_BREAK_ON_ACCESS
        elif access == 'w':
            access = debug.BP_BREAK_ON_WRITE
        elif access == 'e':
            access = debug.BP_BREAK_ON_EXECUTION
        else:
            raise CmdError, "bad access type: %s" % token_list[0]
        if   size == '1':
            size = debug.BP_WATCH_BYTE
        elif size == '2':
            size = debug.BP_WATCH_WORD
        elif size == '4':
            size = debug.BP_WATCH_DWORD
        elif size == '8':
            size = debug.BP_WATCH_QWORD
        else:
            raise CmdError, "bad breakpoint size: %s" % size
        if len(token_list) > 4:
            tid = self.input_thread(token_list[4])
            pid = debug.system.get_thread(tid).get_pid()
        else:
            pid = self.lastEvent.get_pid()
            tid = self.lastEvent.get_tid()
        address = self.input_address(address, pid)
        if debug.has_hardware_breakpoint(tid, address):
            debug.erase_hardware_breakpoint(tid, address)
        debug.define_hardware_breakpoint(tid, address, access, size)
        debug.enable_hardware_breakpoint(tid, address)

    def do_bm(self, arg):
        """
        bm <address-address> [process] - set memory breakpoint
        """
        token_list = self.split_tokens(arg, 1, 2)
        if len(token_list) > 1:
            pid = self.input_process(token_list[1])
        else:
            pid = self.lastEvent.get_pid()
        address, size = self.input_address_range(token_list[0], pid)
        self.lastEvent.debug.watch_buffer(pid, address, size)

    def do_bl(self, arg):
        """
        bl - list the breakpoints for the current process
        bl * - list the breakpoints for all processes
        bl <process> [process...] - list the breakpoints for each given process
        """
        debug = self.lastEvent.debug
        if arg == '*':
            breakpoints = debug.get_debugees_pids()
        else:
            targets = self.input_process_list( self.split_tokens(arg) )
            if not targets:
                targets = [ self.lastEvent.get_pid() ]
        for pid in targets:
            bplist = debug.get_process_code_breakpoints(pid)
            if bplist:
                print "Process %d:" % pid
                for bp in bplist:
                    print "  %s" % repr(bp)[1:-1].replace('remote address ','')
            bplist = debug.get_process_page_breakpoints(pid)
            if bplist:
                print "Process %d:" % pid
                for bp in bplist:
                    print "  %s" % repr(bp)[1:-1].replace('remote address ','')
            for tid in debug.system.get_process(pid).iter_thread_ids():
                bplist = debug.get_thread_hardware_breakpoints(tid)
                if bplist:
                    print "Thread %d:" % tid
                    for bp in bplist:
                        print "  %s" % repr(bp)[1:-1].replace('remote address ','')

    def do_bo(self, arg):
        """
        bo <address> [process] - make a code breakpoint one-shot
        bo <address> [thread] - make a hardware breakpoint one-shot
        bo <address-address> [process] - make a memory breakpoint one-shot
        """
        debug = self.lastEvent.debug
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_any_breakpoint(token_list)
        found = False
        if size is None:
            if tid is not None:
                if debug.has_hardware_breakpoint(tid, address):
                    debug.enable_one_shot_hardware_breakpoint(tid, address)
                    found = True
            if pid is not None:
                if debug.has_code_breakpoint(pid, address):
                    debug.enable_one_shot_code_breakpoint(pid, address)
                    found = True
        else:
            if debug.has_page_breakpoint(pid, address):
                debug.enable_one_shot_page_breakpoint(pid, address)
                found = True
        if not found:
            print "Error: breakpoint not found."

    def do_be(self, arg):
        """
        be <address> [process] - enable a code breakpoint
        be <address> [thread] - enable a hardware breakpoint
        be <address-address> [process] - enable a memory breakpoint
        """
        debug = self.lastEvent.debug
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_any_breakpoint(token_list)
        found = False
        if size is None:
            if tid is not None:
                if debug.has_hardware_breakpoint(tid, address):
                    debug.enable_hardware_breakpoint(tid, address)
                    found = True
            if pid is not None:
                if debug.has_code_breakpoint(pid, address):
                    debug.enable_code_breakpoint(pid, address)
                    found = True
        else:
            if debug.has_page_breakpoint(pid, address):
                debug.enable_page_breakpoint(pid, address)
                found = True
        if not found:
            print "Error: breakpoint not found."

    def do_bd(self, arg):
        """
        bd <address> [process] - disable a code breakpoint
        bd <address> [thread] - disable a hardware breakpoint
        bd <address-address> [process] - disable a memory breakpoint
        """
        debug = self.lastEvent.debug
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_any_breakpoint(token_list)
        found = False
        if size is None:
            if tid is not None:
                if debug.has_hardware_breakpoint(tid, address):
                    debug.disable_hardware_breakpoint(tid, address)
                    found = True
            if pid is not None:
                if debug.has_code_breakpoint(pid, address):
                    debug.disable_code_breakpoint(pid, address)
                    found = True
        else:
            if debug.has_page_breakpoint(pid, address):
                debug.disable_page_breakpoint(pid, address)
                found = True
        if not found:
            print "Error: breakpoint not found."

    def do_bc(self, arg):
        """
        bd <address> [process] - clear a code breakpoint
        bd <address> [thread] - clear a hardware breakpoint
        bd <address-address> [process] - clear a memory breakpoint
        """
        debug = self.lastEvent.debug
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_any_breakpoint(token_list)
        found = False
        if size is None:
            if tid is not None:
                if debug.has_hardware_breakpoint(tid, address):
                    debug.dont_watch_variable(tid, address)
                    found = True
            if pid is not None:
                if debug.has_code_breakpoint(pid, address):
                    debug.dont_break_at(pid, address)
                    found = True
        else:
            if debug.has_page_breakpoint(pid, address):
                debug.dont_watch_buffer(pid, address, size)
                found = True
        if not found:
            print "Error: breakpoint not found."

    def do_disassemble(self, arg):
        """
        u <address> [process] - show code disassembly
        disassembly <address> [process] - show code disassembly
        """
        if arg:
            self.last_disasm_target = arg
        else:
            arg = self.last_disasm_target
        token_list   = self.split_tokens(arg, 1, 2)
        pid, address = self.input_address_and_process(token_list)
        process      = self.lastEvent.debug.system.get_process(pid)
        try:
            code = process.disassemble(address, 15*8)[:8]
        except Exception, e:
            msg = "can't disassemble address %s"
            msg = msg % winappdbg.HexDump.address(address)
            raise CmdError, msg
        for line in code:
            print winappdbg.CrashDump.dump_code_line(line)

    do_u = do_disassemble

    def do_db(self, arg):
        """
        db <address> [process] - show memory contents as bytes
        db <address-address> [process] - show memory contents as bytes
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 64
        data = process.peek(address, size)
        if data:
            print winappdbg.HexDump.hexblock(data, address),

    do_display = do_db

    def do_dw(self, arg):
        """
        dw <address> [process] - show memory contents as words
        dw <address-address> [process] - show memory contents as words
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 64
        data = process.peek(address, size)
        if data:
            print winappdbg.HexDump.hexblock_word(data, address),

    def do_dd(self, arg):
        """
        dd <address> [process] - show memory contents as dwords
        dd <address-address> [process] - show memory contents as dwords
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 64
        data = process.peek(address, size)
        if data:
            print winappdbg.HexDump.hexblock_dword(data, address),

    def do_dq(self, arg):
        """
        dq <address> [process] - show memory contents as qwords
        dq <address-address> [process] - show memory contents as qwords
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 64
        data = process.peek(address, size)
        if data:
            print winappdbg.HexDump.hexblock_qword(data, address),

    def do_ds(self, arg):
        """
        ds <address> [process] - show memory contents as ANSI
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 128
        data = process.peek_string(address, False, size)
        if data:
            print repr(data)

    def do_du(self, arg):
        """
        du <address> [process] - show memory contents as Unicode
        """
        if arg:
            self.last_display_target = arg
        else:
            arg = self.last_display_target
        token_list         = self.split_tokens(arg, 1, 2)
        pid, address, size = self.input_address_range_and_process(token_list)
        process            = self.lastEvent.debug.system.get_process(pid)
        if not size:
            size = 256
        data = process.peek_string(address, True, size)
        if data:
            print repr(data)

#==============================================================================

class ConsoleDebuggerEventHandler (winappdbg.EventHandler):

#------------------------------------------------------------------------------
# Event handling

    def event(self, event):
        self.print_event(event)
        self.prompt_user()

    def exception(self, event):
        self.print_exception(event)
        self.prompt_user()

    def breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        self.print_location(event)
        self.prompt_user()

    def single_step(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        self.print_location(event)
        self.prompt_user()

    def create_process(self, event):
        self.print_process_start(event)
        self.print_thread_start(event)
        self.print_module_load(event)

    def exit_process(self, event):
        self.print_process_end(event)

    def create_thread(self, event):
        self.print_thread_start(event)

    def exit_thread(self, event):
        self.print_thread_end(event)

    def load_dll(self, event):
        self.print_module_load(event)

    def unload_dll(self, event):
        self.print_module_unload(event)

    def output_string(self, event):
        self.print_debug_string(event)

#==============================================================================

# TODO
# * add an option to show python tracebacks of all errors, disabled by default

class ConsoleDebuggerStartup (object):

#------------------------------------------------------------------------------
# Command line parsing

    def parse_cmdline(self):

        # Define the command line parser
        usage = (
                "\n"
                "\n"
                "  Just show the prompt:\n"
                "    %prog\n"
                "\n"
                "  Create a new process:\n"
                "    %prog [options] -c \"console_target.exe optional parameters...\"\n"
                "    %prog [options] -w \"windowed_target.exe optional parameters...\"\n"
                "\n"
                "  Attach to a running process (by filename):\n"
                "    %prog [options] -a \"executable\"\n"
                "\n"
                "  Attach to a running process (by ID):\n"
                "    %prog [options] -a pid"
                )
        self.parser = optparse.OptionParser(
                                        usage=usage,
                                        version=winappdbg.version,
                                      )
        commands = optparse.OptionGroup(self.parser, "Commands")
        commands.add_option("-a", "--attach", action="append", metavar="PROCESS",
                            help="attach to a running process")
        commands.add_option("-w", "--windowed", action="append", metavar="CMDLINE",
                            help="create a new windowed process for debugging")
        commands.add_option("-c", "--console", action="append", metavar="CMDLINE",
                            help="create a new console process for debugging")
        self.parser.add_option_group(commands)
        debugging = optparse.OptionGroup(self.parser, "Debugging options")
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
        self.parser.add_option_group(debugging)

        # Set the default values
        self.parser.set_defaults(
            attach      = [],
            console     = [],
            windowed    = [],
            follow      = True,
            autodetach  = True,
        )

        # Parse the command line
        (self.options, args) = self.parser.parse_args(self.argv)
        if len(args) > 1:
            self.parser.error("don't know what to do with: %r" % args[1])

#------------------------------------------------------------------------------
# Debugger create and destroy

    def create_debugger(self):

        # Instance a debugger
        debug = winappdbg.Debug(self, bKillOnExit = not self.options.autodetach)

        # Populate the snapshot of processes
        debug.system.scan()

        # Instance a dummy event, just to contain the debugger object.
        self.lastEvent = winappdbg.NoEvent(debug)

        # Queue the attach command
        if self.options.attach:
            cmd = 'attach %s' % self.join_tokens(self.options.attach)
            self.cmdqueue.append(cmd)

        # Queue the start commands
        for cmdline in self.options.windowed:
            self.cmdqueue.append( 'start %s' % cmdline )

        # Queue the startc commands
        for cmdline in self.options.console:
            self.cmdqueue.append( 'startc %s' % cmdline )

        # Queue the go command
        if len(self.cmdqueue) > 0:
            self.cmdqueue.append('go')

    # Circular references must be removed, or the destructors never get called.
    def destroy_debugger(self):
        if hasattr(self, 'lastEvent'):
            event = self.lastEvent
            del self.lastEvent
            debug = event.debug
            try:
                debug.stop(event)
            finally:
                debug.system.clear()

#==============================================================================

class ConsoleDebugger (
        ConsoleDebuggerStartup,
        ConsoleDebuggerEventHandler,
        ConsoleInput,
        ConsoleOutput,
        ConsoleCommands,
        ):

    dwMilliseconds = 1000

    def __init__(self):
        ConsoleDebuggerStartup.__init__(self)
        ConsoleDebuggerEventHandler.__init__(self)
        ConsoleInput.__init__(self)
        ConsoleOutput.__init__(self)
        ConsoleCommands.__init__(self)

#------------------------------------------------------------------------------
# Main loop

    def initialize(self):
        self.print_banner()
        self.parse_cmdline()
        self.create_debugger()
        self.load_history()
##        self.set_control_c_handler()

    def finalize(self):
##        self.remove_control_c_handler()
        self.destroy_debugger()

    def run(self, argv):
        self.argv = [x for x in argv]
        try:
            self.initialize()
            try:
                self.main_loop()
            except KeyboardInterrupt:
##                self.control_c_break()
                pass
        finally:
            self.finalize()

    def main_loop(self):
        self.prompt = '> '
        self.debuggerExit = False
        debug = self.lastEvent.debug
        
        if debug.get_debugee_count() == 0:
            self.prompt_user()

        while not self.debuggerExit:

            if self.lastEvent:
                debug.cont(self.lastEvent)
                lastCode = self.lastEvent.get_event_code()
                self.lastEvent = winappdbg.NoEvent(debug)

            self.prompt = '> '
            while not self.debuggerExit and \
                self.lastEvent.debug.get_debugee_count() <= 0:
                    self.prompt_user()
            if self.debuggerExit:
                break

            while 1:
                try:
                    self.lastEvent = debug.wait(self.dwMilliseconds)
                except WindowsError, e:
                    if e.winerror == win32.ERROR_SEM_TIMEOUT:
                        continue
                    raise
                break

            pid = self.lastEvent.get_pid()
            tid = self.lastEvent.get_tid()
            self.prompt = '%d:%d> ' % (pid, tid)

            try:
                handled = self.lastEvent.debug.dispatch(self.lastEvent)
                if handled:
                    break
            except Exception:
                traceback.print_exc()
                self.prompt_user()

#==============================================================================

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    ConsoleDebugger().run(sys.argv)
