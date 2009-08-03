#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his command line debugger on which this is inspired.

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
import time
import optparse
import traceback

from cmd import Cmd

import winappdbg
from winappdbg import EventHandler, win32

try:
    import readline
    import atexit
except ImportError:
    pass

#==============================================================================

# Exception to be raised when a command parsing error occurs.
class CmdError (Exception):
    pass

#==============================================================================

class ConsoleDebugger (Cmd, EventHandler):

#------------------------------------------------------------------------------
# Class variables

    # Exception to raise when an error occurs executing a command.
    command_error_exception = CmdError

    # Milliseconds to wait for debug events in the main loop.
    dwMilliseconds = 100

    # History file name.
    history_file = '.pdebug'

    # Valid plugin name characters.
    valid_plugin_name_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXY' \
                              'abcdefghijklmnopqrstuvwxy' \
                              '012345678'                 \
                              '_'

    # Names of the registers.
    register_names = (
        'eax', 'ebx', 'ecx', 'edx',
        'esi', 'edi', 'ebp', 'esp',
        'eip',
    )
    segment_names         = ( 'cs', 'ds', 'es', 'fs', 'gs' )
    register_alias_16     = { 'ax':'Eax', 'bx':'Ebx', 'cx':'Ecx', 'dx':'Edx' }
    register_alias_8_low  = { 'al':'Eax', 'bl':'Ebx', 'cl':'Ecx', 'dl':'Edx' }
    register_alias_8_high = { 'ah':'Eax', 'bh':'Ebx', 'ch':'Ecx', 'dh':'Edx' }

    register_names_full = list(register_names)
    register_names_full.extend(segment_names)
    register_names_full.extend(register_alias_16.iterkeys())
    register_names_full.extend(register_alias_8_low.iterkeys())
    register_names_full.extend(register_alias_8_high.iterkeys())
    register_names_full = tuple(register_names_full)

    # Names of the control flow instructions.
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
# Instance variables

    def __init__(self):
        Cmd.__init__(self)
        EventHandler.__init__(self)

        self.debuggerExit = False       # Quit the debugger when True

#------------------------------------------------------------------------------
# History file

    def load_history(self):
        try:
            readline
        except NameError:
            return
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
        except IOError:
            pass
        atexit.register(self.save_history)

    def save_history(self):
        try:
            readline
        except NameError:
            return
        try:
            readline.write_history_file(self.history_file)
        except IOError:
            pass

#------------------------------------------------------------------------------
# Input

# TODO
# * try to guess breakpoints when insufficient data is given
# * child Cmd instances will have to be used for other prompts, for example
#   when assembling or editing memory - it may also be a good idea to think
#   if it's possible to make the main Cmd instance also a child, instead of
#   the debugger itself - probably the same goes for the EventHandler, maybe
#   it can be used as an object rather than a parent class.

    # Join a token list into an argument string.
    def join_tokens(self, token_list):
        return self.lastEvent.debug.system.argv_to_cmdline(token_list)

    # Split an argument string into a token list.
    def split_tokens(self, arg, min_count = 0, max_count = None):
        token_list = self.lastEvent.debug.system.cmdline_to_argv(arg)
        if len(token_list) < min_count:
            raise CmdError, "missing parameters."
        if max_count and len(token_list) > max_count:
            raise CmdError, "too many parameters."
        return token_list

    # Token is a thread ID or name.
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

    # Token list is a list of thread IDs or names.
    def input_thread_list(self, token_list):
        targets = set()
        system  = self.lastEvent.debug.system
        for token in token_list:
            try:
                tid = self.input_integer(token)
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

    # Token is a process ID or name.
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

    # Token list is a list of process IDs or names.
    def input_process_list(self, token_list):
        targets = set()
        system  = self.lastEvent.debug.system
        for token in token_list:
            try:
                pid = self.input_integer(token)
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

    # Token is a command line to execute.
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

    # Token is an integer.
    # Only hexadecimal format is supported.
    def input_hexadecimal_integer(self, token):
        return int(token, 0x10)

    # Token is an integer.
    # It can be in any supported format.
    def input_integer(self, token):
        return winappdbg.HexInput.integer(token)
##    input_integer = input_hexadecimal_integer

    # Token is an address.
    # The address can be a integer, a label or a register.
    def input_address(self, token, pid = None, tid = None):
        address = None
        if token in self.register_names_full:
            if tid is None:
                if pid != self.lastEvent.get_pid():
                    msg = "can't resolve register (%s) for unknown thread"
                    raise CmdError, msg % token
                tid = self.lastEvent.get_tid()
            address = self.input_register(token, tid)
        if address is None:
            try:
                address = self.input_hexadecimal_integer(token)
            except ValueError:
                if pid is None or pid == self.lastEvent.get_pid():
                    if not self.lastEvent:
                        raise CmdError, "no current process set"
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

    # Token is an address range, or a single address.
    # The addresses can be integers, labels or registers.
    def input_address_range(self, token_list, pid = None, tid = None):
        if len(token_list) == 2:
            token_1, token_2 = token_list
            address = self.input_address(token_1, pid, tid)
            try:
                size = self.input_integer(token_2)
            except ValueError:
                raise CmdError, "bad address range: %s %s" % (token_1, token_2)
        elif len(token_list) == 1:
            token = token_list[0]
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

    # The token is a register name.
    # Returns None if no register name is matched.
    def input_register(self, token, tid = None):
        if tid is None:
            if not self.lastEvent:
                raise CmdError, "no current process set"
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

    # Token list contains an address or address range.
    # The prefix is also parsed looking for process and thread IDs.
    def input_full_address_range(self, token_list):
        pid, tid      = self.get_process_and_thread_ids_from_prefix()
        address, size = self.input_address_range(token_list, pid, tid)
        return pid, tid, address, size

    # Token list contains a breakpoint.
    def input_breakpoint(self, token_list):
        pid, tid, address, size = self.input_full_address_range(token_list)
        if not self.lastEvent.debug.is_debugee(pid):
            raise CmdError, "target process is not being debugged"
        return pid, tid, address, size

    # Token list contains a memory address, and optional size and process.
    # Sets the results as the default for the next display command.
    def input_display(self, token_list, default_size = 64):
        pid, tid, address, size = self.input_full_address_range(token_list)
        if not size:
            size = default_size
        next_address = winappdbg.HexOutput.integer(address + size)
        self.default_display_target = next_address
        return pid, tid, address, size

#------------------------------------------------------------------------------
# Output

    # Print the welcome banner.
    def print_banner(self):
        print "WinAppDbg console debugger"
        print "by Mario Vilas (mvilas at gmail.com)"
        print

    # Tell the user a module was loaded.
    def print_module_load(self, event):
        mod  = event.get_module()
        base = mod.get_base()
        name = mod.get_filename()
        if not name:
            name = ''
        msg = "Loaded module (%s) %s"
        msg = msg % (winappdbg.HexDump.address(base), name)
        print msg

    # Tell the user a module was unloaded.
    def print_module_unload(self, event):
        mod  = event.get_module()
        base = mod.get_base()
        name = mod.get_filename()
        if not name:
            name = ''
        msg = "Unloaded module (%s) %s"
        msg = msg % (winappdbg.HexDump.address(base), name)
        print msg

    # Tell the user a process was started.
    def print_process_start(self, event):
        pid   = event.get_pid()
        start = event.get_start_address()
        if start:
            start = winappdbg.HexOutput.address(start)
            print "Started process %d at %s" % (pid, start)
        else:
            print "Attached to process %d" % pid

    # Tell the user a thread was started.
    def print_thread_start(self, event):
        tid   = event.get_tid()
        start = event.get_start_address()
        if start:
            start = event.get_process().get_label_at_address(start)
            print "Started thread %d at %s" % (tid, start)
        else:
            print "Attached to thread %d" % tid

    # Tell the user a process has finished.
    def print_process_end(self, event):
        pid  = event.get_pid()
        code = event.get_exit_code()
        print "Process %d terminated, exit code %d" % (pid, code)

    # Tell the user a thread has finished.
    def print_thread_end(self, event):
        tid  = event.get_tid()
        code = event.get_exit_code()
        print "Thread %d terminated, exit code %d" % (tid, code)

    # Print debug strings.
    def print_debug_string(self, event):
        tid    = event.get_tid()
        string = event.get_debug_string()
        print "Thread %d says: %r" % (tid, string)

    # Inform the user of any other debugging event.
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
        self.print_event_location(event)

    # Stop on exceptions and prompt for commands.
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
        self.print_event_location(event)

    # Show the current location in the code.
    def print_event_location(self, event):
        process = event.get_process()
        thread  = event.get_thread()
        self.print_current_location(process, thread)

    # Show the current location in any process and thread.
    def print_current_location(self, process = None, thread = None):
        if not process:
            if not self.lastEvent:
                raise CmdError, "no current process set"
            process = self.lastEvent.get_process()
        if not thread:
            if not self.lastEvent:
                raise CmdError, "no current process set"
            thread  = self.lastEvent.get_thread()
        thread.suspend()
        try:
            pc  = thread.get_pc()
            ctx = thread.get_context()
        finally:
            thread.resume()
        label = process.get_label_at_address(pc)
        try:
            disasm = process.disassemble(pc, 15)
        except NotImplementedError:
            disasm = None
        print
        print winappdbg.CrashDump.dump_registers(ctx),
        print "%s:" % label
        if disasm:
            print winappdbg.CrashDump.dump_code_line(disasm[0], pc, bShowDump = False)

    # Display memory contents using a given method.
    def print_memory_display(self, arg, method):
        if not arg:
            arg = self.default_display_target
        token_list              = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_display(token_list)
        label                   = self.get_process(pid).get_label_at_address(address)
        data                    = self.read_memory(address, size, pid)
        if data:
            print "%s:" % label
            print method(data, address),

#------------------------------------------------------------------------------
# Debugging

    # Get the process ID from the prefix or the last event.
    def get_process_id_from_prefix(self):
        if self.cmdprefix:
            pid = self.input_process(self.cmdprefix)
        else:
            if not self.lastEvent:
                raise CmdError, "no current process set"
            pid = self.lastEvent.get_pid()
        return pid

    # Get the thread ID from the prefix or the last event.
    def get_thread_id_from_prefix(self):
        if self.cmdprefix:
            tid = self.input_thread(self.cmdprefix)
        else:
            if not self.lastEvent:
                raise CmdError, "no current process set"
            tid = self.lastEvent.get_tid()
        return tid

    # Get the process from the prefix or the last event.
    def get_process_from_prefix(self):
        pid = self.get_process_id_from_prefix()
        return self.get_process(pid)

    # Get the thread from the prefix or the last event.
    def get_thread_from_prefix(self):
        tid = self.get_thread_id_from_prefix()
        return self.get_thread(tid)

    # Get the process and thread IDs from the prefix or the last event.
    def get_process_and_thread_ids_from_prefix(self):
        if self.cmdprefix:
            try:
                pid = self.input_process(self.cmdprefix)
                tid = None
            except CmdError:
                try:
                    tid = self.input_thread(self.cmdprefix)
                    pid = self.lastEvent.debug.system.get_thread(tid).get_pid()
                except CmdError:
                    msg = "unknown process or thread (%s)" % self.cmdprefix
                    raise CmdError, msg
        else:
            if not self.lastEvent:
                raise CmdError, "no current process set"
            pid = self.lastEvent.get_pid()
            tid = self.lastEvent.get_tid()
        return pid, tid

    # Get the process and thread from the prefix or the last event.
    def get_process_and_thread_from_prefix(self):
        pid, tid = self.get_process_and_thread_ids_from_prefix()
        process  = self.get_process(pid)
        thread   = self.get_thread(tid)
        return process, thread

    # Get the process object.
    def get_process(self, pid = None):
        if pid is None or pid == self.lastEvent.get_pid():
            if self.lastEvent.debug.get_debugee_count() <= 0:
                raise CmdError, "no current process set"
            process = self.lastEvent.get_process()
        else:
            try:
                process = self.lastEvent.debug.system.get_process(pid)
            except KeyError:
                raise CmdError, "process not found (%d)" % pid
        return process

    # Get the thread object.
    def get_thread(self, tid = None):
        if tid is None or tid == self.lastEvent.get_tid():
            if self.lastEvent.debug.get_debugee_count() <= 0:
                raise CmdError, "no current process set"
            thread = self.lastEvent.get_thread()
        else:
            try:
                thread = self.lastEvent.debug.system.get_thread(tid)
            except KeyError:
                raise CmdError, "thread not found (%d)" % pid
        return thread

    # Read the process memory.
    def read_memory(self, address, size, pid = None):
        process = self.get_process(pid)
        try:
            data = process.peek(address, size)
        except WindowsError, e:
            address = winappdbg.HexOutput.integer(address + size)
            msg = "error reading process %d, from %s to %s (%d bytes)"
            msg = msg % (pid, address, next_address, size)
            raise CmdError, msg
        return data

    # Write the process memory.
    def write_memory(self, address, data, pid = None):
        process = self.get_process(pid)
        try:
            process.write(address, data)
        except WindowsError, e:
            address = winappdbg.HexOutput.integer(address + size)
            msg = "error writing process %d, from %s to %s (%d bytes)"
            msg = msg % (pid, address, next_address, size)
            raise CmdError, msg

    # Change a register value.
    def change_register(self, register, value, tid = None):

        # Get the thread.
        if tid is None:
            if self.lastEvent.debug.get_debugee_count() <= 0:
                raise CmdError, "no current process set"
            thread = self.lastEvent.get_thread()
        else:
            try:
                thread = self.lastEvent.debug.system.get_thread(tid)
            except KeyError:
                raise CmdError, "thread not found (%d)" % tid

        # Convert the value to integer type.
        try:
            value = self.input_integer(value)
        except ValueError:
            pid   = thread.get_pid()
            value = self.input_address(value, pid, tid)

        # Suspend the thread.
        # The finally clause ensures the thread is resumed before returning.
        thread.suspend()
        try:

            # Get the current context.
            ctx = thread.get_context()

            # Register name matching is case insensitive.
            register = register.lower()

            # Integer 32 bits registers.
            if register in self.register_names:
                register = register.title()                 # eax -> Eax

            # Segment (16 bit) registers.
            if register in self.segment_names:
                register = 'Seg%s' % token.title()          # cs -> SegCs
                value    = value & 0x0000FFFF

            # Integer 16 bits registers.
            if register in self.register_alias_16.keys():
                register = self.register_alias_16[token]
                previous = ctx.get(register) & 0xFFFF0000
                value    = (value & 0x0000FFFF) | previous

            # Integer 8 bits registers (low part).
            if register in self.register_alias_8_low.keys():
                register = self.register_alias_8_low[token]
                previous = ctx.get(register) % 0xFFFFFF00
                value    = (value & 0x000000FF) | previous

            # Integer 8 bits registers (high part).
            if register in self.register_alias_8_high.keys():
                register = self.register_alias_8_high[token]
                previous = ctx.get(register) % 0xFFFF00FF
                value    = ((value & 0x000000FF) << 8) | previous

            # Set the new context.
            ctx.__setitem__(register, value)
            thread.set_context(ctx)

        # Resume the thread.
        finally:
            thread.resume()

    # Very crude way to find data within the process memory.
    # TODO: Perhaps pfind.py can be integrated here instead.
    def find_in_memory(self, query, process):
        for mbi in process.get_memory_map():
            if mbi.State != win32.MEM_COMMIT or mbi.Protect & win32.PAGE_GUARD:
                continue
            address = mbi.BaseAddress
            size    = mbi.RegionSize
            try:
                data = process.read(address, size)
            except WindowsError:
                msg = "*** Warning: read error at address %s"
                msg = msg % winappdbg.HexDump.address(address)
                print msg
            width = min(len(query), 16)
            p = data.find(query)
            while p >= 0:
                q = p + len(query)
                d = data[ p : min(q, p + width) ]
                h = winappdbg.HexDump.hexline(d, width = width)
                a = winappdbg.HexDump.address(address + p)
                print "%s: %s" % (a, h)
                p = data.find(query, q)

    # Kill a process.
    def kill_process(self, pid):
        process = self.lastEvent.debug.system.get_process(pid)
        try:
            process.kill()
            if self.lastEvent.debug.is_debugee(pid):
                self.lastEvent.debug.detach(pid)
            print "Killed process (%d)" % pid
        except Exception, e:
            print "Error trying to kill process (%d)" % pid

    # Kill a thread.
    def kill_thread(self, tid):
        thread = self.lastEvent.debug.system.get_thread(tid)
        try:
            thread.kill()
            process = thread.get_process()
            pid = process.get_pid()
            if self.lastEvent.debug.is_debugee(pid) and not process.is_alive():
                self.lastEvent.debug.detach(pid)
            print "Killed thread (%d)" % tid
        except Exception, e:
            print "Error trying to kill thread (%d)" % tid

#------------------------------------------------------------------------------
# Command prompt input

    # Prompt the user for commands.
    def prompt_user(self):
        while not self.debuggerExit:
            try:
                self.cmdloop()
                break
            except CmdError, e:
                print "*** Error: %s" % str(e)
            except Exception, e:
                traceback.print_exc(e)
##                self.debuggerExit = True

    # Prompt the user for a YES/NO kind of question.
    def ask_user(self, msg, prompt = "Are you sure? (y/N): "):
        print msg
        answer = raw_input(prompt)
        answer = answer.strip()[:1].lower()
        return answer == 'y'

    # Autocomplete the given command when not ambiguous.
    # Convert it to lowercase (so commands are seen as case insensitive).
    def autocomplete(self, cmd):
        cmd = cmd.lower()
        completed = self.completenames(cmd)
        if len(completed) == 1:
            cmd = completed[0]
        return cmd

    # Get the help text for the given list of command methods.
    # Note it's NOT a list of commands, but a list of actual method names.
    # Each line of text is stripped and all lines are sorted.
    # Repeated text lines are removed.
    # Returns a single, possibly multiline, string.
    def get_help(self, commands):
        msg = set()
        for name in commands:
            if name != 'do_help':
                try:
                    doc = getattr(self, name).__doc__.split('\n')
                except Exception:
                    return ( "No help available when Python"
                             " is run with the -OO switch." )
                for x in doc:
                    x = x.strip()
                    if x:
                        msg.add('  %s' % x)
        msg = list(msg)
        msg.sort()
        msg = '\n'.join(msg)
        return msg

    # Parse the prefix and remove it from the command line.
    def split_prefix(self, line):
        prefix = None
        if line.startswith('~'):
            pos         = line.find(' ')
            if pos == 1:
                pos     = line.find(' ', pos + 1)
            if not pos < 0:
                prefix  = line[ 1 : pos ].strip()
                line    = line[ pos : ].strip()
        return prefix, line

#------------------------------------------------------------------------------
# Cmd() hacks

    # Header for help page.
    doc_header = 'Available commands (type help * or help <command>)'

##    # Read and write directly to stdin and stdout.
##    # This prevents the use of raw_input and print.
##    use_rawinput = False

    @property
    def prompt(self):
        if self.lastEvent:
            pid = self.lastEvent.get_pid()
            tid = self.lastEvent.get_tid()
            if self.lastEvent.debug.is_debugee(pid):
##                return '~%d(%d)> ' % (tid, pid)
                return '%d:%d> ' % (pid, tid)
        return '> '

    # Return a sorted list of method names.
    # Only returns the methods that implement commands.
    def get_names(self):
        names = Cmd.get_names(self)
        names = [ x for x in set(names) if x.startswith('do_') ]
        names.sort()
        return names

    # Automatically autocomplete commands, even if Tab wasn't pressed.
    # The prefix is removed from the line and stored in self.cmdprefix.
    def parseline(self, line):
        self.cmdprefix, line = self.split_prefix(line)
        line = line.strip()
        if line and line[0] == '.':
            line = 'plugin ' + line[1:]
        cmd, arg, line = Cmd.parseline(self, line)
        if cmd:
            cmd = self.autocomplete(cmd)
        return cmd, arg, line

##    # Don't repeat the last executed command.
##    def emptyline(self):
##        pass

    # Reset the defaults for some commands.
    def preloop(self):
        self.default_disasm_target  = 'eip'
        self.default_display_target = 'eip'
        self.last_display_command   = self.do_db

    # Put the prefix back in the command line.
    def get_lastcmd(self):
        return self.__lastcmd
    def set_lastcmd(self, lastcmd):
        if self.cmdprefix:
            lastcmd = '~%s %s' % (self.cmdprefix, lastcmd)
        self.__lastcmd = lastcmd
    lastcmd = property(get_lastcmd, set_lastcmd)

    # Quit the command prompt if the debuggerExit flag is on.
    def postcmd(self, stop, line):
        return stop or self.debuggerExit

#------------------------------------------------------------------------------
# Commands

    # Each command contains a docstring with it's help text.
    # The help text consist of independent text lines,
    # where each line shows a command and it's parameters.
    # Each command method has the help message for itself and all it's aliases.
    # Only the docstring for the "help" command is shown as-is.

    # NOTE: Command methods MUST be all lowercase!

    # Extended help command.
    def do_help(self, arg):
        """
        ? - show the list of available commands
        ? * - show help for all commands
        ? <command> [command...] - show help for the given command(s)
        help - show the list of available commands
        help * - show help for all commands
        help <command> [command...] - show help for the given command(s)
        """
        if not arg:
            Cmd.do_help(self, arg)
        elif arg in ('?', 'help'):
            # An easter egg :)
            print "  Help! I need somebody..."
            print "  Help! Not just anybody..."
            print "  Help! You know, I need someone..."
            print "  Heeelp!"
        else:
            if arg == '*':
                commands = self.get_names()
                commands = [ x for x in commands if x.startswith('do_') ]
            else:
                commands = set()
                for x in arg.split(' '):
                    x = x.strip()
                    if x:
                        for n in self.completenames(x):
                            commands.add( 'do_%s' % n )
                commands = list(commands)
                commands.sort()
            print self.get_help(commands)

    def do_shell(self, arg):
        """
        ! <command> [arguments...] - execute a shell command
        shell <command> [arguments...] - execute a shell command
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"

        # Try to use the environment to locate cmd.exe.
        # If not found, it's usually OK to just use the filename,
        # since cmd.exe is one of those "magic" programs that
        # can be automatically found by CreateProcess.
        arg = '%s /c %s' % (os.getenv('ComSpec', 'cmd.exe'), arg)
        process = self.lastEvent.debug.system.start_process(arg, bConsole = True)
        process.wait()

    def do_plugin(self, arg):
        """
        [~prefix] .<name> [arguments] - run a plugin command
        [~prefix] plugin <name> [arguments] - run a plugin command
        """
        pos = arg.find(' ')
        if pos < 0:
            name = arg
            arg  = ''
        else:
            name = arg[:pos]
            arg  = arg[pos:].strip()
        if not name:
            raise CmdError, "missing plugin name"
        for c in name:
            if c not in self.valid_plugin_name_chars:
                raise CmdError, "invalid plugin name: %r" % name
        name = 'do_%s' % name

        # The plugins interface is quite simple.
        #
        # Just place a .py file with the plugin name in the "plugins" folder,
        # for example "do_example.py" would implement the "example" command.
        #
        # The plugin must have a function named "do", which implements the
        # command functionality exactly like the do_* methods of Cmd instances.
        #
        # The docstring for the "do" function will be parsed exactly like
        # one of the debugger's commands - that is, each line is treated
        # independently.

        plugins_path = sys.argv[0]
        plugins_path = plugins_path[:-len(os.path.basename(plugins_path))]
        plugins_path = os.path.join(plugins_path, 'plugins')
        old_path = sys.path
        sys.path = [ plugins_path ]
        print sys.path
        try:
            try:
                plugin = __import__(name)
                reload(plugin)
            except ImportError:
                raise CmdError, "plugin not found: %s" % name
        finally:
            sys.path = old_path
        return plugin.do(self, arg)

    def do_quit(self, arg):
        """
        quit - detach from all processes and quit
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        if arg:
            raise CmdError, "too many arguments"
        count = self.lastEvent.debug.get_debugee_count()
        if count > 0:
            if count == 1:
                msg = "There's a program still running."
            else:
                msg = "There are %s programs still running." % count
            if not self.ask_user(msg):
                return False
        self.debuggerExit = True
        return True

    def do_attach(self, arg):
        """
        attach <target> [target...] - attach to the given process(es)
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        targets = self.input_process_list( self.split_tokens(arg, 1) )
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
        [~process] detach - detach from the current process
        detach - detach from the current process
        detach <target> [target...] - detach from the given process(es)
        """
        debug   = self.lastEvent.debug
        token_list = self.split_tokens(arg)
        if self.cmdprefix:
            token_list.insert(0, self.cmdprefix)
        targets = self.input_process_list(token_list)
        if not targets:
            targets = [ self.lastEvent.get_pid() ]
        for pid in targets:
            try:
                debug.detach(pid)
                print "Detached from process (%d)" % pid
            except Exception, e:
                print "Error: can't detach from process (%d)" % pid

    def do_windowed(self, arg):
        """
        windowed <target> [arguments...] - run a windowed program for debugging
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        cmdline = self.input_command_line(arg)
        try:
            process = self.lastEvent.debug.execl(arg,
                                                bConsole = False,
                                                 bFollow = self.options.follow)
            print "Spawned process (%d)" % process.get_pid()
        except Exception, e:
            raise CmdError, "can't execute"

    def do_console(self, arg):
        """
        console <target> [arguments...] - run a console program for debugging
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
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
        continue - go (continue execution)
        g - go (continue execution)
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        if arg:
            raise CmdError, "too many arguments"
        if self.lastEvent.debug.get_debugee_count() > 0:
            return True

    do_g = do_continue

    def do_gh(self, arg):
        """
        gh - go with exception handled
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        if arg:
            raise CmdError, "too many arguments"
        self.lastEvent.continueStatus = win32.DBG_EXCEPTION_HANDLED
        return self.do_go(arg)

    def do_gn(self, arg):
        """
        gn - go with exception not handled
        """
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        if arg:
            raise CmdError, "too many arguments"
        self.lastEvent.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
        return self.do_go(arg)

    def do_refresh(self, arg):
        """
        refresh - refresh the list of running processes and threads
        [~process] refresh - refresh the list of running threads
        """
        if arg:
            raise CmdError, "too many arguments"
        if self.cmdprefix:
            process = self.get_process_from_prefix()
            process.scan()
        else:
            self.lastEvent.debug.system.scan()

    def do_processlist(self, arg):
        """
        pl - show the processes being debugged
        processlist - show the processes being debugged
        """
        if arg:
            raise CmdError, "too many arguments"
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        system   = self.lastEvent.debug.system
        pid_list = self.lastEvent.debug.get_debugee_pids()
        if pid_list:
            print "Process ID   File name"
            for pid in pid_list:
                if   pid == 0:
                    filename = "System Idle Process"
                elif pid == 4:
                    filename = "System"
                else:
                    filename = system.get_process(pid).get_filename()
                    filename = winappdbg.PathOperations.pathname_to_filename(filename)
                print "%-12d %s" % (pid, filename)

    do_pl = do_processlist

    def do_threadlist(self, arg):
        """
        tl - show the threads being debugged
        threadlist - show the threads being debugged
        """
        if arg:
            raise CmdError, "too many arguments"
        if self.cmdprefix:
            process = self.get_process_from_prefix()
            for thread in process.iter_threads():
                tid  = thread.get_tid()
                name = thread.get_name()
                print "%-12d %s" % (tid, name)
        else:
            system   = self.lastEvent.debug.system
            pid_list = self.lastEvent.debug.get_debugee_pids()
            if pid_list:
                print "Thread ID    Thread name"
                for pid in pid_list:
                    process = system.get_process(pid)
                    for thread in process.iter_threads():
                        tid  = thread.get_tid()
                        name = thread.get_name()
                        print "%-12d %s" % (tid, name)

    do_tl = do_threadlist

    def do_kill(self, arg):
        """
        [~process] kill - kill a process
        [~thread] kill - kill a thread
        kill - kill the current process
        kill * - kill all debugged processes
        kill <processes and/or threads...> - kill the given processes and threads
        """
        if arg:
            if arg == '*':
                target_pids = self.lastEvent.debug.get_debugee_pids()
                target_tids = list()
            else:
                target_pids = set()
                target_tids = set()
                if self.cmdprefix:
                    pid, tid = self.get_process_and_thread_ids_from_prefix()
                    if tid is None:
                        target_tids.add(tid)
                    else:
                        target_pids.add(pid)
                for token in self.split_tokens(arg):
                    try:
                        pid = self.input_process(token)
                        target_pids.add(pid)
                    except CmdError:
                        try:
                            tid = self.input_process(token)
                            target_pids.add(pid)
                        except CmdError:
                            msg = "unknown process or thread (%s)" % token
                            raise CmdError, msg
                target_pids = list(target_pids)
                target_tids = list(target_tids)
                target_pids.sort()
                target_tids.sort()
            msg = "You are about to kill %d processes and %d threads."
            msg = msg % ( len(target_pids), len(target_tids) )
            if self.ask_user(msg):
                for pid in target_pids:
                    self.kill_process(pid)
                for tid in target_tids:
                    self.kill_thread(tid)
        else:
            if self.cmdprefix:
                pid, tid = self.get_process_and_thread_ids_from_prefix()
                if tid is None:
                    if pid == self.lastEvent.get_pid():
                        msg = "You are about to kill the current process."
                    else:
                        msg = "You are about to kill process %d." % pid
                    if self.ask_user(msg):
                        self.kill_process(pid)
                else:
                    if tid == self.lastEvent.get_tid():
                        msg = "You are about to kill the current thread."
                    else:
                        msg = "You are about to kill thread %d." % tid
                    if self.ask_user(msg):
                        self.kill_thread(tid)
            else:
                if not self.lastEvent:
                    raise CmdError, "no current process set"
                pid = self.lastEvent.get_pid()
                if self.ask_user("You are about to kill the current process."):
                    self.kill_process(pid)

    # TODO: create hidden threads using undocumented API calls.
    def do_modload(self, arg):
        """
        [~process] modload <filename.dll> - load a DLL module
        """
        filename = self.split_tokens(arg, 1, 1)[0]
        process  = self.get_process_from_prefix()
        try:
            process.inject_dll(filename, bWait=False)
        except RuntimeError:
            print "Can't inject module: %r" % filename

    # TODO: modunload

    def do_stack(self, arg):
        """
        [~thread] k - show the stack trace
        [~thread] stack - show the stack trace
        """
        if arg:     # XXX TODO add depth parameter
            raise CmdError, "too many arguments"
        pid, tid        = self.get_process_and_thread_ids_from_prefix()
        process         = self.get_process(pid)
        thread          = process.get_thread(tid)
        try:
            stack_trace = thread.get_stack_trace_with_labels()
            if stack_trace:
                print winappdbg.CrashDump.dump_stack_trace_with_labels(stack_trace),
            else:
                print "No stack trace available for thread (%d)" % tid
        except WindowsError, e:
            print "Can't get stack trace for thread (%d)" % tid

    do_k = do_stack

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
        if self.cmdprefix:
            raise CmdError, "prefix not allowed"
        if not self.lastEvent:
            raise CmdError, "no current process set"
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
        [~process] bp <address> - set a code breakpoint
        """
        pid = self.get_process_id_from_prefix()
        if not self.lastEvent.debug.is_debugee(pid):
            raise CmdError, "target process is not being debugged"
        process    = self.get_process(pid)
        token_list = self.split_tokens(arg, 1, 1)
        address    = self.input_address(token_list[0], pid)
        self.lastEvent.debug.break_at(pid, address)

    def do_ba(self, arg):
        """
        [~thread] ba <a|w|e> <1|2|4|8> <address> - set hardware breakpoint
        """
        debug      = self.lastEvent.debug
        thread     = self.get_thread_from_prefix()
        pid        = thread.get_pid()
        tid        = thread.get_tid()
        if not debug.is_debugee(pid):
            raise CmdError, "target thread is not being debugged"
        token_list = self.split_tokens(arg, 3, 3)
        access     = token_list[0].lower()
        size       = token_list[1]
        address    = token_list[2]
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
        thread  = self.get_thread_from_prefix()
        tid     = thread.get_tid()
        pid     = thread.get_pid()
        if not debug.is_debugee(pid):
            raise CmdError, "target process is not being debugged"
        address = self.input_address(address, pid)
        if debug.has_hardware_breakpoint(tid, address):
            debug.erase_hardware_breakpoint(tid, address)
        debug.define_hardware_breakpoint(tid, address, access, size)
        debug.enable_hardware_breakpoint(tid, address)

    def do_bm(self, arg):
        """
        [~process] bm <address-address> - set memory breakpoint
        """
        pid = self.get_process_id_from_prefix()
        if not self.lastEvent.debug.is_debugee(pid):
            raise CmdError, "target process is not being debugged"
        process       = self.get_process(pid)
        token_list    = self.split_tokens(arg, 1, 2)
        address, size = self.input_address_range(token_list[0], pid)
        self.lastEvent.debug.watch_buffer(pid, address, size)

    def do_bl(self, arg):
        """
        bl - list the breakpoints for the current process
        bl * - list the breakpoints for all processes
        [~process] bl - list the breakpoints for the given process
        bl <process> [process...] - list the breakpoints for each given process
        """
        debug = self.lastEvent.debug
        if arg == '*':
            if self.cmdprefix:
                raise CmdError, "prefix not supported"
            breakpoints = debug.get_debugee_pids()
        else:
            targets = self.input_process_list( self.split_tokens(arg) )
            if self.cmdprefix:
                targets.insert(0, self.input_process(self.cmdprefix))
            if not targets:
                if not self.lastEvent:
                    raise CmdError, "no current process is set"
                targets = [ self.lastEvent.get_pid() ]
        for pid in targets:
            bplist = debug.get_process_code_breakpoints(pid)
            if bplist:
                print "Process %d:" % pid
                for bp in bplist:
                    address = repr(bp)[1:-1].replace('remote address ','')
                    print "  %s" % address
            bplist = debug.get_process_page_breakpoints(pid)
            if bplist:
                print "Process %d:" % pid
                for bp in bplist:
                    address = repr(bp)[1:-1].replace('remote address ','')
                    print "  %s" % address
            for tid in debug.system.get_process(pid).iter_thread_ids():
                bplist = debug.get_thread_hardware_breakpoints(tid)
                if bplist:
                    print "Thread %d:" % tid
                    for bp in bplist:
                        address = repr(bp)[1:-1].replace('remote address ','')
                        print "  %s" % address

    def do_bo(self, arg):
        """
        [~process] bo <address> - make a code breakpoint one-shot
        [~thread] bo <address> - make a hardware breakpoint one-shot
        [~process] bo <address-address> - make a memory breakpoint one-shot
        [~process] bo <address> <size> - make a memory breakpoint one-shot
        """
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_breakpoint(token_list)
        debug = self.lastEvent.debug
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
        [~process] be <address> - enable a code breakpoint
        [~thread] be <address> - enable a hardware breakpoint
        [~process] be <address-address> - enable a memory breakpoint
        [~process] be <address> <size> - enable a memory breakpoint
        """
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_breakpoint(token_list)
        debug = self.lastEvent.debug
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
        [~process] bd <address> - disable a code breakpoint
        [~thread] bd <address> - disable a hardware breakpoint
        [~process] bd <address-address> - disable a memory breakpoint
        [~process] bd <address> <size> - disable a memory breakpoint
        """
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_breakpoint(token_list)
        debug = self.lastEvent.debug
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
        [~process] bc <address> - clear a code breakpoint
        [~thread] bc <address> - clear a hardware breakpoint
        [~process] bc <address-address> - clear a memory breakpoint
        [~process] bc <address> <size> - clear a memory breakpoint
        """
        token_list = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_breakpoint(token_list)
        debug = self.lastEvent.debug
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
        [~thread] u [register] - show code disassembly
        [~process] u [address] - show code disassembly
        [~thread] disassemble [register] - show code disassembly
        [~process] disassemble [address] - show code disassembly
        """
        if not arg:
            arg = self.default_disasm_target
        token_list      = self.split_tokens(arg, 1, 1)
        pid, tid        = self.get_process_and_thread_ids_from_prefix()
        process         = self.get_process(pid)
        address         = self.input_address(token_list[0], pid, tid)
        try:
            code = process.disassemble(address, 15*8)[:8]
        except Exception, e:
            msg = "can't disassemble address %s"
            msg = msg % winappdbg.HexDump.address(address)
            raise CmdError, msg
        if code:
            label        = process.get_label_at_address(address)
            last_code    = code[-1]
            next_address = last_code[0] + last_code[1]
            next_address = winappdbg.HexOutput.integer(next_address)
            self.default_disasm_target = next_address
            print "%s:" % label
##            print winappdbg.CrashDump.dump_code(code)
            for line in code:
                print winappdbg.CrashDump.dump_code_line(line, bShowDump = False)

    do_u = do_disassemble

    def do_d(self, arg):
        """
        [~thread] d <register> - show memory contents
        [~thread] d <register-register> - show memory contents
        [~thread] d <register> <size> - show memory contents
        [~process] d <address> - show memory contents
        [~process] d <address-address> - show memory contents
        [~process] d <address> <size> - show memory contents
        """
        return self.last_display_command(arg)

    def do_db(self, arg):
        """
        [~thread] db <register> - show memory contents as bytes
        [~thread] db <register-register> - show memory contents as bytes
        [~thread] db <register> <size> - show memory contents as bytes
        [~process] db <address> - show memory contents as bytes
        [~process] db <address-address> - show memory contents as bytes
        [~process] db <address> <size> - show memory contents as bytes
        """
        self.print_memory_display(arg, winappdbg.HexDump.hexblock)
        self.last_display_command = self.do_db

    def do_dw(self, arg):
        """
        [~thread] dw <register> - show memory contents as words
        [~thread] dw <register-register> - show memory contents as words
        [~thread] dw <register> <size> - show memory contents as words
        [~process] dw <address> - show memory contents as words
        [~process] dw <address-address> - show memory contents as words
        [~process] dw <address> <size> - show memory contents as words
        """
        self.print_memory_display(arg, winappdbg.HexDump.hexblock_word)
        self.last_display_command = self.do_dw

    def do_dd(self, arg):
        """
        [~thread] dd <register> - show memory contents as dwords
        [~thread] dd <register-register> - show memory contents as dwords
        [~thread] dd <register> <size> - show memory contents as dwords
        [~process] dd <address> - show memory contents as dwords
        [~process] dd <address-address> - show memory contents as dwords
        [~process] dd <address> <size> - show memory contents as dwords
        """
        self.print_memory_display(arg, winappdbg.HexDump.hexblock_dword)
        self.last_display_command = self.do_dd

    def do_dq(self, arg):
        """
        [~thread] dq <register> - show memory contents as qwords
        [~thread] dq <register-register> - show memory contents as qwords
        [~thread] dq <register> <size> - show memory contents as qwords
        [~process] dq <address> - show memory contents as qwords
        [~process] dq <address-address> - show memory contents as qwords
        [~process] dq <address> <size> - show memory contents as qwords
        """
        self.print_memory_display(arg, winappdbg.HexDump.hexblock_qword)
        self.last_display_command = self.do_dq

    # XXX TODO
    # Change the way the default is used with ds and du

    def do_ds(self, arg):
        """
        [~thread] ds <register> - show memory contents as ANSI string
        [~process] ds <address> - show memory contents as ANSI string
        """
        if not arg:
            arg = self.default_display_target
        token_list              = self.split_tokens(arg, 1, 1)
        pid, tid, address, size = self.input_display(token_list, 256)
        process                 = self.get_process(pid)
        data                    = process.peek_string(address, False, size)
        if data:
            print repr(data)
        self.last_display_command = self.do_ds

    def do_du(self, arg):
        """
        [~thread] du <register> - show memory contents as Unicode string
        [~process] du <address> - show memory contents as Unicode string
        """
        if not arg:
            arg = self.default_display_target
        token_list              = self.split_tokens(arg, 1, 2)
        pid, tid, address, size = self.input_display(token_list, 256)
        process                 = self.get_process(pid)
        data                    = process.peek_string(address, True, size)
        if data:
            print repr(data)
        self.last_display_command = self.do_du

    def do_register(self, arg):
        """
        [~thread] r - print the value of all registers
        [~thread] r <register> - print the value of a register
        [~thread] r <register>=<value> - change the value of a register
        [~thread] register - print the value of all registers
        [~thread] register <register> - print the value of a register
        [~thread] register <register>=<value> - change the value of a register
        """
        arg = arg.strip()
        if not arg:
            self.print_current_location()
        else:
            equ = arg.find('=')
            if equ >= 0:
                register = arg[:equ].strip()
                value    = arg[equ+1:].strip()
                if not value:
                    value = '0'
                self.change_register(register, value)
            else:
                value = self.input_register(arg)
                if value is None:
                    raise CmdError, "unknown register: %s" % arg
                try:
                    label   = None
                    thread  = self.get_thread_from_prefix()
                    process = thread.get_process()
                    module  = process.get_module_at_address(value)
                    if module:
                        label = module.get_label_at_address(value)
                except RuntimeError:
                    label = None
                reg = arg.upper()
                val = winappdbg.HexDump.address(value)
                if label:
                    print "%s: %s (%s)" % (reg, val, label)
                else:
                    print "%s: %s" % (reg, val)

    do_r = do_register

    def do_eb(self, arg):
        """
        [~process] eb <address> <data> - write the data to the specified address
        """
        # TODO
        # data parameter should be optional, use a child Cmd here
        pid        = self.get_process_id_from_prefix()
        token_list = self.split_tokens(arg, 2)
        address    = self.input_address(token_list[0], pid)
        data       = winappdbg.HexInput.hexadecimal(' '.join(token_list[1:]))
        self.write_memory(address, data, pid)

    def do_find(self, arg):
        """
        [~process] f <string> - find the string in the process memory
        [~process] find <string> - find the string in the process memory
        """
        if not arg:
            raise CmdError, "missing parameter: string"
        process = self.get_process_from_prefix()
        self.find_in_memory(arg, process)

    do_f = do_find

    def do_memory(self, arg):
        """
        [~process] m - show the process memory map
        [~process] memory - show the process memory map
        """
        if arg:     # TODO: take min and max addresses
            raise CmdError, "too many arguments"
        process = self.get_process_from_prefix()
        try:
            memoryMap       = process.get_memory_map()
            mappedFilenames = process.get_mapped_filenames()
            print
            print winappdbg.CrashDump.dump_memory_map(memoryMap, mappedFilenames)
        except WindowsError, e:
            msg = "can't get memory information for process (%d)"
            raise CmdError, msg % process.get_pid()

    do_m = do_memory

#------------------------------------------------------------------------------
# Event handling

# FIXME
# * not all breakpoints and single steps should be handled, we have to
#   remember which ones we set and which ones we didn't

# TODO
# * add configurable stop/don't stop behavior on events and exceptions

    # Stop for all events, unless stated otherwise.
    def event(self, event):
        self.print_event(event)
        self.prompt_user()

    # Stop for all exceptions, unless stated otherwise.
    def exception(self, event):
        self.print_exception(event)
        self.prompt_user()

    # Stop for breakpoint exceptions.
    # Handle all of them, even if they aren't ours.
    def breakpoint(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        self.print_event_location(event)
        self.prompt_user()

    # Stop for single step exceptions.
    # Handle all of them, even if they aren't ours.
    def single_step(self, event):
        event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        self.print_event_location(event)
        self.prompt_user()

    # Don't stop for process start.
    def create_process(self, event):
        self.print_process_start(event)
        self.print_thread_start(event)
        self.print_module_load(event)

    # Don't stop for process exit.
    def exit_process(self, event):
        self.print_process_end(event)

    # Don't stop for thread creation.
    def create_thread(self, event):
        self.print_thread_start(event)

    # Don't stop for thread exit.
    def exit_thread(self, event):
        self.print_thread_end(event)

    # Don't stop for DLL load.
    def load_dll(self, event):
        self.print_module_load(event)

    # Don't stop for DLL unload.
    def unload_dll(self, event):
        self.print_module_unload(event)

    # Don't stop for debug strings.
    def output_string(self, event):
        self.print_debug_string(event)

#------------------------------------------------------------------------------
# Command line parsing

# TODO
# * add an option to show python tracebacks of all errors, disabled by default

    # Define the command line parser and parse the command line.
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
        self.parser.add_option_group(debugging)

        # Set the default values
        self.parser.set_defaults(
            attach      = [],
            console     = [],
            windowed    = [],
            autodetach  = True,
            follow      = True,
            hostile     = False,
        )

        # Parse the command line
        (self.options, args) = self.parser.parse_args(self.argv)
        if len(args) > 1:
            self.parser.error("don't know what to do with: %r" % args[1])

#------------------------------------------------------------------------------
# Debugger create and destroy

    # Instance a Debug object and put it inside a NoEvent object.
    # Then queue some commands, if requested in the command line options.
    def create_debugger(self):

        # Instance a debugger
        debug = winappdbg.Debug(self,
                                    bKillOnExit  = not self.options.autodetach,
                                    bHostileCode = self.options.hostile,
                                    )

        # Populate the snapshot of processes
        debug.system.scan()

        # Instance a dummy event, just to contain the debugger object.
        self.lastEvent = winappdbg.NoEvent(debug)

        # Queue the attach command, if needed
        if self.options.attach:
            cmd = 'attach %s' % self.join_tokens(self.options.attach)
            self.cmdqueue.append(cmd)

        # Queue the start commands, if needed
        for cmdline in self.options.windowed:
            self.cmdqueue.append( 'windowed %s' % cmdline )

        # Queue the startc commands, if needed
        for cmdline in self.options.console:
            self.cmdqueue.append( 'console %s' % cmdline )

        # Queue the go command, if other commands were queued before
        if len(self.cmdqueue) > 0:
            self.cmdqueue.append('continue')

    # Destroy the Debug object.
    # Circular references must be removed, or the destructors never get called.
    def destroy_debugger(self):
        if hasattr(self, 'lastEvent'):
            event = self.lastEvent
            del self.lastEvent
            debug = event.debug
            debug.stop(event)
            debug.system.clear()
            del event.debug

#------------------------------------------------------------------------------
# Main loop

    # Run the debugger.
    # This is the first method called.
    def run(self, argv):
        self.argv = list(argv)
        try:
            self.initialize()
            self.main_loop()
        finally:
            self.finalize()

    # Initialize the debugger.
    def initialize(self):
        self.print_banner()
        self.parse_cmdline()
        self.create_debugger()
        self.load_history()
##        self.set_control_c_handler()

    # Clean up when closing the debugger.
    def finalize(self):
##        self.remove_control_c_handler()
        self.destroy_debugger()

    # Debugger's main loop.
    def main_loop(self):
        self.debuggerExit = False
        debug = self.lastEvent.debug

        # Loop until the debugger is told to quit.
        while not self.debuggerExit:

            try:

                # If for some reason the last event wasn't continued,
                # continue it here. This won't be done more than once
                # for a given Event instance, though.
                if self.lastEvent:
                    print "*** Warning: " \
                          "last debug event wasn't properly handled."
                    lastEvent      = self.lastEvent
                    self.lastEvent = winappdbg.NoEvent(debug)
                    try:
                        debug.cont(lastEvent)
                    # On error, show the command prompt.
                    except Exception:
                        traceback.print_exc()
                        self.prompt_user()

                # While debugees are attached, handle debug events.
                # Some debug events may cause the command prompt to be shown.
                if self.lastEvent.debug.get_debugee_count() > 0:
                    try:

                        # Get the next debug event.
                        self.lastEvent = debug.wait()

                        # Dispatch the debug event.
                        try:
                            debug.dispatch(self.lastEvent)

                        # Continue the debug event.
                        finally:
                            debug.cont(self.lastEvent)
                            self.lastEvent = winappdbg.NoEvent(debug)

                    # On error, show the command prompt.
                    except Exception:
                        traceback.print_exc()
                        self.prompt_user()

                # While no debugees are attached, show the command prompt.
                else:
                    self.prompt_user()

            # When the user presses Ctrl-C send a debug break to all debugees.
            except KeyboardInterrupt:
                try:
                    print "*** User requested debug break"
                    system = debug.system
                    for pid in debug.get_debugee_pids():
                        try:
                            system.get_process(pid).debug_break()
                        except:
                            traceback.print_exc()
                except:
                    traceback.print_exc()

#==============================================================================

def main(argv):
    return ConsoleDebugger().run(argv)

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
