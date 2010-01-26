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

"""
Crash logging module.

@group Crash reporting:
    Crash, CrashContainer, CrashTable,
    VolatileCrashContainer, DummyCrashContainer
"""

__revision__ = "$Id$"

__all__ =   [
                # Object that represents a crash in the debugee.
                'Crash',

                # Container that can store Crash objects in a DBM database.
                'CrashContainer',

                # Container that can store Crash objects in a SQLite database.
                'CrashTable',

                # Volatile container that does not store Crash objects.
                'VolatileCrashContainer',

                # Fake Crash container.
                'DummyCrashContainer',
            ]

from system import MemoryAddresses, PathOperations
from textio import HexDump, CrashDump
import win32

import os
import time
import zlib
import traceback

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    from pickletools import optimize
except ImportError:
    def optimize(picklestring):
        return picklestring

# lazy imports
anydbm = None
sqlite = None

#==============================================================================

class Crash (object):
    """
    Represents a crash, bug, or another interesting event in the debugee.

    @group Key:
        key

    @group Report:
        briefReport, fullReport, notesReport, isExploitable

    @group Notes:
        addNote, getNotes, iterNotes, hasNotes, clearNotes, notes

    @group Miscellaneous:
        fetch_extra_data

    @group Basic information:
        timeStamp, eventCode, eventName, pid, tid, registers, labelPC

    @group Optional information:
        debugString,
        modFileName,
        lpBaseOfDll,
        exceptionCode,
        exceptionName,
        exceptionDescription,
        exceptionAddress,
        exceptionLabel,
        firstChance,
        faultType,
        faultAddress,
        faultLabel,
        isOurBreakpoint,
        isSystemBreakpoint,
        stackTrace,
        stackTracePC,
        stackTraceLabels,
        stackTracePretty

    @group Extra information:
        registersPeek,
        stackRange,
        stackFrame,
        stackPeek,
        faultCode,
        faultMem,
        faultPeek,
        faultDisasm,
        memoryMap

    @type timeStamp: float
    @ivar timeStamp: Timestamp as returned by time.time().

    @type notes: list( str )
    @ivar notes: List of strings, each string is a note.

    @type eventCode: int
    @ivar eventCode: Event code as defined by the Win32 API.

    @type eventName: str
    @ivar eventName: Event code user-friendly name.

    @type pid: int
    @ivar pid: Process global ID.

    @type tid: int
    @ivar tid: Thread global ID.

    @type registers: dict( str S{->} int )
    @ivar registers: Dictionary mapping register names to their values.

    @type registersPeek: None or dict( str S{->} str )
    @ivar registersPeek: Dictionary mapping register names to the data they point to.

        C{None} if unapplicable or unable to retrieve.

    @type labelPC: None or str
    @ivar labelPC: Label pointing to the program counter.

        C{None} or invalid if unapplicable or unable to retrieve.

    @type debugString: None or str
    @ivar debugString: Debug string sent by the debugee.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionCode: None or int
    @ivar exceptionCode: Exception code as defined by the Win32 API.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionName: None or str
    @ivar exceptionName: Exception code user-friendly name.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionDescription: None or str
    @ivar exceptionDescription: Exception description.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionAddress: None or int
    @ivar exceptionAddress: Memory address where the exception occured.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionLabel: None or str
    @ivar exceptionLabel: Label pointing to the exception address.

        C{None} or invalid if unapplicable or unable to retrieve.

    @type faultType: None or int
    @ivar faultType: Access violation type.
        Only applicable to memory faults.
        Should be one of the following constants:

         - L{win32.ACCESS_VIOLATION_TYPE_READ}
         - L{win32.ACCESS_VIOLATION_TYPE_WRITE}
         - L{win32.ACCESS_VIOLATION_TYPE_DEP}

        C{None} if unapplicable or unable to retrieve.

    @type faultAddress: None or int
    @ivar faultAddress: Access violation memory address.
        Only applicable to memory faults.

        C{None} if unapplicable or unable to retrieve.

    @type faultLabel: None or str
    @ivar faultLabel: Label pointing to the access violation memory address.
        Only applicable to memory faults.

        C{None} if unapplicable or unable to retrieve.

    @type firstChance: None or bool
    @ivar firstChance:
        C{True} for first chance exceptions, C{False} for second chance.

        C{None} if unapplicable or unable to retrieve.

    @type isOurBreakpoint: bool
    @ivar isOurBreakpoint:
        C{True} for breakpoints defined by the L{Debug} class,
        C{False} otherwise.

        C{None} if unapplicable.

    @type isSystemBreakpoint: bool
    @ivar isSystemBreakpoint:
        C{True} for known system-defined breakpoints,
        C{False} otherwise.

        C{None} if unapplicable.

    @type modFileName: None or str
    @ivar modFileName: File name of module where the program counter points to.

        C{None} or invalid if unapplicable or unable to retrieve.

    @type lpBaseOfDll: None or int
    @ivar lpBaseOfDll: Base of module where the program counter points to.

        C{None} if unapplicable or unable to retrieve.

    @type stackTrace: None or tuple of tuple( int, int, str )
    @ivar stackTrace:
        Stack trace of the current thread as a tuple of
        ( frame pointer, return address, module filename ).

        C{None} or empty if unapplicable or unable to retrieve.

    @type stackTracePretty: None or tuple of tuple( int, str )
    @ivar stackTracePretty:
        Stack trace of the current thread as a tuple of
        ( frame pointer, return location ).

        C{None} or empty if unapplicable or unable to retrieve.

    @type stackTracePC: None or tuple( int... )
    @ivar stackTracePC: Tuple of return addresses in the stack trace.

        C{None} or empty if unapplicable or unable to retrieve.

    @type stackTraceLabels: None or tuple( str... )
    @ivar stackTraceLabels:
        Tuple of labels pointing to the return addresses in the stack trace.

        C{None} or empty if unapplicable or unable to retrieve.

    @type stackRange: tuple( int, int )
    @ivar stackRange:
        Stack beginning and end pointers, in memory addresses order.

        C{None} if unapplicable or unable to retrieve.

    @type stackFrame: None or str
    @ivar stackFrame: Data pointed to by the stack pointer.

        C{None} or empty if unapplicable or unable to retrieve.

    @type stackPeek: None or dict( int S{->} str )
    @ivar stackPeek: Dictionary mapping stack offsets to the data they point to.

        C{None} or empty if unapplicable or unable to retrieve.

    @type faultCode: None or str
    @ivar faultCode: Data pointed to by the program counter.

        C{None} or empty if unapplicable or unable to retrieve.

    @type faultMem: None or str
    @ivar faultMem: Data pointed to by the exception address.

        C{None} or empty if unapplicable or unable to retrieve.

    @type faultPeek: None or dict( intS{->} str )
    @ivar faultPeek: Dictionary mapping guessed pointers at L{faultMem} to the data they point to.

        C{None} or empty if unapplicable or unable to retrieve.

    @type faultDisasm: None or tuple of tuple( long, int, str, str )
    @ivar faultDisasm: Dissassembly around the program counter.

        C{None} or empty if unapplicable or unable to retrieve.

    @type memoryMap: None or list of L{win32.MemoryBasicInformation} objects.
    @ivar memoryMap: Memory snapshot of the program. May contain the actual
        data from the entire process memory if requested.
        See L{fetch_extra_data} for more details.

        C{None} or empty if unapplicable or unable to retrieve.
    """

    def __init__(self, event):
        """
        @type  event: L{Event}
        @param event: Event object for crash.
        """

        # First of all, take the timestamp.
        self.timeStamp          = time.time()

        # Notes are initially empty.
        self.notes              = list()

        # Get the process and thread, but dont't store them in the DB.
        process                 = event.get_process()
        thread                  = event.get_thread()

        # The following properties are always retrieved for all events.
        self.eventCode          = event.get_code()
        self.eventName          = event.get_event_name()
        self.pid                = event.get_pid()
        self.tid                = event.get_tid()
        self.registers          = dict(thread.get_context())
        self.labelPC            = process.get_label_at_address(self.pc)

        # The following properties are only retrieved for some events.
        self.registersPeek      = None
        self.debugString        = None
        self.modFileName        = None
        self.lpBaseOfDll        = None
        self.exceptionCode      = None
        self.exceptionName      = None
        self.exceptionDescription = None
        self.exceptionAddress   = None
        self.exceptionLabel     = None
        self.firstChance        = None
        self.faultType          = None
        self.faultAddress       = None
        self.faultLabel         = None
        self.isOurBreakpoint    = None
        self.isSystemBreakpoint = None
        self.stackTrace         = None
        self.stackTracePC       = None
        self.stackTraceLabels   = None
        self.stackTracePretty   = None
        self.stackRange         = None
        self.stackFrame         = None
        self.stackPeek          = None
        self.faultCode          = None
        self.faultMem           = None
        self.faultPeek          = None
        self.faultDisasm        = None
        self.memoryMap          = None

        # Get information for debug string events.
        if self.eventCode == win32.OUTPUT_DEBUG_STRING_EVENT:
            self.debugString = event.get_debug_string()

        # Get information for module load and unload events.
        # For create and exit process events, get the information
        # for the main module.
        elif self.eventCode in (win32.CREATE_PROCESS_DEBUG_EVENT,
                                win32.EXIT_PROCESS_DEBUG_EVENT,
                                win32.LOAD_DLL_DEBUG_EVENT,
                                win32.UNLOAD_DLL_DEBUG_EVENT):
            aModule = event.get_module()
            self.modFileName = event.get_filename()
            if not self.modFileName:
                self.modFileName = aModule.get_filename()
            self.lpBaseOfDll = event.get_module_base()
            if not self.lpBaseOfDll:
                self.lpBaseOfDll = aModule.get_base()

        # Get some information for exception events.
        # To get the remaining information call fetch_extra_data().
        elif self.eventCode == win32.EXCEPTION_DEBUG_EVENT:

            # Exception information.
            self.exceptionCode          = event.get_exception_code()
            self.exceptionName          = event.get_exception_name()
            self.exceptionDescription   = event.get_exception_description()
            self.exceptionAddress       = event.get_exception_address()
            self.firstChance            = event.is_first_chance()
            self.exceptionLabel         = process.get_label_at_address(
                                                         self.exceptionAddress)
            if self.exceptionCode in (win32.EXCEPTION_ACCESS_VIOLATION,
                                      win32.EXCEPTION_GUARD_PAGE,
                                      win32.EXCEPTION_IN_PAGE_ERROR):
                self.faultType    = event.get_fault_type()
                self.faultAddress = event.get_fault_address()
                self.faultLabel   = process.get_label_at_address(
                                                            self.faultAddress)
            elif self.exceptionCode in (win32.EXCEPTION_BREAKPOINT,
                                        win32.EXCEPTION_SINGLE_STEP):
                self.isOurBreakpoint = hasattr(event, 'breakpoint') \
                                       and event.breakpoint
                self.isSystemBreakpoint = \
                    process.is_system_defined_breakpoint(self.exceptionAddress)

            # Stack trace.
            try:
                self.stackTracePretty = thread.get_stack_trace_with_labels()
            except Exception, e:
                pass
            try:
                self.stackTrace     = thread.get_stack_trace()
                stackTracePC        = [ ra for (_,ra,_) in self.stackTrace ]
                self.stackTracePC   = tuple(stackTracePC)
                stackTraceLabels    = [ process.get_label_at_address(ra) \
                                             for ra in self.stackTracePC ]
                self.stackTraceLabels = tuple(stackTraceLabels)
            except Exception, e:
                pass

    def fetch_extra_data(self, event, takeMemorySnapshot = 0):
        """
        Fetch extra data from the L{Event} object.

        @note: This is only needed for exceptions. Since this method may take
            a little longer to run, it's best to call it only after you've
            determined the crash is interesting and you want to save it.

        @type  event: L{Event}
        @param event: Event object for crash.

        @type  takeMemorySnapshot: int
        @param takeMemorySnapshot:
            Memory snapshot behavior:
             - C{0} to take no memory information (default).
             - C{1} to take only the memory map.
               See L{Process.get_memory_map}.
             - C{2} to take a full memory snapshot.
               See L{Process.take_memory_snapshot}.
             - C{3} to take a full memory snapshot generator.
               See L{Process.generate_memory_snapshot}.
        """

        # Get the process and thread, but dont't store them in the DB.
        process                 = event.get_process()
        thread                  = event.get_thread()

        # Get some information for exception events.
        if self.eventCode == win32.EXCEPTION_DEBUG_EVENT:

            # Data pointed to by registers.
            self.registersPeek = thread.peek_pointers_in_registers()

            # Module that raised the exception.
            aModule = process.get_module_at_address(self.pc)
            if aModule is not None:
                self.modFileName = aModule.get_filename()
                self.lpBaseOfDll = aModule.get_base()

            # Contents of the stack frame.
            try:
                self.stackRange = thread.get_stack_range()
            except Exception, e:
                pass
            try:
                self.stackFrame = thread.get_stack_frame()
                stackFrame = self.stackFrame
            except Exception, e:
                self.stackFrame = thread.peek_stack_data()
                stackFrame = self.stackFrame[:64]
            if stackFrame:
                self.stackPeek = process.peek_pointers_in_data(stackFrame)

            # Code that raised the exception.
            self.faultCode   = thread.peek_code_bytes()
            try:
                self.faultDisasm = thread.disassemble_around_pc(32)
            except Exception, e:
                pass

            # For memory related exceptions, get the memory contents
            # of the location that caused the exception to be raised.
            if self.pc != self.exceptionAddress and self.exceptionCode in (
                        win32.EXCEPTION_ACCESS_VIOLATION,
                        win32.EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
                        win32.EXCEPTION_DATATYPE_MISALIGNMENT,
                        win32.EXCEPTION_IN_PAGE_ERROR,
                        win32.EXCEPTION_STACK_OVERFLOW,
                        win32.EXCEPTION_GUARD_PAGE,
                        ):
                self.faultMem = process.peek(self.exceptionAddress, 64)
                if self.faultMem:
                    self.faultPeek = process.peek_pointers_in_data(self.faultMem)

            # Take a snapshot of the process memory. Additionally get the
            # memory contents if requested.
            if takeMemorySnapshot == 1:
                self.memoryMap = process.get_memory_map()
                mappedFilenames = process.get_mapped_filenames(self.memoryMap)
                for mbi in self.memoryMap:
                    mbi.filename = mappedFilenames.get(mbi.BaseAddress, None)
                    mbi.content  = None
            elif takeMemorySnapshot == 2:
                self.memoryMap = process.take_memory_snapshot()
            elif takeMemorySnapshot == 3:
                self.memoryMap = process.generate_memory_snapshot()

    @property
    def pc(self):
        """
        Value of the program counter register.

        @rtype:  int
        """
        try:
            return self.registers['Eip']        # i386
        except KeyError:
            return self.registers['Rip']        # amd64

    @property
    def sp(self):
        """
        Value of the stack pointer register.

        @rtype:  int
        """
        try:
            return self.registers['Esp']        # i386
        except KeyError:
            return self.registers['Rsp']        # amd64

    @property
    def fp(self):
        """
        Value of the frame pointer register.

        @rtype:  int
        """
        try:
            return self.registers['Ebp']        # i386
        except KeyError:
            return self.registers['Rbp']        # amd64

    def __str__(self):
        return self.fullReport()

    def key(self):
        """
        Generates an approximately unique key for the Crash object.

        This key can be used as an heuristic to determine if two crashes were
        caused by the same software error. Ideally it should be treated as an
        opaque object.

        @see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/CrashKey}

        @rtype:  (opaque)
        @return: Crash unique key.
        """
        if self.labelPC:
            eip = self.labelPC
        else:
            eip = self.pc
        if self.stackTraceLabels:
            trace = self.stackTraceLabels
        else:
            trace = self.stackTracePC
        return  (
                self.eventCode,
                self.exceptionCode,
                eip,
                trace,
                self.debugString,
                )

    def isExploitable(self):
        """
        Guess how likely is it that the bug causing the crash can be leveraged
        into an exploitable vulnerability.

        @note: Don't take this as an equivalent of a real exploitability
            analysis, that can only be done by a human being! This is only
            a guideline, useful for example to sort crashes - placing the most
            interesting ones at the top.

        @see: The heuristics are similar to those of the B{!exploitable}
            extension for I{WinDBG}, which can be downloaded from here:

            U{http://www.codeplex.com/msecdbg}

        @rtype: tuple( str, str )
        @return: The first element of the tuple is the result of the analysis,
            being one of the following:

             - Not an exception
             - Not exploitable
             - Not likely exploitable
             - Unknown
             - Probably exploitable
             - Exploitable

            The second element of the tuple is a code to identify the matched
            heuristic rule.

            The second element of the tuple is a description string of the
            reason behind the result.
        """

        # Terminal rules

        if self.eventCode != win32.EXCEPTION_DEBUG_EVENT:
            return ("Not an exception", "NotAnException", "The event is not an exception.")

        if self.stackRange and self.pc is not None and self.stackRange[0] <= self.pc < self.stackRange[1]:
            return ("Exploitable", "StackCodeExecution", "Code execution from the stack is considered exploitable.")

        # This rule is NOT from !exploitable
        if self.stackRange and self.sp is not None and not (self.stackRange[0] <= self.sp < self.stackRange[1]):
            return ("Exploitable", "StackPointerCorruption", "Stack pointer corruption is considered exploitable.")

        # XXX add rule to check if code is in writeable memory

        if self.exceptionCode == win32.EXCEPTION_ILLEGAL_INSTRUCTION:
            return ("Exploitable", "IllegalInstruction", "An illegal instruction exception indicates that the attacker controls execution flow.")

        if self.exceptionCode == win32.EXCEPTION_PRIV_INSTRUCTION:
            return ("Exploitable", "PrivilegedInstruction", "A privileged instruction exception indicates that the attacker controls execution flow.")

        if self.exceptionCode == win32.EXCEPTION_GUARD_PAGE:
            return ("Exploitable", "GuardPage", "A guard page violation indicates a stack overflow has occured, and the stack of another thread was reached (possibly the overflow length is not controlled by the attacker).")

        if self.exceptionCode == win32.STATUS_STACK_BUFFER_OVERRUN:
            return ("Exploitable", "GSViolation", "An overrun of a protected stack buffer has been detected. This is considered exploitable, and must be fixed.")

        if self.exceptionCode == win32.STATUS_HEAP_CORRUPTION:
            return ("Exploitable", "HeapCorruption", "Heap Corruption has been detected. This is considered exploitable, and must be fixed.")

        if self.exceptionCode == win32.EXCEPTION_ACCESS_VIOLATION:
            nearNull      = self.faultAddress is None or MemoryAddresses.align_address_to_page_start(self.faultAddress) == win32.NULL
            controlFlow   = self.__is_control_flow()
            blockDataMove = self.__is_block_data_move()
            if self.faultType == win32.EXCEPTION_EXECUTE_FAULT:
                if nearNull:
                    return ("Probably exploitable", "DEPViolation", "User mode DEP access violations are probably exploitable if near NULL.")
                else:
                    return ("Exploitable", "DEPViolation", "User mode DEP access violations are exploitable.")
            elif self.faultType == win32.EXCEPTION_WRITE_FAULT:
                if nearNull:
                    return ("Probably exploitable", "WriteAV", "User mode write access violations that are near NULL are probably exploitable.")
                else:
                    return ("Exploitable", "WriteAV", "User mode write access violations that are not near NULL are exploitable.")
            elif self.faultType == win32.EXCEPTION_READ_FAULT:
                if self.faultAddress == self.pc:
                    if nearNull:
                        return ("Probably exploitable", "ReadAVonIP", "Access violations at the instruction pointer are probably exploitable if near NULL.")
                    else:
                        return ("Exploitable", "ReadAVonIP", "Access violations at the instruction pointer are exploitable if not near NULL.")
                if controlFlow:
                    if nearNull:
                        return ("Probably exploitable", "ReadAVonControlFlow", "Access violations near null in control flow instructions are considered probably exploitable.")
                    else:
                        return ("Exploitable", "ReadAVonControlFlow", "Access violations not near null in control flow instructions are considered exploitable.")
                if blockDataMove:
                    return ("Probably exploitable", "ReadAVonBlockMove", "This is a read access violation in a block data move, and is therefore classified as probably exploitable.")

                # Rule: Tainted information used to control branch addresses is considered probably exploitable
                # Rule: Tainted information used to control the target of a later write is probably exploitable

        # Non terminal rules

        # XXX TODO maybe we should be returning a list of tuples instead?

        result = ("Unknown", "Unknown", "Exploitability unknown.")

        if self.exceptionCode == win32.EXCEPTION_ACCESS_VIOLATION:
            if self.faultType == win32.EXCEPTION_READ_FAULT:
                if nearNull:
                    result = ("Not likely exploitable", "ReadAVNearNull", "This is a user mode read access violation near null, and is probably not exploitable.")

        elif self.exceptionCode == win32.EXCEPTION_INT_DIVIDE_BY_ZERO:
            result = ("Not likely exploitable", "DivideByZero", "This is an integer divide by zero, and is probably not exploitable.")

        elif self.exceptionCode == win32.EXCEPTION_FLT_DIVIDE_BY_ZERO:
            result = ("Not likely exploitable", "DivideByZero", "This is a floating point divide by zero, and is probably not exploitable.")

        elif self.exceptionCode in (win32.EXCEPTION_BREAKPOINT, win32.STATUS_WX86_BREAKPOINT):
            result = ("Unknown", "Breakpoint", "While a breakpoint itself is probably not exploitable, it may also be an indication that an attacker is testing a target. In either case breakpoints should not exist in production code.")

        # Rule: If the stack contains unknown symbols in user mode, call that out
        # Rule: Tainted information used to control the source of a later block move unknown, but called out explicitly
        # Rule: Tainted information used as an argument to a function is an unknown risk, but called out explicitly
        # Rule: Tainted information used to control branch selection is an unknown risk, but called out explicitly

        return result

    def __is_control_flow(self):
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
        isControlFlow = False
        instruction = None
        if self.pc is not None and self.faultDisasm:
            for disasm in self.faultDisasm:
                if disasm[0] == self.pc:
                    instruction = disasm[2].lower().strip()
                    break
        if instruction:
            for x in control_flow_instructions:
                if x in instruction:
                    isControlFlow = True
                    break
        return isControlFlow

    def __is_block_data_move(self):
        block_data_move_instructions = ('movs', 'stos', 'lods')
        isBlockDataMove = False
        instruction = None
        if self.pc is not None and self.faultDisasm:
            for disasm in self.faultDisasm:
                if disasm[0] == self.pc:
                    instruction = disasm[2].lower().strip()
                    break
        if instruction:
            for x in block_data_move_instructions:
                if x in instruction:
                    isBlockDataMove = True
                    break
        return isBlockDataMove

    def briefReport(self):
        """
        @rtype:  str
        @return: Short description of the event.
        """
        if self.exceptionCode is not None:
            if self.exceptionCode == win32.EXCEPTION_BREAKPOINT:
                if self.isOurBreakpoint:
                    what = "Breakpoint hit"
                elif self.isSystemBreakpoint:
                    what = "System breakpoint hit"
                else:
                    what = "Assertion failed"
            elif self.exceptionDescription:
                what = self.exceptionDescription
            elif self.exceptionName:
                what = self.exceptionName
            else:
                what = "Exception %s" % HexDump.integer(self.exceptionCode)
            if self.firstChance:
                chance = 'first'
            else:
                chance = 'second'
            if self.exceptionLabel:
                where = self.exceptionLabel
            elif self.exceptionAddress:
                where = HexDump.address(self.exceptionAddress)
            elif self.labelPC:
                where = self.labelPC
            else:
                where = HexDump.address(self.pc)
            msg = "%s (%s chance) at %s" % (what, chance, where)
        elif self.debugString is not None:
            if self.labelPC:
                where = self.labelPC
            else:
                where = HexDump.address(self.pc)
            msg = "Debug string from %s: %r" % (where, self.debugString)
        else:
            if self.labelPC:
                where = self.labelPC
            else:
                where = HexDump.address(self.pc)
            msg = "%s (%s) at %s" % (
                                             self.eventName,
                                             HexDump.integer(self.eventCode),
                                             where
                                            )
        return msg

    def fullReport(self, bShowNotes = True):
        """
        @type  bShowNotes: bool
        @param bShowNotes: C{True} to show the user notes, C{False} otherwise.

        @rtype:  str
        @return: Long description of the event.
        """
        msg  = self.briefReport()
        msg += '\n'

        if win32.sizeof(win32.LPVOID) == 4:
            width = 16
        else:
            width = 8

        if self.eventCode == win32.EXCEPTION_DEBUG_EVENT:
            (exploitability, expcode, expdescription) = self.isExploitable()
            msg += '\nSecurity risk level: %s\n' % exploitability
            msg += '  %s\n' % expdescription

        if bShowNotes and self.notes:
            msg += '\nNotes:\n'
            msg += self.notesReport()

        if not self.labelPC:
            base = HexDump.address(self.lpBaseOfDll)
            if self.modFileName:
                fn   = PathOperations.pathname_to_filename(self.modFileName)
                msg += '\nRunning in %s (%s)\n' % (fn, base)
            else:
                msg += '\nRunning in module at %s\n' % base

        if self.registers:
            msg += '\nRegisters:\n'
            msg += CrashDump.dump_registers(self.registers)
            if self.registersPeek:
                msg += '\n'
                msg += CrashDump.dump_registers_peek(self.registers,
                                                     self.registersPeek,
                                                     width = width)

        if self.faultDisasm:
            msg += '\nCode disassembly:\n'
            msg += CrashDump.dump_code(self.faultDisasm, self.pc)

        if self.stackTrace:
            msg += '\nStack trace:\n'
            if self.stackTracePretty:
                msg += CrashDump.dump_stack_trace_with_labels(
                                                         self.stackTracePretty)
            else:
                msg += CrashDump.dump_stack_trace(self.stackTrace)

        if self.stackFrame:
            if self.stackPeek:
                msg += '\nStack pointers:\n'
                msg += CrashDump.dump_stack_peek(self.stackPeek, width = width)
            msg += '\nStack dump:\n'
            msg += HexDump.hexblock(self.stackFrame, self.sp, width = width)

        if self.faultCode and not self.modFileName:
            msg += '\nCode dump:\n'
            msg += HexDump.hexblock(self.faultCode, self.pc, width = width)

        if self.faultMem:
            if self.faultPeek:
                msg += '\nException address pointers:\n'
                msg += CrashDump.dump_data_peek(self.faultPeek,
                                                self.exceptionAddress,
                                                width = width)
            msg += '\nException address dump:\n'
            msg += HexDump.hexblock(self.faultMem, self.exceptionAddress,
                                    width = width)

        if self.memoryMap:
            msg += '\nMemory map:\n'
            mappedFileNames = dict()
            for mbi in self.memoryMap:
                if hasattr(mbi, 'filename') and mbi.filename:
                    mappedFileNames[mbi.BaseAddress] = mbi.filename
            msg += CrashDump.dump_memory_map(self.memoryMap, mappedFileNames)

        if not msg.endswith('\n\n'):
            if not msg.endswith('\n'):
                msg += '\n'
            msg += '\n'
        return msg

    def notesReport(self):
        """
        @rtype:  str
        @return: All notes, merged and formatted for a report.
        """
        msg = ''
        if self.notes:
            for n in self.notes:
                n = n.strip('\n')
                if '\n' in n:
                    n = n.strip('\n')
                    msg += ' * %s\n' % n.pop(0)
                    for x in n:
                        msg += '   %s\n' % x
                else:
                    msg += ' * %s\n' % n
        return msg

    def addNote(self, msg):
        """
        Add a note to the crash event.

        @type msg:  str
        @param msg: Note text.
        """
        self.notes.append(msg)

    def clearNotes(self):
        """
        Clear the notes of this crash event.
        """
        self.notes = list()

    def getNotes(self):
        """
        Get the list of notes of this crash event.

        @rtype:  list( str )
        @return: List of notes.
        """
        return self.notes

    def iterNotes(self):
        """
        Iterate the notes of this crash event.

        @rtype:  listiterator
        @return: Iterator of the list of notes.
        """
        return self.notes.__iter__()

    def hasNotes(self):
        """
        @rtype:  bool
        @return: C{True} if there are notes for this crash event.
        """
        return bool( self.notes )

#==============================================================================

class CrashContainer (object):
    """
    Manages a database of persistent Crash objects, trying to avoid duplicates.

    Uses a DBM database file for persistency.

    @see: L{Crash.key}
    """

    # The interface is meant to be similar to a Python set.
    # However it may not be necessary to implement all of the set methods.
    # Other methods like get, has_key, iterkeys and itervalues
    # are dictionary-like.

    class __CrashContainerIterator (object):
        """
        Iterator of Crash objects. Returned by L{CrashContainer.__iter__}.
        """

        def __init__(self, container):
            """
            @type  container: L{CrashContainer}
            @param container: Crash set to iterate.
            """
            # It's important to keep a reference to the CrashContainer,
            # rather than it's underlying database.
            # Otherwise the destructor of CrashContainer may close the
            # database while we're still iterating it.
            #
            # TODO: lock the database when iterating it.
            #
            self.__container = container
            self.__keys_iter = container.iterkeys()

        def next(self):
            """
            @rtype:  L{Crash}
            @return: A B{copy} of a Crash object in the L{CrashContainer}.
            @raise StopIteration: No more items left.
            """
            key  = self.__keys_iter.next()
            return self.__container.get(key)

    def __init__(self, filename = None, allowRepeatedKeys = False):
        """
        @type  filename: str
        @param filename: (Optional) File name for crash database.
            If no filename is specified, the container is volatile.

            Volatile containers are stored only in memory and
            destroyed when they go out of scope.
        """
##
##        @type  allowRepeatedKeys: bool
##        @param allowRepeatedKeys:
##            If C{True} all L{Crash} objects are stored.
##
##            If C{False} any L{Crash} object with the same key as a
##            previously existing object will be ignored.
        if allowRepeatedKeys:
            raise NotImplementedError
        self.__filename = filename
        if filename:
            global anydbm
            if not anydbm:
                import anydbm
            self.__db   = anydbm.open(filename, 'c')
            self.__keys = dict([ (self.__unmarshall_key(mk), mk) \
                                                  for mk in self.__db.keys() ])
        else:
            self.__db   = dict()
            self.__keys = dict()

    def __del__(self):
        try:
            if self.__filename:
                self.__db.close()
        except:
            pass

    def __contains__(self, crash):
        """
        @type  crash: L{Crash}
        @param crash: Crash object.

        @rtype:  bool
        @return: C{True} if the Crash object is in the container.
        """
        return self.__keys.has_key( crash.key() )

    def __iter__(self):
        """
        @see:    L{itervalues}
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} objects.
        """
        return self.itervalues()

    def __len__(self):
        """
        @rtype:  int
        @return: Count of L{Crash} elements in the container.
        """
        return len(self.__keys)

    def __bool__(self):
        """
        @rtype:  bool
        @return: C{False} if the container is empty.
        """
        return bool(self.__keys)

    def has_key(self, key):
        """
        @type  key: L{Crash} unique key.
        @param key: Key of the crash to get.

        @rtype:  bool
        @return: C{True} if a matching L{Crash} object is in the container.
        """
        return key in self.__keys

    def iterkeys(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} object keys.

        @see:     L{get}
        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        return self.__keys.iterkeys()

    def itervalues(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} objects.

        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        return self.__CrashContainerIterator(self)

    def add(self, crash):
        """
        Adds a new crash to the container.
        If the crash appears to be already known, it's ignored.

        @see: L{Crash.key}

        @type  crash: L{Crash}
        @param crash: Crash object to add.
        """
        if crash not in self:
            key  = crash.key()
            skey = self.__marshall_key(key)
            data = self.__marshall_value(crash)
            self.__db[skey]  = data
            self.__keys[key] = skey

    def remove(self, crash):
        """
        Removes a crash from the container.

        @type  crash: L{Crash}
        @param crash: Crash object to remove.
        """
        key  = crash.key()
        skey = self.__keys[key]
        del self.__db[skey]
        del self.__keys[key]

    def get(self, key):
        """
        Retrieves a crash from the container.

        @type  key: L{Crash} unique key.
        @param key: Key of the crash to get.

        @rtype:  L{Crash} object.
        @return: Crash matching the given key.

        @see:     L{iterkeys}
        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        skey  = self.__keys[key]
        data  = self.__db[skey]
        crash = self.__unmarshall_value(data)
        return crash

    def __marshall_key(self, key):
        """
        Marshalls a Crash key to be used in the database.

        @type  key: (opaque object)
        @param key: Key to convert.

        @rtype:  str
        @return: Converted key.
        """
        if key in self.__keys:
            return self.__keys[key]
        key = pickle.dumps(key, protocol = 0)
        return key

    def __unmarshall_key(self, key):
        """
        Unmarshalls a Crash key read from the database.

        @type  key: str
        @param key: Key to convert.

        @rtype:  (opaque object)
        @return: Converted key.
        """
        return pickle.loads(key)

    def __marshall_value(self, value):
        """
        Marshalls a Crash object to be used in the database.
        The C{memoryMap} member is B{NOT} stored here.

        @type  value: L{Crash}
        @param value: Object to convert.

        @rtype:  str
        @return: Converted object.
        """
        # XXX
        # storing the memory map could be a performance problem!
        crash = value
        memoryMap = crash.memoryMap
        try:
            if memoryMap is not None:
                # convert the generator to a list
                crash.memoryMap = list(memoryMap)
            value = pickle.dumps(crash, protocol = pickle.HIGHEST_PROTOCOL)
        finally:
            crash.memoryMap = memoryMap
            del memoryMap
            del crash
        value = optimize(value)
        return zlib.compress(value, zlib.Z_BEST_COMPRESSION)

    def __unmarshall_value(self, value):
        """
        Unmarshalls a Crash object read from the database.

        @type  value: str
        @param value: Object to convert.

        @rtype:  L{Crash}
        @return: Converted object.
        """
        value = zlib.decompress(value)
        return pickle.loads(value)

#==============================================================================

class CrashTable (object):
    """
    Manages a database of persistent Crash objects, trying to avoid duplicates
    only when requested.

    Uses an SQLite database file for persistency.

    @see: L{Crash.key}
    """

    __table_definition = (
        "CREATE TABLE Crashes ("

        # Sequential row IDs.
        "id INTEGER PRIMARY KEY,"

        # These are the bare minimum columns required to store the objects.
        # The rest are just for convenience.
        "timeStamp TIMESTAMP,"              # float converted to GMT timestamp
        "key BLOB,"                         # the pickled key
        "pickle BLOB,"                      # the pickled object

        # Exploitability test.
        "isExploitable TEXT,"               # the result
        "isExploitableRule TEXT,"           # the matched rule

        # Event description.
        "eventCode INTEGER,"
        "pid INTEGER,"
        "tid INTEGER,"
        "pc INTEGER,"
        "sp INTEGER,"
        "fp INTEGER,"
        "labelPC TEXT,"

        # Exception description.
        "exceptionCode INTEGER,"
        "exceptionAddress INTEGER,"
        "exceptionLabel TEXT,"
        "firstChance INTEGER,"              # 0 or 1
        "faultType INTEGER,"
        "faultAddress INTEGER,"
        "faultLabel TEXT,"
        "faultDisasm TEXT,"                 # dumped
        "stackTrace TEXT,"                  # dumped stackTracePretty

        # Additional notes.
        "notes TEXT"                        # joined
        ")"
    )
    __insert_row = (
        "INSERT INTO Crashes VALUES (null%s)"
        % (',?' * (len(__table_definition.split(',')) - 1))
    )

    __select_pickle = "SELECT pickle FROM Crashes"
    __select_key    = "SELECT key FROM Crashes"
    __select_count  = "SELECT COUNT(*) FROM Crashes"

    __memory_table_definition = (
        "CREATE TABLE Memory ("
        "id INTEGER PRIMARY KEY,"       # Sequential row IDs.
        "Crash INTEGER,"                # Row ID in the Crashes table.
        "Address INTEGER,"              # Value of mbi.BaseAddress.
        "Size INTEGER,"                 # Value of mbi.RegionSize.
        "State TEXT,"                   # Value of mbi.State.
        "Access TEXT,"                  # Value of mbi.Protect.
        "Type TEXT,"                    # Value of mbi.Type.
        "File TEXT,"                    # Value of mbi.filename.
        "Data BLOB"                     # Value of mbi.content (compressed?).
        ")"
    )
    __memory_insert_row = (
        "INSERT INTO Memory VALUES "
        "(null, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def __get_row_values(self, crash):
        timeStamp           = time.asctime( time.gmtime( crash.timeStamp ) )
        key                 = self.__marshall_key(crash.key())
        pickle              = self.__marshall_value(crash)
        isExploitable, isExploitableRule, _ = crash.isExploitable()
        eventCode           = crash.eventCode
        pid                 = crash.pid
        tid                 = crash.tid
        pc                  = crash.pc
        sp                  = crash.sp
        fp                  = crash.fp
        labelPC             = crash.labelPC
        exceptionCode       = crash.exceptionCode
        exceptionAddress    = crash.exceptionAddress
        exceptionLabel      = crash.exceptionLabel
        firstChance         = crash.firstChance # int(bool(crash.firstChance))
        faultType           = crash.faultType
        faultAddress        = crash.faultAddress
        faultLabel          = crash.faultLabel
        faultDisasm         = CrashDump.dump_code(crash.faultDisasm, crash.pc)
        stackTrace          = CrashDump.dump_stack_trace_with_labels(
                                                        crash.stackTracePretty)
        notes               = crash.notesReport()
        return (
            timeStamp,
            key,
            pickle,
            isExploitable,
            isExploitableRule,
            eventCode,
            pid,
            tid,
            pc,
            sp,
            fp,
            labelPC,
            exceptionCode,
            exceptionAddress,
            exceptionLabel,
            firstChance,
            faultType,
            faultAddress,
            faultLabel,
            faultDisasm,
            stackTrace,
            notes,
        )

    def __memory_get_row_values(self, CrashID, mbi):

        # State (free or allocated).
        if   mbi.State == win32.MEM_RESERVE:
            State   = "Reserved"
        elif mbi.State == win32.MEM_COMMIT:
            State   = "Commited"
        elif mbi.State == win32.MEM_FREE:
            State   = "Free"
        else:
            State   = "Unknown"

        # Page protection bits (R/W/X/G).
        if mbi.State != win32.MEM_COMMIT:
            Protect = ""
        else:
            if   mbi.Protect & win32.PAGE_NOACCESS:
                Protect = "--- "
            elif mbi.Protect & win32.PAGE_READONLY:
                Protect = "R-- "
            elif mbi.Protect & win32.PAGE_READWRITE:
                Protect = "RW- "
            elif mbi.Protect & win32.PAGE_WRITECOPY:
                Protect = "RC- "
            elif mbi.Protect & win32.PAGE_EXECUTE:
                Protect = "--X "
            elif mbi.Protect & win32.PAGE_EXECUTE_READ:
                Protect = "R-- "
            elif mbi.Protect & win32.PAGE_EXECUTE_READWRITE:
                Protect = "RW- "
            elif mbi.Protect & win32.PAGE_EXECUTE_WRITECOPY:
                Protect = "RCX "
            else:
                Protect = "??? "
            if   mbi.Protect & win32.PAGE_GUARD:
                Protect += "G"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_NOCACHE:
                Protect += "N"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_WRITECOMBINE:
                Protect += "W"
            else:
                Protect += "-"

        # Type (file mapping, executable image, or private memory).
        if   mbi.Type == win32.MEM_IMAGE:
            Type    = "Image"
        elif mbi.Type == win32.MEM_MAPPED:
            Type    = "Mapped"
        elif mbi.Type == win32.MEM_PRIVATE:
            Type    = "Private"
        elif mbi.Type == 0:
            Type    = ""
        else:
            Type    = "Unknown"

        # Memory contents.
        content = mbi.content
        if not content:
            content = ''
        else:
##            content = zlib.compress(content, zlib.Z_BEST_COMPRESSION)
            pass
        content = sqlite.Binary(content)

        # Return a tuple to pass to Cursor.execute().
        return (
            CrashID,
            mbi.BaseAddress,
            mbi.RegionSize,
            State,
            Protect,
            Type,
            mbi.filename,
            content,
        )

    def __init__(self, location = None, allowRepeatedKeys = True):
        """
        @type  location: str
        @param location: (Optional) Location of the crash database.
            If no location is specified, the container is volatile.

            If the location is a filename, it's an SQLite database file.

            Volatile containers are stored only in memory and
            destroyed when they go out of scope.

        @type  allowRepeatedKeys: bool
        @param allowRepeatedKeys:
            If C{True} all L{Crash} objects are stored.

            If C{False} any L{Crash} object with the same key as a
            previously existing object will be ignored.
        """

        # Import sqlite if needed.
        global sqlite
        if sqlite is None:
            try:
                import sqlite3 as sqlite
            except ImportError:
                from pysqlite2 import dbapi2 as sqlite

        # If no location is given store the database in memory.
        if not location:
            location = ':memory:'
        self.__location = location

        # Connect to the database and get a cursor.
        self.__db       = sqlite.connect(self.__location)
        self.__cursor   = self.__db.cursor()

        # Create the tables if needed.
        try:
            self.__cursor.execute(self.__table_definition)
            self.__cursor.execute(self.__memory_table_definition)
            self.__db.commit()
        except Exception:
            pass

        # Populate the cache of existing keys.
        self.__allowRepeatedKeys = allowRepeatedKeys
        self.__keys = dict()
        self.__cursor.execute(self.__select_key)
        for row in self.__cursor:
            marshalled_key   = row[0]
            unmarshalled_key = self.__unmarshall_key(marshalled_key)
            self.__keys[unmarshalled_key] = marshalled_key

        # Get the number of crashes stored in the database.
        self.__cursor.execute(self.__select_count)
        count = 0
        for row in self.__cursor:
            count = long(row[0])
        self.__count = count

    def add(self, crash):
        """
        Adds a new crash to the container.

        @note:
            When the C{allowRepeatedKeys} parameter of the constructor
            is set to C{False}, duplicated crashes are ignored.

        @see: L{Crash.key}

        @type  crash: L{Crash}
        @param crash: Crash object to add.
        """

        # Add the key to the keys cache.
        # Filter out by key if requested.
        key = crash.key()
        if self.__allowRepeatedKeys or key not in self.__keys:
            self.__keys[key] = self.__marshall_key(key)

            # Insert the row into the table.
            row_values = self.__get_row_values(crash)
            self.__cursor.execute(self.__insert_row, row_values)

            # Save the memory snapshot, if any.
            if hasattr(crash, 'memoryMap') and crash.memoryMap:
                cid = self.__cursor.lastrowid
                for mbi in crash.memoryMap:
                    row_values = self.__memory_get_row_values(cid, mbi)
                    self.__cursor.execute(self.__memory_insert_row, row_values)

            # Commit the changes to the database.
            self.__db.commit()

            # Increment the counter of crashes.
            self.__count += 1

    def __iter__(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} objects.
        """
        self.__cursor.execute(self.__select_pickle)
        for row in self.__cursor:
            crash = row[0]
            crash = self.__unmarshall_value(crash)
            yield crash

    def __contains__(self, crash):
        """
        @type  crash: L{Crash}
        @param crash: Crash object.

        @rtype:  bool
        @return: C{True} if the Crash object is in the container.
        """
        return self.__keys.has_key( crash.key() )

    def __len__(self):
        """
        @rtype:  int
        @return: Count of L{Crash} elements in the container.
        """
        return self.__count

    def __bool__(self):
        """
        @rtype:  bool
        @return: C{False} if the container is empty.
        """
        # XXX HACK
        # Check if the keys cache is empty instead of querying the database.
        return bool(self.__keys)

    def __marshall_key(self, key):
        """
        Marshalls a Crash key to be used in the database.

        @type  key: (opaque object)
        @param key: Key to convert.

        @rtype:  BLOB
        @return: Converted key.
        """
        if key in self.__keys:
            return self.__keys[key]
        key = pickle.dumps(key, protocol = pickle.HIGHEST_PROTOCOL)
        key = optimize(key)
        key = sqlite.Binary(key)
        return key

    def __unmarshall_key(self, key):
        """
        Unmarshalls a Crash key read from the database.

        @type  key: str
        @param key: Key to convert.

        @rtype:  (opaque object)
        @return: Converted key.
        """
        key = str(key)
        key = pickle.loads(key)
        return key

    def __marshall_value(self, value):
        """
        Marshalls a Crash object to be used in the database.
        The C{memoryMap} member is B{NOT} stored here.

        @type  value: L{Crash}
        @param value: Object to convert.

        @rtype:  BLOB
        @return: Converted object.
        """
        # XXX TODO
        # maybe the memory map can be stored, if the raw data is stripped first
        crash = value
        memoryMap = crash.memoryMap
        try:
            crash.memoryMap = None
            value = pickle.dumps(crash, protocol = pickle.HIGHEST_PROTOCOL)
        finally:
            crash.memoryMap = memoryMap
            del memoryMap
            del crash
        value = optimize(value)
        value = zlib.compress(value, zlib.Z_BEST_COMPRESSION)
        value = sqlite.Binary(value)
        return value

    def __unmarshall_value(self, value):
        """
        Unmarshalls a Crash object read from the database.

        @type  value: str
        @param value: Object to convert.

        @rtype:  L{Crash}
        @return: Converted object.
        """
        value = str(value)
        value = zlib.decompress(value)
        value = pickle.loads(value)
        return value

#==============================================================================

class VolatileCrashContainer(CrashContainer):
    """
    Manages a database of volatile Crash objects,
    trying to avoid duplicates if requested.

    @see: L{Crash.key}
    """

    def __init__(self, allowRepeatedKeys = True):
        """
        Volatile containers are stored only in memory and
        destroyed when they go out of scope.

        @type  allowRepeatedKeys: bool
        @param allowRepeatedKeys:
            If C{True} all L{Crash} objects are stored.

            If C{False} any L{Crash} object with the same key as a
            previously existing object will be ignored.
        """
        super(VolatileCrashContainer, self).__init__()
        self.__allowRepeatedKeys = allowRepeatedKeys
        self.__dict = dict()
        self.__set  = set()

    def __contains__(self, crash):
        """
        @type  crash: L{Crash}
        @param crash: Crash object.

        @rtype:  bool
        @return: C{True} if the Crash object is in the container.
        """
        return self.__dict.has_key( crash.key() )

    def __iter__(self):
        """
        @see:    L{itervalues}
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} objects.
        """
        return self.itervalues()

    def __len__(self):
        """
        @rtype:  int
        @return: Count of L{Crash} elements in the container.
        """
        return len(self.__set)

    def __bool__(self):
        """
        @rtype:  bool
        @return: C{False} if the container is empty.
        """
        return bool(len(self))

    def add(self, crash):
        """
        Adds a new crash to the container.

        @note:
            When the C{allowRepeatedKeys} parameter of the constructor
            is set to C{False}, duplicated crashes are ignored.

        @see: L{Crash.key}

        @type  crash: L{Crash}
        @param crash: Crash object to add.
        """
        key = crash.key()
        if self.__allowRepeatedKeys or key not in self.__dict:
            self.__dict[key] = crash
            self.__set.add(crash)

    def has_key(self, key):
        """
        @type  key: L{Crash} unique key.
        @param key: Key of the crash to get.

        @rtype:  bool
        @return: C{True} if a matching L{Crash} object is in the container.
        """
        return self.__dict.has_key(key)

    def iterkeys(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} object keys.

        @see:     L{get}
        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        return self.__dict.iterkeys()

    def itervalues(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} objects.

        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        return iter(self.__set)

#==============================================================================

class DummyCrashContainer(CrashContainer):
    """
    Fakes a database of volatile Crash objects,
    trying to mimic part of it's interface, but
    doesn't actually store anything.

    @see: L{Crash.key}
    """

    def __init__(self, allowRepeatedKeys = True):
        """
        Fake containers don't store L{Crash} objects, but they implement the
        interface properly.

        @type  allowRepeatedKeys: bool
        @param allowRepeatedKeys:
            If C{True} the len() of the container returns the total number
            of L{Crash} objects added.

            If C{False} the len() of the container returns the total number
            of L{Crash} objects keys added.
        """
        super(DummyCrashContainer, self).__init__()
        self.__keys  = set()
        self.__count = 0
        self.__allowRepeatedKeys = allowRepeatedKeys

    def __contains__(self, crash):
        """
        @type  crash: L{Crash}
        @param crash: Crash object.

        @rtype:  bool
        @return: C{True} if the Crash object is in the container.
        """
        return crash.key() in self.__keys

    def __len__(self):
        """
        @rtype:  int
        @return: Count of L{Crash} elements in the container.
        """
        if self.__allowRepeatedKeys:
            return self.__count
        return len(self.__keys)

    def __bool__(self):
        """
        @rtype:  bool
        @return: C{False} if the container is empty.
        """
        return bool(len(self))

    def add(self, crash):
        """
        Adds a new crash to the container.

        @note:
            When the C{allowRepeatedKeys} parameter of the constructor
            is set to C{False}, duplicated crashes are ignored.

        @see: L{Crash.key}

        @type  crash: L{Crash}
        @param crash: Crash object to add.
        """
        self.__keys.add( crash.key() )
        self.__count += 1

    def has_key(self, key):
        """
        @type  key: L{Crash} unique key.
        @param key: Key of the crash to get.

        @rtype:  bool
        @return: C{True} if a matching L{Crash} object is in the container.
        """
        return self.__dict.has_key(key)

    def iterkeys(self):
        """
        @rtype:  iterator
        @return: Iterator of the contained L{Crash} object keys.

        @see:     L{get}
        @warning: A B{copy} of each object is returned,
            so any changes made to them will be lost.

            To preserve changes do the following:
                1. Keep a reference to the object.
                2. Delete the object from the set.
                3. Modify the object and add it again.
        """
        return iter(self.__dict)
