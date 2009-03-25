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
Crash logger.
"""

__all__ =   [
                'Crash',
                'CrashContainer',
            ]

from textio import HexDump, CrashDump
import win32

import time
import zlib
import cPickle
import traceback

#==============================================================================

class Crash (object):
    """
    Represents a crash, bug, or another interesting event in the debugee.
    
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
    
    @type registersPeek: dict( str S{->} str )
    @ivar registersPeek: Dictionary mapping register names to the data they point to.
    
    @type debugString: str
    @ivar debugString: Debug string sent by the debugee.
    
    @type exceptionCode: int
    @ivar exceptionCode: Exception code as defined by the Win32 API.
    
    @type exceptionName: str
    @ivar exceptionName: Exception code user-friendly name.
    
    @type exceptionAddress: int
    @ivar exceptionAddress: Memory address where the exception occured.
    
    @type firstChance: bool
    @ivar firstChance: True for first chance exceptions, False for second chance.
    
    @type modFileName: str
    @ivar modFileName: File name of module where the program counter points to.
    
    @type lpBaseOfDll: int
    @ivar lpBaseOfDll: Base of module where the program counter points to.
    
    @type stackTrace: list( int, int, str )
    @ivar stackTrace: Stack trace of the current thread as a tuple of ( return address, frame pointer, module filename ).
    
    @type stackTracePC: tuple( int )
    @ivar stackTracePC: List of return addresses in the stack trace.
        Converted to tuple to make it hashable.
    
    @type stackFrame: str
    @ivar stackFrame: Data pointed to by the stack pointer.
    
    @type stackPeek: dict( int S{->} str )
    @ivar stackPeek: Dictionary mapping stack offsets to the data they point to.
    
    @type faultCode: str
    @ivar faultCode: Data pointed to by the program counter.
    
    @type faultMem: str
    @ivar faultMem: Data pointed to by the exception address.
    
    @type faultPeek: dict( intS{->} str )
    @ivar faultPeek: Dictionary mapping guessed pointers at L{faultMem} to the data they point to.
    
    @type faultDisasm: 
    @ivar faultDisasm: Dissassembly around the program counter.
    """

    def __init__(self, event):
        """
        @type  event: L{Event}
        @param event: Event object for crash.
        """

        self.timeStamp          = time.time()

        self.notes              = list()

        process                 = event.get_process()
        thread                  = event.get_thread()

        self.eventCode          = event.get_code()
        self.eventName          = event.get_event_name()
        self.pid                = event.get_pid()
        self.tid                = event.get_tid()
        self.registers          = event.get_thread().get_context()
        self.registersPeek      = thread.peek_pointers_in_registers()

        self.debugString        = None
        self.exceptionCode      = None
        self.exceptionName      = None
        self.exceptionAddress   = None
        self.firstChance        = None
        self.modFileName        = None
        self.lpBaseOfDll        = None
        self.stackTrace         = None
        self.stackTracePC       = None
        self.stackFrame         = None
        self.stackPeek          = None
        self.faultCode          = None
        self.faultMem           = None
        self.faultPeek          = None
        self.faultDisasm        = None

        if self.eventCode == win32.EXCEPTION_DEBUG_EVENT:
            self.exceptionCode          = event.get_exception_code()
            self.exceptionName          = event.get_exception_name()
            self.exceptionDescription   = event.get_exception_description()
            self.exceptionAddress       = event.get_exception_address()
            self.firstChance            = event.is_first_chance()

        elif self.eventCode == win32.OUTPUT_DEBUG_STRING_EVENT:
            self.debugString = event.get_debug_string()

        aModule = process.get_module_from_address(self.pc)
        if aModule is not None:
            self.modFileName = aModule.get_filename()
            self.lpBaseOfDll = aModule.get_base()

        self.stackTrace     = thread.get_stack_trace()
        stackTracePC        = [ ra for (fp, ra, lib) in self.stackTrace ]
        self.stackTracePC   = tuple(stackTracePC)   # now it's hashable

        try:
            self.stackFrame = thread.get_stack_frame()
            stackFrame = self.stackFrame
        except Exception, e:
            self.stackFrame = thread.get_stack_data()
            stackFrame = self.stackFrame[:64]
        if stackFrame:
            self.stackPeek = process.peek_pointers_in_data(stackFrame)

        self.faultCode = thread.get_code_bytes()

        self.faultDisasm = thread.disassemble_around_pc(32)

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
                self.faultPeek = process.peek_data(self.faultMem)

    @property
    def pc(self):
        """
        Value of the program counter register.
        
        @rtype:  int
        """
        return self.registers['Eip']

    @property
    def sp(self):
        """
        Value of the stack pointer register.
        
        @rtype:  int
        """
        return self.registers['Esp']

    @property
    def fp(self):
        """
        Value of the frame pointer register.
        
        @rtype:  int
        """
        return self.registers['Ebp']

    def __str__(self):
        return self.fullReport()

    def key(self):
        """
        Crash unique key.
        
        @see: U{http://code.google.com/p/python-winapp-dbg/wiki/CrashKey}
        
        @return: Crash unique key. Should be treated as an opaque object.
        """
        return  (
                    self.eventCode,
                    self.exceptionCode,
                    self.pc,
                    self.stackTracePC,
                    self.debugString,
                )

    def briefReport(self):
        """
        @rtype:  str
        @return: Short description of the event.
        """
        if self.exceptionCode is not None:
            if self.firstChance:
                chance_str = 'first'
            else:
                chance_str = 'second'
            msg = "%s (%s chance) at 0x%.8x" % (
                                                   self.exceptionDescription,
##                                                   self.exceptionName,
                                                   chance_str,
                                                   self.exceptionAddress
                                                  )
        elif self.debugString is not None:
            msg = "Debug string from 0x%.8x: %r" % (
                                                    self.pc,
                                                    self.debugString
                                                   )
        else:
            msg = "%s (0x%.8x) at 0x%.8x" % (
                                             self.eventName,
                                             self.eventCode,
                                             self.pc
                                            )
        return msg

    def fullReport(self):
        """
        @rtype:  str
        @return: Long description of the event.
        """
        msg  = self.briefReport()
        msg += '\n'

        if self.notes:
            msg += '\nNotes:\n'
            msg += self.notesReport()

        if self.modFileName:
            fn = self.modFileName
            if '\\' in fn:
                fn = fn[ fn.rfind('\\') + 1 : ]
            elif '/' in fn:
                fn = fn[ fn.rfind('/') + 1 : ]
            print 3
            msg += '\nRunning in %s (0x%.8x)\n' % (fn, self.lpBaseOfDll)

        if self.registers:
            msg += '\nRegisters:\n'
            msg += CrashDump.dump_registers(self.registers)
            if self.registersPeek:
                msg += '\n'
                msg += CrashDump.dump_registers_peek(self.registers,
                                                            self.registersPeek)

        if self.faultDisasm:
            msg += '\nCode disassembly:\n'
            msg += CrashDump.dump_code(self.faultDisasm, self.pc)

        if self.stackTrace:
            msg += '\nStack trace:\n'
            msg += CrashDump.dump_stack_trace(self.stackTrace)

        if self.stackFrame:
            if self.stackPeek:
                msg += '\nStack pointers:\n'
                msg += CrashDump.dump_stack_peek(self.stackPeek, self.sp)
            msg += '\nStack dump:\n'
            msg += HexDump.hexblock(self.stackFrame, self.sp)

        if self.faultCode:
            msg += '\nCode dump:\n'
            msg += HexDump.hexblock(self.faultCode, self.pc)

        if self.faultMem:
            if self.faultPeek:
                msg += '\nException address pointers:\n'
                msg += CrashDump.dump_data_peek(self.faultPeek,
                                                         self.exceptionAddress)
            msg += '\nException address dump:\n'
            msg += HexDump.hexblock(self.faultMem, self.exceptionAddress)

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
        @return: True if there are notes for this crash event.
        """
        return bool( self.notes )

#==============================================================================

# TODO
#
# It would be better to have a storage module, with classes to separate the
# crash dump logic from the storage itself. The current implementation using
# pickle and zlib could be moved there.
#
# Also we need a more efficient way to manage crashes, to avoid loading the
# entire crash dump file in memory. Zip files could be used for this, where
# each file name would be the key (ascii pickled) and the file contents would
# be the Crash object (binary pickled).

class CrashContainer (object):
    """
    Contains a set of Crash objects, trying to avoid duplicates.
    
    @see: L{Crash.key}
    """

    def __init__(self, filename = None):
        """
        @type  filename: str
        @param filename: (Optional)
           File name for crash container database to read.
           If no filename is specified, an empty container is created.
        """
        self.reset()
        if filename:
            self.load(filename)

    def __contains__(self, crash):
        return self.__container.has_key(crash.key())

    def __iter__(self):
        return self.__container.itervalues()

    def __len__(self):
        return len(self.__container)

    def __bool__(self):
        return bool(self.__container)

    def reset(self):
        """
        Remove all crashes from the container.
        """
        self.__container = {}

    def add(self, crash):
        """
        Add a new crash to the container.
        If the crash appears to be already known, it is ignored.
        
        @type crash:  L{Crash}
        @param crash: Crash object to add.
        """
        if crash not in self:
            self.__container[crash.key()] = crash

    def remove(self, crash):
        """
        Remove a crash from the container.
        
        @type crash:  L{Crash}
        @param crash: Crash object to remove.
        """
        del self.__container[crash.key()]

    def load(self, filename):
        """
        Load crashes from a crash dump file
        and merge them into the container.
        Existing crashes are not modified.
        
        @type  filename: str
        @param filename: File name for crash container database to read.
        """
        data = open(filename, 'rb').read()
        data = zlib.decompress(data)
        data = cPickle.loads(data)
        data.update(self.__container)
        self.__container = data

    def save(self, filename, protocol = cPickle.HIGHEST_PROTOCOL):
        """
        Save the crashes in a crash dump file.
        
        @type  filename: str
        @param filename: File name for crash container database to write.
        
        @type  protocol: int
        @param protocol: (Optional) Pickle protocol to use.
        """
        data = self.__container
        data = cPickle.dumps(data, protocol)
        data = zlib.compress(data, 9)
        open(filename, 'wb').write(data)
