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

"""
Crash logging module.
"""

__revision__ = "$Id$"

__all__ =   [
                # Object that represents a crash in the debugee.
                'Crash',

                # Container that can store Crash objects in a database.
                'CrashContainer',
            ]

from system import PathOperations
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

#==============================================================================

class Crash (object):
    """
    Represents a crash, bug, or another interesting event in the debugee.

    @group Key:
        key

    @group Report:
        briefReport, fullReport, notesReport

    @group Notes:
        addNote, getNotes, iterNotes, hasNotes, clearNotes

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

    @type exceptionAddress: None or int
    @ivar exceptionAddress: Memory address where the exception occured.

        C{None} if unapplicable or unable to retrieve.

    @type exceptionLabel: None or str
    @ivar exceptionLabel: Label pointing to the exception address.

        C{None} or invalid if unapplicable or unable to retrieve.

    @type firstChance: None or bool
    @ivar firstChance:
        C{True} for first chance exceptions, C{False} for second chance.

        C{None} if unapplicable or unable to retrieve.

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
        self.registers          = thread.get_context()
        self.labelPC            = process.get_label_at_address(self.pc)

        # The following properties are only retrieved for some events.
        self.registersPeek      = None
        self.debugString        = None
        self.exceptionCode      = None
        self.exceptionName      = None
        self.exceptionAddress   = None
        self.firstChance        = None
        self.modFileName        = None
        self.lpBaseOfDll        = None
        self.exceptionLabel     = None
        self.stackTrace         = None
        self.stackTracePC       = None
        self.stackTraceLabels   = None
        self.stackFrame         = None
        self.stackPeek          = None
        self.faultCode          = None
        self.faultMem           = None
        self.faultPeek          = None
        self.faultDisasm        = None

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

        # Get information for exception events.
        elif self.eventCode == win32.EXCEPTION_DEBUG_EVENT:

            # Exception information.
            self.exceptionCode          = event.get_exception_code()
            self.exceptionName          = event.get_exception_name()
            self.exceptionDescription   = event.get_exception_description()
            self.exceptionAddress       = event.get_exception_address()
            self.firstChance            = event.is_first_chance()
            self.exceptionLabel         = process.get_label_at_address(
                                                         self.exceptionAddress)

            # Data pointed to by registers.
            self.registersPeek = thread.peek_pointers_in_registers()

            # Module that raised the exception.
            aModule = process.get_module_at_address(self.pc)
            if aModule is not None:
                self.modFileName = aModule.get_filename()
                self.lpBaseOfDll = aModule.get_base()

            # Stack trace.
            self.stackTrace     = thread.get_stack_trace()
            self.stackTracePretty = thread.get_stack_trace_with_labels()
            stackTracePC        = [ ra for (fp, ra, lib) in self.stackTrace ]
            self.stackTracePC   = tuple(stackTracePC)
            stackTraceLabels    = [ process.get_label_at_address(ra) \
                                         for ra in self.stackTracePC ]
            self.stackTraceLabels = tuple(stackTraceLabels)

            # Contents of the stack frame.
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
            self.faultDisasm = thread.disassemble_around_pc(32)

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

    def briefReport(self):
        """
        @rtype:  str
        @return: Short description of the event.
        """
        if self.exceptionCode is not None:
            if self.exceptionDescription:
                what = self.exceptionDescription
            elif self.exceptionName:
                what = self.exceptionName
            else:
                what = "Exception 0x%.8x" % self.exceptionCode
            if self.firstChance:
                chance = 'first'
            else:
                chance = 'second'
            if self.exceptionLabel:
                where = self.exceptionLabel
            elif self.exceptionAddress:
                where = "0x%.8x" % self.exceptionAddress
            elif self.labelPC:
                where = self.labelPC
            else:
                where = "0x%.8x" % self.pc
            msg = "%s (%s chance) at %s" % (what, chance, where)
        elif self.debugString is not None:
            if self.labelPC:
                where = self.labelPC
            else:
                where = "0x%.8x" % self.pc
            msg = "Debug string from %s: %r" % (where, self.debugString)
        else:
            if self.labelPC:
                where = self.labelPC
            else:
                where = "0x%.8x" % self.pc
            msg = "%s (0x%.8x) at %s" % (
                                             self.eventName,
                                             self.eventCode,
                                             where
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

        if not self.labelPC:
            if self.modFileName:
                fn = PathOperations.pathname_to_filename(self.modFileName)
                msg += '\nRunning in %s (0x%.8x)\n' % (fn, self.lpBaseOfDll)
            else:
                msg += '\nRunning in module at 0x%.8x\n' % self.lpBaseOfDll

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
            if self.stackTracePretty:
                msg += CrashDump.dump_stack_trace_with_labels(
                                                         self.stackTracePretty)
            else:
                msg += CrashDump.dump_stack_trace(self.stackTrace)

        if self.stackFrame:
            if self.stackPeek:
                msg += '\nStack pointers:\n'
                msg += CrashDump.dump_stack_peek(self.stackPeek)
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
        @return: C{True} if there are notes for this crash event.
        """
        return bool( self.notes )

#==============================================================================

class CrashContainer (object):
    """
    Manages a database of persistent Crash objects, trying to avoid duplicates.

    @see: L{Crash.key}
    """

    # The interface is meant to be similar to a Python set.
    # However it may not be necessary to implement all of the set methods.
    # Other methods like get, has_key, iterkeys and itervalues
    # are dictionary-like.

    # TODO:
    # Lock the files for modifications by other processes.
    # Otherwise the database could be corrupted by opening it more than once.

    # FIXME:
    # The underlying database may encounter collisions.
    # Not much can be done about the keys (maybe change the pickle protocol?),
    # but the Crash objects could have a spurious public member set to any
    # value (for example it could be an incremental integer counter), to add
    # and change if a collision occurs.

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

    def __init__(self, filename = None):
        """
        @type  filename: str
        @param filename: (Optional) File name for crash database.
            If no filename is specified, the container is be volatile.

            Volatile containers are stored only in memory and
            destroyed when they go out of scope.
        """
        self.__filename = filename
        if filename:
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
        return crash.key() in self.__keys

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
        key = pickle.dumps(key, protocol = pickle.HIGHEST_PROTOCOL)
        key = optimize(key)
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

        @type  value: L{Crash}
        @param value: Object to convert.

        @rtype:  str
        @return: Converted object.
        """
        value = pickle.dumps(value, protocol = pickle.HIGHEST_PROTOCOL)
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
