#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
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
This submodule controls breakpoints logic. There are two layers to this API, a lower level and a higher level.
"""

__all__ = [
    # Base class for breakpoints
    "Breakpoint",
    # Breakpoint implementations
    "CodeBreakpoint",
    "PageBreakpoint",
    "HardwareBreakpoint",
    # Hooks and watches
    "HookFactory",
    "ApiHook",
    "BufferWatch",
    # Warnings
    "BreakpointWarning",
    "BreakpointCallbackWarning",
]

import ctypes
import traceback
import warnings

from . import win32
from .process import Process, Thread
from .textio import HexDump
from .util import IntelDebugRegister, MemoryAddresses

# ==============================================================================


class BreakpointWarning(UserWarning):
    """
    This warning is issued when a non-fatal error occurs that's related to
    breakpoints.
    """


class BreakpointCallbackWarning(RuntimeWarning):
    """
    This warning is issued when an uncaught exception was raised by a
    breakpoint's user-defined callback.
    """


# ==============================================================================


class Breakpoint:
    """
    Base class for breakpoints. Here's the breakpoints state machine.

    .. seealso:: :class:`CodeBreakpoint`, :class:`PageBreakpoint`, :class:`HardwareBreakpoint`

    :cvar DISABLED: *Disabled* -> Enabled, OneShot
    :type DISABLED: int
    :cvar ENABLED:  *Enabled*  -> *Running*, Disabled
    :type ENABLED:  int
    :cvar ONESHOT:  *OneShot*  -> *Disabled*
    :type ONESHOT:  int
    :cvar RUNNING:  *Running*  -> *Enabled*, Disabled
    :type RUNNING:  int
    :cvar stateNames: User-friendly names for each breakpoint state.
    :type stateNames: dict{int: str}
    :cvar typeName: User friendly breakpoint type string.
    :type typeName: str
    """

    # I don't think transitions Enabled <-> OneShot should be allowed... plus
    #  it would require special handling to avoid setting the same bp twice

    DISABLED = 0
    ENABLED = 1
    ONESHOT = 2
    RUNNING = 3

    # Breakpoint type constants.
    CODE_BREAKPOINT = 0
    HARDWARE_BREAKPOINT = 1
    PAGE_BREAKPOINT = 2

    typeName = "breakpoint"

    stateNames = {
        DISABLED: "disabled",
        ENABLED: "enabled",
        ONESHOT: "one shot",
        RUNNING: "running",
    }

    def __init__(self, address, size=1, condition=True, action=None):
        """
        Breakpoint object.

        :param int address: Memory address for breakpoint.
        :param int size: Size of breakpoint in bytes (defaults to 1).
        :param callable condition: Optional condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean (``True`` to dispatch the event,
            ``False`` otherwise).
        :param callable action: Optional action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.

            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object.
        """
        self.__address = address
        self.__size = size
        self.__state = self.DISABLED

        self.set_condition(condition)
        self.set_action(action)

    def __repr__(self):
        if self.is_disabled():
            state = "Disabled"
        else:
            state = "Active (%s)" % self.get_state_name()
        if self.is_conditional():
            condition = "conditional"
        else:
            condition = "unconditional"
        name = self.typeName
        size = self.get_size()
        if size == 1:
            address = HexDump.address(self.get_address())
        else:
            begin = self.get_address()
            end = begin + size
            begin = HexDump.address(begin)
            end = HexDump.address(end)
            address = "range %s-%s" % (begin, end)
        msg = "<%s %s %s at remote address %s>"
        msg = msg % (state, condition, name, address)
        return msg

    # ------------------------------------------------------------------------------

    def is_disabled(self):
        """
        :rtype:  bool
        :return: ``True`` if the breakpoint is in :attr:`DISABLED` state.
        """
        return self.get_state() == self.DISABLED

    def is_enabled(self):
        """
        :rtype:  bool
        :return: ``True`` if the breakpoint is in :attr:`ENABLED` state.
        """
        return self.get_state() == self.ENABLED

    def is_one_shot(self):
        """
        :rtype:  bool
        :return: ``True`` if the breakpoint is in :attr:`ONESHOT` state.
        """
        return self.get_state() == self.ONESHOT

    def is_running(self):
        """
        :rtype:  bool
        :return: ``True`` if the breakpoint is in :attr:`RUNNING` state.
        """
        return self.get_state() == self.RUNNING

    def is_here(self, address):
        """
        :rtype:  bool
        :return: ``True`` if the address is within the range of the breakpoint.
        """
        begin = self.get_address()
        end = begin + self.get_size()
        return begin <= address < end

    def get_address(self):
        """
        :rtype:  int
        :return: The target memory address for the breakpoint.
        """
        return self.__address

    def get_size(self):
        """
        :rtype:  int
        :return: Size of breakpoint in bytes.
        """
        return self.__size

    def get_span(self):
        """
        Get the range of memory addresses for this breakpoint.

        :rtype:  tuple( int, int )
        :return: Tuple containing the first and last memory addresses.
        """
        address = self.get_address()
        return (address, address + self.get_size() - 1)

    def get_state(self):
        """
        :rtype:  int
        :return: The current state of the breakpoint.
        """
        return self.__state

    def get_state_name(self):
        """
        :rtype:  str
        :return: The user-friendly name for the current state of the breakpoint.
        """
        return self.stateNames[self.get_state()]

    # ------------------------------------------------------------------------------

    def is_conditional(self):
        """
        Check if this is a conditional breakpoint.
        A breakpoint is conditional if a callback function was set.

        :rtype:  bool
        :return: ``True`` if this is a conditional breakpoint.
        """
        # Do not evaluate as boolean! Test for identity with True instead.
        return self.__condition is not True

    def is_unconditional(self):
        """
        :rtype:  bool
        :return: ``True`` if this is not a conditional breakpoint.
        """
        # Do not evaluate as boolean! Test for identity with True instead.
        return self.__condition is True

    def get_condition(self):
        """
        :rtype:  callable
        :return: The condition callback function. Returns ``True`` for unconditional breakpoints.
        """
        return self.__condition

    def set_condition(self, condition=True):
        """
        Set the condition callback function for this breakpoint.

        :param callable condition: Condition callback function.
        """
        if condition is None:
            condition = True
        if condition is not True and not callable(condition):
            msg = "Condition must be a callable object or the value True, "
            msg = msg + "got %s instead" % type(condition)
            raise TypeError(msg)
        self.__condition = condition

    def eval_condition(self, event):
        """
        Evaluate the condition callback for this breakpoint.

        :param event: Event that triggered this breakpoint.
        :type event: :class:`~winappdbg.event.Event`
        :rtype:  bool
        :return: ``True`` to dispatch the event, ``False`` otherwise.
        """
        condition = self.get_condition()
        if condition is True:  # shortcut for unconditional breakpoints
            return True
        if not callable(condition):
            msg = "Condition must be a callable object, got %s instead"
            raise TypeError(msg % type(condition))
        try:
            return bool(condition(event))
        except Exception:
            msg = "Breakpoint condition callback %s raised an exception"
            msg = msg % repr(condition)
            traceback.print_exc()
            warnings.warn(msg, BreakpointCallbackWarning)
            return False

    # ------------------------------------------------------------------------------

    def is_automatic(self):
        """
        :rtype:  bool
        :return: ``True`` if this breakpoint is automatic.
        """
        return self.__action is not None

    def is_interactive(self):
        """
        :rtype:  bool
        :return: ``True`` if this breakpoint is interactive.
        """
        return self.__action is None

    def get_action(self):
        """
        :rtype:  callable
        :return: The action callback function for this breakpoint.
        """
        return self.__action

    def set_action(self, action=None):
        """
        Set the action callback function for this breakpoint.

        :param callable action: Action callback function.
        """
        if action is not None and not callable(action):
            raise TypeError("Action must be a callable object or None")
        self.__action = action

    def run_action(self, event):
        """
        Run the action callback for this breakpoint.

        :param event: Event that triggered this breakpoint.
        :type event: :class:`~winappdbg.event.Event`
        """
        action = self.get_action()
        if action is not None:
            try:
                return bool(action(event))
            except Exception as e:
                msg = "Breakpoint action callback %r raised an exception: %s"
                msg = msg % (action, traceback.format_exc(e))
                warnings.warn(msg, BreakpointCallbackWarning)
                return False
        return True

    # ------------------------------------------------------------------------------

    def __bad_transition(self, state):
        oldState = self.stateNames[self.__state]
        newState = self.stateNames[state]
        msg = "Invalid state transition (%s -> %s) for breakpoint at address %s"
        msg = msg % (oldState, newState, HexDump.address(self.get_address()))
        raise AssertionError(msg)

    def disable(self, aProcess, aThread):
        """
        Disables a breakpoint.

        :param aProcess: Process that contains the breakpoint.
        :type aProcess: :class:`~winappdbg.process.Process`
        :param aThread: Current thread.
        :type aThread: :class:`~winappdbg.thread.Thread`
        :raises RuntimeError: The breakpoint was not in an active state.
        """
        if self.__state not in (self.ENABLED, self.ONESHOT, self.RUNNING):
            self.__bad_transition(self.DISABLED)
        self.__state = self.DISABLED

    def enable(self, aProcess, aThread):
        """
        Enables a breakpoint.

        :param aProcess: Process that contains the breakpoint.
        :type aProcess: :class:`~winappdbg.process.Process`
        :param aThread: Current thread.
        :type aThread: :class:`~winappdbg.thread.Thread`
        :raises RuntimeError: The breakpoint was already enabled.
        """
        if self.__state not in (self.DISABLED, self.RUNNING):
            self.__bad_transition(self.ENABLED)
        self.__state = self.ENABLED

    def one_shot(self, aProcess, aThread):
        """
        Sets a breakpoint for one shot.

        :param aProcess: Process that contains the breakpoint.
        :type aProcess: :class:`~winappdbg.process.Process`
        :param aThread: Current thread.
        :type aThread: :class:`~winappdbg.thread.Thread`
        :raises RuntimeError: The breakpoint was already enabled.
        """
        if self.__state != self.DISABLED:
            self.__bad_transition(self.ONESHOT)
        self.__state = self.ONESHOT

    def running(self, aProcess, aThread):
        """
        Puts the breakpoint in running state. This happens when a breakpoint
        is hit and it's condition evaluates to ``False``.

        :param aProcess: Process that contains the breakpoint.
        :type aProcess: :class:`~winappdbg.process.Process`
        :param aThread: Current thread.
        :type aThread: :class:`~winappdbg.thread.Thread`
        :raises RuntimeError: The breakpoint was not enabled.
        """
        if self.__state != self.ENABLED:
            self.__bad_transition(self.RUNNING)
        self.__state = self.RUNNING

    def hit(self, event):
        """
        This method is called when the breakpoint is hit.
        It evaluates the breakpoint's condition and automatically disables it
        if it's a one-shot breakpoint.

        :param event: Event that triggered this breakpoint.
        :type event: :class:`~winappdbg.event.Event`
        :raises RuntimeError: An unexpected error occurred.
        """
        aProcess = event.get_process()
        aThread = event.get_thread()
        state = self.get_state()

        event.breakpoint = self

        if state == self.ENABLED:
            self.running(aProcess, aThread)

        elif state == self.RUNNING:
            self.enable(aProcess, aThread)

        elif state == self.ONESHOT:
            self.disable(aProcess, aThread)

        elif state == self.DISABLED:
            # this should not happen
            msg = "Hit a disabled breakpoint at address %s"
            msg = msg % HexDump.address(self.get_address())
            warnings.warn(msg, BreakpointWarning)


# ==============================================================================

# XXX TODO
# Check if the user is trying to set a code breakpoint on a memory mapped file,
# so we don't end up writing the int3 instruction in the file by accident.


class CodeBreakpoint(Breakpoint):
    """
    Code execution breakpoints (using an ``int3`` opcode).

    .. seealso:: :meth:`~winappdbg.debug.Debug.break_at`
    """

    typeName = "code breakpoint"

    bpInstructions = {
        win32.ARCH_I386: b"\xcc",               # INT 3
        win32.ARCH_AMD64: b"\xcc",              # INT 3
        win32.ARCH_ARM64: b"\x00\x00\x20\xd4",  # BRK #0
    }

    def __init__(self, address, arch=None, condition=True, action=None):
        """
        Code breakpoint object.

        :param int address: Memory address for breakpoint.
        :param callable condition: Optional condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean (``True`` to dispatch the event,
            ``False`` otherwise).

        :param str arch: Architecture of the target process.
            This is used to know how to assemble a breakpoint instruction.
            If the value is None, the default architecture is assumed.

        :param callable action: Optional action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object.
        """
        if not arch:
            arch = win32.arch
        code = self.bpInstructions.get(arch)
        if not code:
            msg = "Code breakpoints not supported for %s" % arch
            raise NotImplementedError(msg)
        super().__init__(address, len(code), condition, action)
        self.__bpInstruction = code
        self.__previousValue = code

    def __set_bp(self, aProcess):
        """
        Writes a breakpoint instruction at the target address.

        :param Process aProcess: Process object.
        """
        address = self.get_address()
        self.__previousValue = aProcess.read(address, len(self.__bpInstruction))
        # XXX FIXME this needs to account for larger than 1 byte breakpoints
        if self.__previousValue == self.__bpInstruction:
            msg = "Possibly overlapping code breakpoints at %s"
            msg = msg % HexDump.address(address)
            warnings.warn(msg, BreakpointWarning)
        aProcess.write(address, self.__bpInstruction)

    def __clear_bp(self, aProcess):
        """
        Restores the original byte at the target address.

        :param Process aProcess: Process object.
        """
        address = self.get_address()
        currentValue = aProcess.read(address, len(self.__bpInstruction))
        if currentValue == self.__bpInstruction:
            # Only restore the previous value if the int3 is still there.
            # XXX FIXME this needs to account for larger than 1 byte breakpoints
            aProcess.write(self.get_address(), self.__previousValue)
        else:
            self.__previousValue = currentValue
            msg = "Overwritten code breakpoint at %s"
            msg = msg % HexDump.address(address)
            warnings.warn(msg, BreakpointWarning)

    def disable(self, aProcess, aThread):
        if not self.is_disabled() and not self.is_running():
            self.__clear_bp(aProcess)
        super().disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aProcess)
        super().enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aProcess)
        super().one_shot(aProcess, aThread)

    # FIXME race condition here (however unlikely)
    # If another thread runs on over the target address while
    # the breakpoint is in RUNNING state, we'll miss it. There
    # is a solution to this but it's somewhat complicated, so
    # I'm leaving it for another version of the debugger. :(
    #
    # 2025 edit: reading this feels like finding Fermat's Last Theorem.
    # Not cause it's smart, but because I have no fucking clue what the
    # solution is supposed to be. Also, I'm doing this in my free time,
    # so fuck it. If someone else can fix it, be my guest. I sure won't.
    # I'm old and tired now.
    def running(self, aProcess, aThread):
        if self.is_enabled():
            self.__clear_bp(aProcess)
            aThread.set_tf()
        super().running(aProcess, aThread)


# ==============================================================================

# TODO:
# * If the original page was already a guard page, the exception should be
#   passed to the debugee instead of being handled by the debugger.
# * If the original page was already a guard page, it should NOT be converted
#   to a no-access page when disabling the breakpoint.
# * If the page permissions were modified after the breakpoint was enabled,
#   no change should be done on them when disabling the breakpoint. For this
#   we need to remember the original page permissions instead of blindly
#   setting and clearing the guard page bit on them.
# * Some pages seem to be "magic" and resist all attempts at changing their
#   protect bits (for example the pages where the PEB and TEB reside). Maybe
#   a more descriptive error message could be shown in this case.


class PageBreakpoint(Breakpoint):
    """
    Page access breakpoint (using guard pages).

    .. seealso:: :meth:`~winappdbg.debug.Debug.watch_buffer`
    """

    typeName = "page breakpoint"

    # ------------------------------------------------------------------------------

    def __init__(self, address, pages=1, condition=True, action=None):
        """
        Page breakpoint object.

        :param int address: Memory address for breakpoint. Must be page aligned.
        :param int pages: Number of pages to watch for access.
        :param callable condition: Optional condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean (``True`` to dispatch the event,
            ``False`` otherwise).
        :param callable action: Optional action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object.
        """
        super().__init__(address, pages * MemoryAddresses.pageSize, condition, action)
        ##        if (address & 0x00000FFF) != 0:
        floordiv_align = int(address) // int(MemoryAddresses.pageSize)
        truediv_align = float(address) / float(MemoryAddresses.pageSize)
        if floordiv_align != truediv_align:
            msg = (
                "Address of page breakpoint "
                "must be aligned to a page size boundary "
                "(value %s received)" % HexDump.address(address)
            )
            raise ValueError(msg)

    def get_size_in_pages(self):
        """
        :rtype:  int
        :return: Size of breakpoint in pages.
        """
        # The size is always a multiple of the page size.
        return self.get_size() // MemoryAddresses.pageSize

    def __set_bp(self, aProcess):
        """
        Sets the target pages as guard pages.

        :param Process aProcess: Process object.
        """
        lpAddress = self.get_address()
        dwSize = self.get_size()
        flNewProtect = aProcess.mquery(lpAddress).Protect
        flNewProtect = flNewProtect | win32.PAGE_GUARD
        aProcess.mprotect(lpAddress, dwSize, flNewProtect)

    def __clear_bp(self, aProcess):
        """
        Restores the original permissions of the target pages.

        :param Process aProcess: Process object.
        """
        lpAddress = self.get_address()
        flNewProtect = aProcess.mquery(lpAddress).Protect
        flNewProtect = flNewProtect & (0xFFFFFFFF ^ win32.PAGE_GUARD)  # DWORD
        aProcess.mprotect(lpAddress, self.get_size(), flNewProtect)

    def disable(self, aProcess, aThread):
        if not self.is_disabled():
            self.__clear_bp(aProcess)
        super().disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        if win32.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            msg = "Only one-shot page breakpoints are supported for %s"
            raise NotImplementedError(msg % win32.arch)
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aProcess)
        super().enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aProcess)
        super().one_shot(aProcess, aThread)

    def running(self, aProcess, aThread):
        aThread.set_tf()
        super().running(aProcess, aThread)


# ==============================================================================


# TODO: ARM does support hardware breakpoints, but that involves refactoring
#       this whole class, or possibly writing a separate class entirely.
class HardwareBreakpoint(Breakpoint):
    """
    Hardware breakpoint (using debug registers).

    .. seealso:: :meth:`~winappdbg.debug.Debug.watch_variable`

    :cvar BREAK_ON_EXECUTION: Break on execution.
    :type BREAK_ON_EXECUTION: int
    :cvar BREAK_ON_WRITE: Break on write.
    :type BREAK_ON_WRITE: int
    :cvar BREAK_ON_ACCESS: Break on read or write.
    :type BREAK_ON_ACCESS: int
    :cvar WATCH_BYTE: Watch a byte.
    :type WATCH_BYTE: int
    :cvar WATCH_WORD: Watch a word (2 bytes).
    :type WATCH_WORD: int
    :cvar WATCH_DWORD: Watch a double word (4 bytes).
    :type WATCH_DWORD: int
    :cvar WATCH_QWORD: Watch one quad word (8 bytes).
    :type WATCH_QWORD: int
    :cvar validTriggers: Valid trigger flag values.
    :type validTriggers: tuple
    :cvar validWatchSizes: Valid watch flag values.
    :type validWatchSizes: tuple
    """

    typeName = "hardware breakpoint"

    BREAK_ON_EXECUTION = IntelDebugRegister.BREAK_ON_EXECUTION
    BREAK_ON_WRITE = IntelDebugRegister.BREAK_ON_WRITE
    BREAK_ON_ACCESS = IntelDebugRegister.BREAK_ON_ACCESS

    WATCH_BYTE = IntelDebugRegister.WATCH_BYTE
    WATCH_WORD = IntelDebugRegister.WATCH_WORD
    WATCH_DWORD = IntelDebugRegister.WATCH_DWORD
    WATCH_QWORD = IntelDebugRegister.WATCH_QWORD

    validTriggers = (
        BREAK_ON_EXECUTION,
        BREAK_ON_WRITE,
        BREAK_ON_ACCESS,
    )

    validWatchSizes = (
        WATCH_BYTE,
        WATCH_WORD,
        WATCH_DWORD,
        WATCH_QWORD,
    )

    def __init__(
        self,
        address,
        triggerFlag=BREAK_ON_ACCESS,
        sizeFlag=WATCH_DWORD,
        condition=True,
        action=None,
    ):
        """
        Hardware breakpoint object.

        :param int address: Memory address for breakpoint.
        :param int triggerFlag: When to trigger the breakpoint.
            Must be one of the following values:
            - :attr:`BREAK_ON_EXECUTION`
            - :attr:`BREAK_ON_WRITE`
            - :attr:`BREAK_ON_ACCESS`
        :param int sizeFlag: Size of the data to watch.
            Must be one of the following values:
            - :attr:`WATCH_BYTE`
            - :attr:`WATCH_WORD`
            - :attr:`WATCH_DWORD`
            - :attr:`WATCH_QWORD`
        :param callable condition: Optional condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean (``True`` to dispatch the event,
            ``False`` otherwise).
        :param callable action: Optional action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object.
        """
        if win32.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
            msg = "Hardware breakpoints not supported for %s" % win32.arch
            raise NotImplementedError(msg)
        if sizeFlag == self.WATCH_BYTE:
            size = 1
        elif sizeFlag == self.WATCH_WORD:
            size = 2
        elif sizeFlag == self.WATCH_DWORD:
            size = 4
        elif sizeFlag == self.WATCH_QWORD:
            size = 8
        else:
            msg = "Invalid size flag for hardware breakpoint (%s)"
            msg = msg % repr(sizeFlag)
            raise ValueError(msg)

        if triggerFlag not in self.validTriggers:
            msg = "Invalid trigger flag for hardware breakpoint (%s)"
            msg = msg % repr(triggerFlag)
            raise ValueError(msg)

        super().__init__(address, size, condition, action)
        self.__trigger = triggerFlag
        self.__watch = sizeFlag
        self.__slot = None

    def __clear_bp(self, aThread):
        if self.__slot is not None:
            aThread.suspend()
            try:
                ctx = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
                IntelDebugRegister.clear_bp(ctx, self.__slot)
                aThread.set_context(ctx)
                self.__slot = None
            finally:
                aThread.resume()

    def __set_bp(self, aThread):
        if self.__slot is None:
            aThread.suspend()
            try:
                ctx = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
                self.__slot = IntelDebugRegister.find_slot(ctx)
                if self.__slot is None:
                    msg = "No available hardware breakpoint slots for thread ID %d"
                    msg = msg % aThread.get_tid()
                    raise RuntimeError(msg)
                IntelDebugRegister.set_bp(
                    ctx, self.__slot, self.get_address(), self.__trigger, self.__watch
                )
                aThread.set_context(ctx)
            finally:
                aThread.resume()

    def get_slot(self):
        """
        :rtype:  int
        :return: The debug register slot used by this breakpoint.
        """
        return self.__slot

    def get_trigger(self):
        """
        :rtype:  int
        :return: The trigger flag for this breakpoint.
        """
        return self.__trigger

    def get_watch(self):
        """
        :rtype:  int
        :return: The watch size flag for this breakpoint.
        """
        return self.__watch

    def disable(self, aProcess, aThread):
        if not self.is_disabled():
            self.__clear_bp(aThread)
        super().disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aThread)
        super().enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        if not self.is_enabled() and not self.is_one_shot():
            self.__set_bp(aThread)
        super().one_shot(aProcess, aThread)

    def running(self, aProcess, aThread):
        self.__clear_bp(aThread)
        super().running(aProcess, aThread)
        aThread.set_tf()


# ==============================================================================

# XXX FIXME
#
# The implementation of function hooks is very simple. A breakpoint is set at
# the entry point. Each time it's hit the "pre" callback is executed. If a
# "post" callback was defined, a one-shot breakpoint is set at the return
# address - and when that breakpoint hits, the "post" callback is executed.
#
# Functions hooks, as they are implemented now, don't work correctly for
# recursive functions. The problem is we don't know when to remove the
# breakpoint at the return address. Also there could be more than one return
# address.
#
# One possible solution would involve a dictionary of lists, where the key
# would be the thread ID and the value a stack of return addresses. But we
# still don't know what to do if the "wrong" return address is hit for some
# reason (maybe check the stack pointer?). Or if both a code and a hardware
# breakpoint are hit simultaneously.
#
# For now, the workaround for the user is to set only the "pre" callback for
# functions that are known to be recursive.
#
# If an exception is thrown by a hooked function and caught by one of it's
# parent functions, the "post" callback won't be called and weird stuff may
# happen. A possible solution is to put a breakpoint in the system call that
# unwinds the stack, to detect this case and remove the "post" breakpoint.
#
# Hooks may also behave oddly if the return address is overwritten by a buffer
# overflow bug (this is similar to the exception problem). But it's probably a
# minor issue since when you're fuzzing a function for overflows you're usually
# not interested in the return value anyway.

class HookFactory:
    """
    Factory class to produce hook objects. Used by
    :meth:`~winappdbg.debug.Debug.hook_function` and
    :meth:`~winappdbg.debug.Debug.stalk_function`.

    When you try to instance this class, one of the architecture specific
    implementations is returned instead.

    Instances act as an action callback for breakpoints set at the beginning
    of a function. It automatically retrieves the parameters from the stack,
    sets a breakpoint at the return address and retrieves the return value
    from the function call.

    .. seealso:: :class:`_Hook_i386`, :class:`_Hook_amd64`
    """

    def __new__(cls,
        preCB=None,
        postCB=None,
        paramCount=None,
        signature=None,
        arch=None,
        preCBArgs=None,
        postCBArgs=None,
        bpTypeEntry=None,
        bpTypeReturn=None,
    ):
        if arch is None:
            arch = win32.arch
        if arch == win32.ARCH_I386:
            return _Hook_i386(
                preCB, postCB, paramCount, signature, arch,
                preCBArgs, postCBArgs, bpTypeEntry, bpTypeReturn)
        if arch == win32.ARCH_AMD64:
            return _Hook_amd64(
                preCB, postCB, paramCount, signature, arch,
                preCBArgs, postCBArgs, bpTypeEntry, bpTypeReturn)
        raise NotImplementedError(
            "Hooks not supported for architecture: %s" % arch)


class Hook:
    """
    Base class for hooks.
    """

    def __init__(
        self,
        preCB=None,
        postCB=None,
        paramCount=None,
        signature=None,
        arch=None,
        preCBArgs=None,
        postCBArgs=None,
        bpTypeEntry=None,
        bpTypeReturn=None,
    ):
        """
        Hook object.

        :param callable preCB: Optional callback triggered on function entry.
            The signature for the callback should be something like this::

                def pre_LoadLibraryEx(event, ra, lpFilename, hFile, dwFlags):

                    # return address
                    ra = params[0]

                    # function arguments start from here...
                    szFilename = event.get_process().peek_string(lpFilename)

                    # (...)

            Note that all pointer types are treated like void pointers, so your
            callback won't get the string or structure pointed to by it, but
            the remote memory address instead. This is so to prevent the ctypes
            library from being "too helpful" and trying to dereference the
            pointer. To get the actual data being pointed to, use one of the
            :meth:`~winappdbg.process.Process.read` methods.

        :param callable postCB: Optional callback triggered on function exit.
            The signature for the callback should be something like this::

                def post_LoadLibraryEx(event, return_value):

                    # (...)

        :param int paramCount: Optional number of parameters for the ``preCB``
            callback, not counting the return address. Parameters are read from
            the stack and assumed to be DWORDs in 32 bits and QWORDs in 64.

            This is a faster way to pull stack parameters in 32 bits, but in 64
            bits (or with some odd APIs in 32 bits) it won't be useful, since
            not all arguments to the hooked function will be of the same size.

            For a more reliable and cross-platform way of hooking use the
            ``signature`` argument instead.

        :param tuple signature: Optional tuple of ``ctypes`` data types that
            constitute the hooked function signature. When the function is
            called, this will be used to parse the arguments from the stack.
            Overrides the ``paramCount`` argument.

        :param str arch: Target architecture for the hooked function.
            See :data:`winappdbg.win32.arch`.

        :param tuple preCBArgs: Optional tuple of extra arguments to ``preCB``.

        :param tuple postCBArgs: Optional tuple of extra arguments to ``postCB``.

        :param str bpTypeEntry: Optionally set the type of breakpoints to use
            for the function entrypoint.

            Defaults to :data:`Breakpoint.CODE_BREAKPOINT`. For hostile targets
            (that is, for malware analysis) you may want instead to use
            :data:`Breakpoint.PAGE_BREAKPOINT`. There will be a performance
            cost if you do this, of course.

        :param str bpTypeReturn: Optionally set the type of breakpoints to use
            for the function return address.

            Defaults to :data:`Breakpoint.CODE_BREAKPOINT` for compatibility, but
            if possible it's best to use :data:`Breakpoint.HARDWARE_BREAKPOINT`.
            The reason for this is hardware breakpoints are thread specific,
            so they eliminate any potential race conditions if multiple threads
            are calling the same hooked function at the same time.
        """
        self.__preCB = preCB
        self.__postCB = postCB
        self.__paramStack = dict()  # tid -> list of tuple( arg, arg, arg... )

        self._paramCount = paramCount

        if win32.bits == 64 and paramCount and not signature:
            signature = (win32.QWORD,) * paramCount

        if signature:
            self._signature = self._calc_signature(signature)
        else:
            self._signature = None

        self.__preCBArgs = preCBArgs
        self.__postCBArgs = postCBArgs

        if bpTypeEntry is None:
            bpTypeEntry = Breakpoint.CODE_BREAKPOINT
        if bpTypeReturn is None:
            bpTypeReturn = Breakpoint.CODE_BREAKPOINT

        self.__bpTypeEntry = bpTypeEntry
        self.__bpTypeReturn = bpTypeReturn

    def _cast_signature_pointers_to_void(self, signature):
        c_void_p = ctypes.c_void_p
        c_char_p = ctypes.c_char_p
        c_wchar_p = ctypes.c_wchar_p
        _Pointer = ctypes._Pointer
        cast = ctypes.cast
        for i in range(len(signature)):
            t = signature[i]
            if t is not c_void_p and (
                issubclass(t, _Pointer) or t in [c_char_p, c_wchar_p]
            ):
                signature[i] = cast(t, c_void_p)

    def _calc_signature(self, signature):
        raise NotImplementedError(
            "Hook signatures are not supported for architecture: %s" % win32.arch
        )

    def _get_return_address(self, aProcess, aThread):
        return None

    def _get_function_arguments(self, aProcess, aThread):
        if self._signature or self._paramCount:
            raise NotImplementedError(
                "Hook signatures are not supported for architecture: %s" % win32.arch
            )
        return ()

    def _get_return_value(self, aThread):
        return None

    def __call__(self, event):
        """
        Handles the breakpoint event on entry of the function.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :raises WindowsError: An error occurred.
        """
        debug = event.debug

        dwProcessId = event.get_pid()
        dwThreadId = event.get_tid()
        aProcess = event.get_process()
        aThread = event.get_thread()

        # Get the return address and function arguments.
        ra = self._get_return_address(aProcess, aThread)
        params = self._get_function_arguments(aProcess, aThread)

        # Keep the function arguments for later use.
        self.__push_params(dwThreadId, params)

        # If we need to hook the return from the function...
        bHookedReturn = False
        if ra is not None and self.__postCB is not None:

            # Set a breakpoint at the return address.
            # On failure, fallback to code breakpoints.
            # We can use a one-shot breakpoint if it's a hardware breakpoint,
            # but other types need to be a regular breakpoint because we need
            # to check if it was hit by the correct thread.
            if self.__bpTypeReturn == Breakpoint.HARDWARE_BREAKPOINT:
                try:
                    debug.stalk_variable(
                        dwThreadId, ra, aProcess.get_bits() // 8, self.__postCallAction_hwbp)
                    bHookedReturn = True
                except Exception:
                    msg = (
                        "Failed to set hardware breakpoint at address %s for thread ID %d"
                    )
                    msg = msg % (HexDump.address(ra), dwThreadId)
                    warnings.warn(msg, BreakpointWarning)
            elif self.__bpTypeReturn == Breakpoint.PAGE_BREAKPOINT:
                try:
                    debug.watch_buffer(
                        dwProcessId, ra, aProcess.get_bits() // 8, self.__postCallAction_pagebp)
                    bHookedReturn = True
                except Exception:
                    msg = (
                        "Failed to set page breakpoint at address %s for process ID %d"
                    )
                    msg = msg % (HexDump.address(ra), dwProcessId)
                    warnings.warn(msg, BreakpointWarning)
            if not bHookedReturn:   # code bp is the fallback
                try:
                    debug.break_at(dwProcessId, ra, self.__postCallAction_codebp)
                    bHookedReturn = True
                except Exception:
                    msg = (
                        "Failed to set code breakpoint at address %s for process ID %d"
                    )
                    msg = msg % (HexDump.address(ra), dwProcessId)
                    warnings.warn(msg, BreakpointWarning)

        # Call the "pre" callback.
        try:
            if self.__preCBArgs is not None:
                self.__callHandler(self.__preCB, event, ra, self.__preCBArgs, *params)
            else:
                self.__callHandler(self.__preCB, event, ra, *params)

        # If no "post" callback is defined, forget the function arguments.
        finally:
            if not bHookedReturn:
                self.__pop_params(dwThreadId)

    def __postCallAction_hwbp(self, event):
        """
        Handles the breakpoint event on exit of the function.
        This method is a callback for a hardware breakpoint.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        """

        # TODO: maybe disassemble the code that triggered
        # the event to ensure it was hit by a return instruction.
        # Otherwise malware can read its own return address as
        # a way to break this functionality.

        # Call the "post" callback.
        self.__postCallAction(event)

    def __postCallAction_codebp(self, event):
        """
        Handles the breakpoint event on exit of the function.
        This method is a callback for a code breakpoint.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        """

        # If the breakpoint was accidentally hit by another thread,
        # pass it to the debugger instead of calling the "post" callback.
        tid = event.get_tid()
        if tid not in self.__paramStack:
            return True

        # Remove the code breakpoint at the return address.
        pid = event.get_pid()
        address = event.breakpoint.get_address()
        event.debug.dont_break_at(pid, address)

        # Call the "post" callback.
        self.__postCallAction(event)

    def __postCallAction_pagebp(self, event):
        """
        Handles the breakpoint event on exit of the function.
        This method is a callback for a page breakpoint.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        """

        # TODO: maybe disassemble the code that triggered
        # the event to ensure it was hit by a return instruction.
        # Otherwise malware can read its own return address as
        # a way to break this functionality.

        # If the breakpoint was accidentally hit by another thread,
        # pass it to the debugger instead of calling the "post" callback.
        tid = event.get_tid()
        if tid not in self.__paramStack:
            return True

        # Remove the page breakpoint at the return address.
        pid = event.get_pid()
        address = event.breakpoint.get_address()
        size = event.get_process().get_bits() // 8
        event.debug.dont_watch_buffer(pid, address, size)

        # Call the "post" callback.
        self.__postCallAction(event)

    def __postCallAction(self, event):
        """
        This method is called when the hooked function returns.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        """

        # Call the user defined callback.
        try:
            aThread = event.get_thread()
            retval = self._get_return_value(aThread)
            if self.__postCBArgs is not None:
                self.__callHandler(self.__postCB, event, self.__postCBArgs, retval)
            else:
                self.__callHandler(self.__postCB, event, retval)

        # Forget the parameters.
        finally:
            self.__pop_params(tid)

    def __callHandler(self, callback, event, *params):
        """
        This is a wrapper for the user-defined callbacks.

        :param callable callback: Callback function to call.
        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :param params: Parameters for the callback function.
        """
        if callback is not None:
            event.hook = self
            callback(event, *params)

    def __push_params(self, tid, params):
        """
        Remembers the arguments tuple for the last call to the hooked function
        from this thread.

        :param int tid: Thread ID.
        :param params: Tuple of arguments.
        :type params: tuple
        """
        stack = self.__paramStack.get(tid, [])
        stack.append(params)
        self.__paramStack[tid] = stack

    def __pop_params(self, tid):
        """
        Forgets the arguments tuple for the last call to the hooked function
        from this thread.

        :param int tid: Thread ID.
        """
        stack = self.__paramStack[tid]
        stack.pop()
        if not stack:
            del self.__paramStack[tid]

    def get_params(self, tid):
        """
        Returns the parameters found in the stack when the hooked function
        was last called by this thread.

        :param int tid: Thread ID.
        :return: Tuple of arguments.
        :rtype: tuple
        """
        try:
            params = self.get_params_stack(tid)[-1]
        except IndexError:
            msg = "Hooked function called from .thread %d already returned"
            raise IndexError(msg % tid)
        return params

    def get_params_stack(self, tid):
        """
        Returns the parameters found in the stack each time the hooked function
        was called by this thread and hasn't returned yet.

        :param int tid: Thread ID.
        :return: List of tuples of parameters.
        :rtype: list
        """
        try:
            stack = self.__paramStack[tid]
        except KeyError:
            msg = "Hooked function was not called from .thread %d"
            raise KeyError(msg % tid)
        return stack

    def hook(self, debug, pid, address):
        """
        Convenience method to set the hook.

        :param debug: Debugger object.
        :type debug: :class:`~winappdbg.debug.Debug`
        :param int pid: Process ID.
        :param int address: Address to hook.
        :return: The new breakpoint object.
        :rtype: :class:`Breakpoint`
        """

        # For hardware breakpoints, we need to set them on every thread.
        if self.__bpTypeEntry == Breakpoint.HARDWARE_BREAKPOINT:
            process = debug.get_process()
            arch = process.get_arch()
            if arch == win32.I386 or arch == win32.AMD64:
                size = 1
            else:
                size = process.get_bits() // 8
            bp_list = []
            for thread in process.iter_threads():
                tid = thread.get_tid()
                bp_list.append(debug.watch_variable(tid, address, size, self))
            if len(bp_list) == 1:
                return bp_list[0]
            return bp_list

        # For page breakpoints we set a buffer watch on the first instruction.
        if self.__bpTypeEntry == Breakpoint.PAGE_BREAKPOINT:
            process = debug.get_process()
            arch = process.get_arch()
            if arch == win32.I386 or arch == win32.AMD64:
                size = 1    # TODO: maybe disassemble and get the real size?
            else:
                size = process.get_bits() // 8
            return debug.watch_buffer(pid, address, size, self)

        # Code breakpoints are the default.
        return debug.break_at(pid, address, self)

    def unhook(self, debug, pid, address):
        """
        Convenience method to remove the hook.

        :param debug: Debugger object.
        :type debug: :class:`~winappdbg.debug.Debug`
        :param int pid: Process ID.
        :param int address: Address of the hook.
        """
        if self.__bpTypeEntry == Breakpoint.HARDWARE_BREAKPOINT:
            process = debug.get_process()
            arch = process.get_arch()
            if arch == win32.I386 or arch == win32.AMD64:
                size = 1
            else:
                size = process.get_bits() // 8
            for thread in process.iter_threads():
                tid = thread.get_tid()
                debug.dont_watch_variable(tid, address, size)
        if self.__bpTypeEntry == Breakpoint.PAGE_BREAKPOINT:
            process = debug.get_process()
            arch = process.get_arch()
            if arch == win32.I386 or arch == win32.AMD64:
                size = 1
            else:
                size = process.get_bits() // 8
            return debug.dont_watch_buffer(pid, address, size)
        return debug.dont_break_at(pid, address)


class _Hook_i386(Hook):
    """Implementation details for :class:`Hook` on the
    :data:`~winappdbg.win32.ARCH_I386` architecture.
    """

    def _calc_signature(self, signature):
        self._cast_signature_pointers_to_void(signature)

        class Arguments(ctypes.Structure):
            # pack structures, don't align 64 bit values to 64 bit boundaries
            _pack_ = ctypes.sizeof(ctypes.c_void_p)
            _fields_ = [("arg_%s" % i, t) for (i, t) in enumerate(signature)]

        return Arguments

    def _get_return_address(self, aProcess, aThread):
        return aProcess.read_pointer(aThread.get_sp())

    def _get_function_arguments(self, aProcess, aThread):
        if self._signature:
            params = aThread.read_stack_structure(
                self._signature, offset=win32.sizeof(win32.LPVOID)
            )
        elif self._paramCount:
            params = aThread.read_stack_dwords(
                self._paramCount, offset=win32.sizeof(win32.LPVOID)
            )
        else:
            params = ()
        return params

    def _get_return_value(self, aThread):
        ctx = aThread.get_context(win32.CONTEXT_INTEGER)
        return ctx["Eax"]


class _Hook_amd64(Hook):
    """Implementation details for :class:`Hook` on the
    :data:`~winappdbg.win32.ARCH_AMD64` architecture.
    """

    # Make a list of floating point types.
    __float_types = (
        ctypes.c_double,
        ctypes.c_float,
    )
    # Long doubles are not supported in old versions of ctypes!
    try:
        __float_types += (ctypes.c_longdouble,)
    except AttributeError:
        pass

    def _calc_signature(self, signature):
        self._cast_signature_pointers_to_void(signature)

        float_types = self.__float_types
        c_sizeof = ctypes.sizeof
        reg_size = c_sizeof(ctypes.c_size_t)

        reg_int_sig = []
        reg_float_sig = []
        stack_sig = []

        for i in range(len(signature)):
            arg = signature[i]
            name = "arg_%d" % i
            stack_sig.append((name, arg))
            if i < 4:
                if type(arg) in float_types:
                    reg_float_sig.append((name, arg))
                elif c_sizeof(arg) <= reg_size:
                    reg_int_sig.append((name, arg))
                else:
                    msg = (
                        "Hook signatures don't support structures"
                        " within the first 4 arguments of a function"
                        " for the %s architecture"
                    ) % win32.arch
                    raise NotImplementedError(msg)

        if reg_int_sig:

            class RegisterArguments(ctypes.Structure):
                _fields_ = reg_int_sig
        else:
            RegisterArguments = None
        if reg_float_sig:

            class FloatArguments(ctypes.Structure):
                _fields_ = reg_float_sig
        else:
            FloatArguments = None
        if stack_sig:

            class StackArguments(ctypes.Structure):
                _fields_ = stack_sig
        else:
            StackArguments = None

        return (len(signature), RegisterArguments, FloatArguments, StackArguments)

    def _get_return_address(self, aProcess, aThread):
        return aProcess.read_pointer(aThread.get_sp())

    def _get_function_arguments(self, aProcess, aThread):
        if self._signature:
            (args_count, RegisterArguments, FloatArguments, StackArguments) = (
                self._signature
            )
            arguments = {}
            if StackArguments:
                address = aThread.get_sp() + win32.sizeof(win32.LPVOID)
                stack_struct = aProcess.read_structure(address, StackArguments)
                stack_args = dict(
                    [
                        (name, stack_struct.__getattribute__(name))
                        for (name, type) in stack_struct._fields_
                    ]
                )
                arguments.update(stack_args)
            flags = 0
            if RegisterArguments:
                flags = flags | win32.CONTEXT_INTEGER
            if FloatArguments:
                flags = flags | win32.CONTEXT_MMX_REGISTERS
            if flags:
                ctx = aThread.get_context(flags)
                if RegisterArguments:
                    buffer = (win32.QWORD * 4)(
                        ctx["Rcx"], ctx["Rdx"], ctx["R8"], ctx["R9"]
                    )
                    reg_args = self._get_arguments_from_buffer(
                        buffer, RegisterArguments
                    )
                    arguments.update(reg_args)
                if FloatArguments:
                    buffer = (win32.M128A * 4)(
                        ctx["XMM0"], ctx["XMM1"], ctx["XMM2"], ctx["XMM3"]
                    )
                    float_args = self._get_arguments_from_buffer(buffer, FloatArguments)
                    arguments.update(float_args)
            params = tuple([arguments["arg_%d" % i] for i in range(args_count)])
        else:
            params = ()
        return params

    def _get_arguments_from_buffer(self, buffer, structure):
        b_ptr = ctypes.pointer(buffer)
        v_ptr = ctypes.cast(b_ptr, ctypes.c_void_p)
        s_ptr = ctypes.cast(v_ptr, ctypes.POINTER(structure))
        struct = s_ptr.contents
        return dict(
            [(name, struct.__getattribute__(name)) for (name, type) in struct._fields_]
        )

    def _get_return_value(self, aThread):
        return aThread.get_context(win32.CONTEXT_INTEGER)["Rax"]

#------------------------------------------------------------------------------
# This class acts as a factory of Hook objects, one per target process.
# Said objects are deleted by the unhook() method.


class ApiHook:
    """Used by :class:`~winappdbg.event.EventHandler`.

    This class acts as an action callback for code breakpoints set at the
    beginning of a function. It automatically retrieves the parameters from
    the stack, sets a breakpoint at the return address and retrieves the
    return value from the function call.

    .. seealso:: :attr:`winappdbg.event.EventHandler.apiHooks`

    :ivar str modName: Module name.
    :ivar str procName: Procedure name.
    """

    def __init__(
        self, eventHandler, modName, procName, paramCount=None, signature=None
    ):
        """
        :param eventHandler:
            Event handler instance. This is where the hook
            callbacks are to be defined (see below).
        :type eventHandler: :class:`~winappdbg.event.EventHandler`

        :param str modName: Module name.

        :param str procName:
            Procedure name.
            The pre and post callbacks will be deduced from it.

            For example, if the procedure is "LoadLibraryEx" the callback
            routines will be "pre_LoadLibraryEx" and "post_LoadLibraryEx".

            The signature for the callbacks should be something like this::

                def pre_LoadLibraryEx(self, event, ra, lpFilename, hFile, dwFlags):

                    # return address
                    ra = params[0]

                    # function arguments start from here...
                    szFilename = event.get_process().peek_string(lpFilename)

                    # (...)

                def post_LoadLibraryEx(self, event, return_value):

                    # (...)

            Note that all pointer types are treated like void pointers, so your
            callback won't get the string or structure pointed to by it, but
            the remote memory address instead. This is so to prevent the ctypes
            library from being "too helpful" and trying to dereference the
            pointer. To get the actual data being pointed to, use one of the
            :meth:`~winappdbg.process.Process.read` methods.

        :param int paramCount:
            Optional number of parameters for the ``preCB``
            callback, not counting the return address. Parameters are read from
            the stack and assumed to be DWORDs in 32 bits and QWORDs in 64.
            This is a faster way to pull stack parameters in 32 bits, but in 64
            bits (or with some odd APIs in 32 bits) it won't be useful, since
            not all arguments to the hooked function will be of the same size.

            For a more reliable and cross-platform way of hooking use the
            ``signature`` argument instead.

        :param tuple signature:
            Optional tuple of ``ctypes`` data types that
            constitute the hooked function signature. When the function is
            called, this will be used to parse the arguments from the stack.
            Overrides the ``paramCount`` argument.
        """
        self.__modName = modName
        self.__procName = procName
        self.__paramCount = paramCount
        self.__signature = signature
        self.__preCB = getattr(eventHandler, "pre_" + procName, None)
        self.__postCB = getattr(eventHandler, "post_" + procName, None)
        self.__hook = dict()

    def __call__(self, event):
        """
        Handles the breakpoint event on entry of the function.

        :param event: Breakpoint hit event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :raises WindowsError: An error occurred.
        """
        pid = event.get_pid()
        try:
            hook = self.__hook[pid]
        except KeyError:
            warnings.warn(
                "Got a breakpoint hit for a removed hook in PID %d!" % pid)
            return
        return hook(event)

    @property
    def modName(self):
        return self.__modName

    @property
    def procName(self):
        return self.__procName

    def hook(self, debug, pid, bpTypeEntry=None, bpTypeReturn=None):
        """
        Installs the API hook on a given process and module.

        .. warning:: Do not call from an API hook callback.

        :param debug: Debug object.
        :type debug: :class:`~winappdbg.debug.Debug`
        :param int pid: Process ID.
        """
        label = "%s!%s" % (self.__modName, self.__procName)
        try:
            hook = self.__hook[pid]
        except KeyError:
            try:
                aProcess = debug.system.get_process(pid)
            except KeyError:
                aProcess = Process(pid)
            hook = HookFactory(
                self.__preCB,
                self.__postCB,
                self.__paramCount,
                self.__signature,
                aProcess.get_arch(),
                bpTypeEntry=bpTypeEntry,
                bpTypeReturn=bpTypeReturn
            )
            self.__hook[pid] = hook
        hook.hook(debug, pid, label)

    def unhook(self, debug, pid):
        """
        Removes the API hook from the given process and module.

        .. warning:: Do not call from an API hook callback.

        :param debug: Debug object.
        :type debug: :class:`~winappdbg.debug.Debug`
        :param int pid: Process ID.
        """
        try:
            hook = self.__hook[pid]
        except KeyError:
            return
        label = "%s!%s" % (self.__modName, self.__procName)
        hook.unhook(debug, pid, label)
        del self.__hook[pid]


# ==============================================================================


class BufferWatch:
    """Returned by :meth:`~winappdbg.debug.Debug.watch_buffer`.

    This object uniquely references a buffer being watched, even if there are
    multiple watches set on the exact memory region.

    :ivar int pid: Process ID.
    :ivar int start: Memory address of the start of the buffer.
    :ivar int end: Memory address of the end of the buffer.
    :ivar callable action: Action callback.
    :ivar bool oneshot: ``True`` for one shot breakpoints, ``False`` otherwise.
    """

    def __init__(self, pid, start, end, action=None, oneshot=False):
        self.__pid = pid
        self.__start = start
        self.__end = end
        self.__action = action
        self.__oneshot = oneshot

    @property
    def pid(self):
        return self.__pid

    @property
    def start(self):
        return self.__start

    @property
    def end(self):
        return self.__end

    @property
    def action(self):
        return self.__action

    @property
    def oneshot(self):
        return self.__oneshot

    def match(self, address):
        """Determine if the given memory address lies within the watched buffer.

        :param int address: Memory address to check.
        :rtype: bool
        :return: ``True`` if the given memory address lies within the watched
            buffer, ``False`` otherwise.
        """
        return self.__start <= address < self.__end


# ==============================================================================


class _BufferWatchCondition:
    """Used by :meth:`~winappdbg.debug.Debug.watch_buffer`.

    This class acts as a condition callback for page breakpoints.
    It emulates page breakpoints that can overlap and/or take up less
    than a page's size.
    """

    def __init__(self):
        self.__ranges = list()  # list of BufferWatch in definition order

    def add(self, bw):
        """Adds a buffer watch identifier.

        :param BufferWatch bw: Buffer watch identifier.
        """
        self.__ranges.append(bw)

    def remove(self, bw):
        """Removes a buffer watch identifier.

        :param BufferWatch bw: Buffer watch identifier.
        :raises KeyError: The buffer watch identifier was already removed.
        """
        try:
            self.__ranges.remove(bw)
        except KeyError:
            if not bw.oneshot:
                raise

    def remove_last_match(self, address, size):
        """Removes the last buffer from the watch object
        to match the given address and size.

        :param int address: Memory address of buffer to stop watching.
        :param int size: Size in bytes of buffer to stop watching.
        :rtype:  int
        :return:
            Number of matching elements found. Only the last one to be
            added is actually deleted upon calling this method.

            This counter allows you to know if there are more matching elements
            and how many.
        """
        count = 0
        start = address
        end = address + size - 1
        matched = None
        for item in self.__ranges:
            if item.match(start) and item.match(end):
                matched = item
                count += 1
        self.__ranges.remove(matched)
        return count

    def count(self):
        """
        :rtype: int
        :return: Number of buffers being watched.
        """
        return len(self.__ranges)

    def __call__(self, event):
        """Breakpoint condition callback.

        This method will also call the action callbacks for each
        buffer being watched.

        :param event: Guard page exception event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`

        :rtype:  bool
        :return: ``True`` if the address being accessed belongs
            to at least one of the buffers that was being watched
            and had no action callback.
        """
        address = event.get_exception_information(1)
        bCondition = False
        for bw in self.__ranges:
            bMatched = bw.match(address)
            try:
                action = bw.action
                if bMatched and action is not None:
                    try:
                        action(event)
                    except Exception as e:
                        msg = "Breakpoint action callback %r raised an exception: %s"
                        msg = msg % (action, traceback.format_exc(e))
                        warnings.warn(msg, BreakpointCallbackWarning)
                else:
                    bCondition = bCondition or bMatched
            finally:
                if bMatched and bw.oneshot:
                    event.debug.dont_watch_buffer(bw)
        return bCondition


# ==============================================================================


class _BreakpointContainer:
    """Encapsulates the capability to contain Breakpoint objects.

    .. rubric:: Breakpoints

    - :meth:`break_at`
    - :meth:`watch_variable`
    - :meth:`watch_buffer`
    - :meth:`hook_function`
    - :meth:`dont_break_at`
    - :meth:`dont_watch_variable`
    - :meth:`dont_watch_buffer`
    - :meth:`dont_hook_function`
    - :meth:`unhook_function`
    - :meth:`break_on_error`
    - :meth:`dont_break_on_error`

    .. rubric:: Stalking

    - :meth:`stalk_at`
    - :meth:`stalk_variable`
    - :meth:`stalk_buffer`
    - :meth:`stalk_function`
    - :meth:`dont_stalk_at`
    - :meth:`dont_stalk_variable`
    - :meth:`dont_stalk_buffer`
    - :meth:`dont_stalk_function`

    .. rubric:: Tracing

    - :meth:`is_tracing`
    - :meth:`get_traced_tids`
    - :meth:`start_tracing`
    - :meth:`stop_tracing`
    - :meth:`start_tracing_process`
    - :meth:`stop_tracing_process`
    - :meth:`start_tracing_all`
    - :meth:`stop_tracing_all`

    .. rubric:: Symbols

    - :meth:`resolve_label`
    - :meth:`resolve_exported_function`

    .. rubric:: Advanced breakpoint use

    - :meth:`define_code_breakpoint`
    - :meth:`define_page_breakpoint`
    - :meth:`define_hardware_breakpoint`
    - :meth:`has_code_breakpoint`
    - :meth:`has_page_breakpoint`
    - :meth:`has_hardware_breakpoint`
    - :meth:`get_code_breakpoint`
    - :meth:`get_page_breakpoint`
    - :meth:`get_hardware_breakpoint`
    - :meth:`erase_code_breakpoint`
    - :meth:`erase_page_breakpoint`
    - :meth:`erase_hardware_breakpoint`
    - :meth:`enable_code_breakpoint`
    - :meth:`enable_page_breakpoint`
    - :meth:`enable_hardware_breakpoint`
    - :meth:`enable_one_shot_code_breakpoint`
    - :meth:`enable_one_shot_page_breakpoint`
    - :meth:`enable_one_shot_hardware_breakpoint`
    - :meth:`disable_code_breakpoint`
    - :meth:`disable_page_breakpoint`
    - :meth:`disable_hardware_breakpoint`

    .. rubric:: Listing breakpoints

    - :meth:`get_all_breakpoints`
    - :meth:`get_all_code_breakpoints`
    - :meth:`get_all_page_breakpoints`
    - :meth:`get_all_hardware_breakpoints`
    - :meth:`get_process_breakpoints`
    - :meth:`get_process_code_breakpoints`
    - :meth:`get_process_page_breakpoints`
    - :meth:`get_process_hardware_breakpoints`
    - :meth:`get_thread_hardware_breakpoints`
    - :meth:`get_all_deferred_code_breakpoints`
    - :meth:`get_process_deferred_code_breakpoints`

    .. rubric:: Batch operations on breakpoints

    - :meth:`enable_all_breakpoints`
    - :meth:`enable_one_shot_all_breakpoints`
    - :meth:`disable_all_breakpoints`
    - :meth:`erase_all_breakpoints`
    - :meth:`enable_process_breakpoints`
    - :meth:`enable_one_shot_process_breakpoints`
    - :meth:`disable_process_breakpoints`
    - :meth:`erase_process_breakpoints`

    :cvar int BP_TYPE_ANY: To get all breakpoints.
    :cvar int BP_TYPE_CODE: To get code breakpoints only.
    :cvar int BP_TYPE_PAGE: To get page breakpoints only.
    :cvar int BP_TYPE_HARDWARE: To get hardware breakpoints only.

    :cvar int BP_STATE_DISABLED: Breakpoint is disabled.
    :cvar int BP_STATE_ENABLED: Breakpoint is enabled.
    :cvar int BP_STATE_ONESHOT: Breakpoint is enabled for one shot.
    :cvar int BP_STATE_RUNNING: Breakpoint is running (recently hit).

    :cvar int BP_BREAK_ON_EXECUTION: Break on code execution.
    :cvar int BP_BREAK_ON_WRITE: Break on memory write.
    :cvar int BP_BREAK_ON_ACCESS: Break on memory read or write.

    :cvar int BP_WATCH_BYTE: Watch a byte.
    :cvar int BP_WATCH_WORD: Watch a word (2 bytes).
    :cvar int BP_WATCH_DWORD: Watch a double word (4 bytes).
    :cvar int BP_WATCH_QWORD: Watch one quad word (8 bytes).
    """

    # Breakpoint types
    BP_TYPE_ANY = 0  # to get all breakpoints
    BP_TYPE_CODE = 1
    BP_TYPE_PAGE = 2
    BP_TYPE_HARDWARE = 3

    # Breakpoint states
    BP_STATE_DISABLED = Breakpoint.DISABLED
    BP_STATE_ENABLED = Breakpoint.ENABLED
    BP_STATE_ONESHOT = Breakpoint.ONESHOT
    BP_STATE_RUNNING = Breakpoint.RUNNING

    # Memory breakpoint trigger flags
    BP_BREAK_ON_EXECUTION = HardwareBreakpoint.BREAK_ON_EXECUTION
    BP_BREAK_ON_WRITE = HardwareBreakpoint.BREAK_ON_WRITE
    BP_BREAK_ON_ACCESS = HardwareBreakpoint.BREAK_ON_ACCESS

    # Memory breakpoint size flags
    BP_WATCH_BYTE = HardwareBreakpoint.WATCH_BYTE
    BP_WATCH_WORD = HardwareBreakpoint.WATCH_WORD
    BP_WATCH_QWORD = HardwareBreakpoint.WATCH_QWORD
    BP_WATCH_DWORD = HardwareBreakpoint.WATCH_DWORD

    def __init__(self):
        self.__codeBP = dict()  # (pid, address) -> CodeBreakpoint
        self.__pageBP = dict()  # (pid, address) -> PageBreakpoint
        self.__hardwareBP = dict()  # tid -> [ HardwareBreakpoint ]
        self.__runningBP = dict()  # tid -> set( Breakpoint )
        self.__tracing = set()  # set( tid )
        self.__deferredBP = dict()  # pid -> label -> (action, oneshot)

    # ------------------------------------------------------------------------------

    # This operates on the dictionary of running breakpoints.
    # Since the bps are meant to stay alive no cleanup is done here.

    def __get_running_bp_set(self, tid):
        """Get the set of running breakpoints for a thread."""
        return self.__runningBP.get(tid, ())

    def __add_running_bp(self, tid, bp):
        """Add a running breakpoint to a thread."""
        if tid not in self.__runningBP:
            self.__runningBP[tid] = set()
        self.__runningBP[tid].add(bp)

    def __del_running_bp(self, tid, bp):
        """Delete a running breakpoint from a thread."""
        self.__runningBP[tid].remove(bp)
        if not self.__runningBP[tid]:
            del self.__runningBP[tid]

    def __del_running_bp_from_all_threads(self, bp):
        """Delete a running breakpoint from all threads."""
        for tid, bpset in self.__runningBP.items():
            if bp in bpset:
                bpset.remove(bp)
                self.system.get_thread(tid).clear_tf()

    # ------------------------------------------------------------------------------

    # This is the cleanup code. Mostly called on response to exit/unload debug
    # events. If possible it shouldn't raise exceptions on runtime errors.
    # The main goal here is to avoid memory or handle leaks.

    def __cleanup_breakpoint(self, event, bp):
        """Cleanup a breakpoint object."""
        try:
            process = event.get_process()
            thread = event.get_thread()
            bp.disable(process, thread)  # clear the debug regs / trap flag
        except Exception:
            pass
        bp.set_condition(True)  # break possible circular reference
        bp.set_action(None)  # break possible circular reference

    def __cleanup_thread(self, event):
        """Cleanup breakpoints associated with a thread that's exiting."""
        tid = event.get_tid()

        # Cleanup running breakpoints
        try:
            for bp in self.__runningBP[tid]:
                self.__cleanup_breakpoint(event, bp)
            del self.__runningBP[tid]
        except KeyError:
            pass

        # Cleanup hardware breakpoints
        try:
            for bp in self.__hardwareBP[tid]:
                self.__cleanup_breakpoint(event, bp)
            del self.__hardwareBP[tid]
        except KeyError:
            pass

        # Cleanup set of threads being traced
        if tid in self.__tracing:
            self.__tracing.remove(tid)

    def __cleanup_process(self, event):
        """Cleanup breakpoints associated with a process that's exiting."""
        pid = event.get_pid()

        # Cleanup code breakpoints
        for bp_pid, bp_address in list(self.__codeBP.keys()):
            if bp_pid == pid:
                bp = self.__codeBP[(bp_pid, bp_address)]
                self.__cleanup_breakpoint(event, bp)
                del self.__codeBP[(bp_pid, bp_address)]

        # Cleanup page breakpoints
        for bp_pid, bp_address in list(self.__pageBP.keys()):
            if bp_pid == pid:
                bp = self.__pageBP[(bp_pid, bp_address)]
                self.__cleanup_breakpoint(event, bp)
                del self.__pageBP[(bp_pid, bp_address)]

        # Cleanup deferred code breakpoints
        try:
            del self.__deferredBP[pid]
        except KeyError:
            pass

    def __cleanup_module(self, event):
        """Cleanup breakpoints associated with a module that's being unloaded."""
        pid = event.get_pid()
        process = event.get_process()
        module = event.get_module()

        # Cleanup thread breakpoints on this module
        for tid in process.iter_thread_ids():
            # Running breakpoints
            if tid in self.__runningBP:
                bplist = list(self.__runningBP[tid])
                for bp in bplist:
                    bp_address = bp.get_address()
                    if process.get_module_at_address(bp_address) == module:
                        self.__cleanup_breakpoint(event, bp)
                        self.__runningBP[tid].remove(bp)

            # Hardware breakpoints
            if tid in self.__hardwareBP:
                bplist = list(self.__hardwareBP[tid])
                for bp in bplist:
                    bp_address = bp.get_address()
                    if process.get_module_at_address(bp_address) == module:
                        self.__cleanup_breakpoint(event, bp)
                        self.__hardwareBP[tid].remove(bp)

        # Cleanup code breakpoints on this module
        for bp_pid, bp_address in list(self.__codeBP.keys()):
            if bp_pid == pid:
                if process.get_module_at_address(bp_address) == module:
                    bp = self.__codeBP[(bp_pid, bp_address)]
                    self.__cleanup_breakpoint(event, bp)
                    del self.__codeBP[(bp_pid, bp_address)]

        # Cleanup page breakpoints on this module
        for bp_pid, bp_address in list(self.__pageBP.keys()):
            if bp_pid == pid:
                if process.get_module_at_address(bp_address) == module:
                    bp = self.__pageBP[(bp_pid, bp_address)]
                    self.__cleanup_breakpoint(event, bp)
                    del self.__pageBP[(bp_pid, bp_address)]

    # ------------------------------------------------------------------------------

    # Defining breakpoints.

    # Code breakpoints.
    def define_code_breakpoint(self, dwProcessId, address, condition=True, action=None):
        """
        Creates a disabled code breakpoint at the given address.

        :see: :meth:`has_code_breakpoint`, :meth:`get_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`disable_code_breakpoint`, :meth:`erase_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of the code instruction to break at.
        :param callable condition: (Optional) Condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean
            (``True`` to dispatch the event, ``False`` otherwise).
        :param callable action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.

            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event`.

        :rtype:  :class:`CodeBreakpoint`
        :return: The code breakpoint object.
        """
        arch = Process(dwProcessId).get_arch()
        bp = CodeBreakpoint(address, arch, condition, action)
        key = (dwProcessId, bp.get_address())
        if key in self.__codeBP:
            msg = "Already exists (PID %d) : %r"
            raise KeyError(msg % (dwProcessId, self.__codeBP[key]))
        self.__codeBP[key] = bp
        return bp

    # Page breakpoints.
    def define_page_breakpoint(
        self, dwProcessId, address, pages=1, condition=True, action=None
    ):
        """
        Creates a disabled page breakpoint at the given address.

        :see: :meth:`has_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`disable_page_breakpoint`, :meth:`erase_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of the first page to watch.
        :param int pages: Number of pages to watch.
        :param callable condition: (Optional) Condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean
            (``True`` to dispatch the event, ``False`` otherwise).
        :param callable action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.

            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean
            (``True`` to dispatch the event, ``False`` otherwise).

        :rtype:  :class:`PageBreakpoint`
        :return: The page breakpoint object.
        """
        bp = PageBreakpoint(address, pages, condition, action)
        begin = bp.get_address()
        end = begin + bp.get_size()

        address = begin
        pageSize = MemoryAddresses.pageSize
        while address < end:
            key = (dwProcessId, address)
            if key in self.__pageBP:
                msg = "Already exists (PID %d) : %r"
                msg = msg % (dwProcessId, self.__pageBP[key])
                raise KeyError(msg)
            address = address + pageSize

        address = begin
        while address < end:
            key = (dwProcessId, address)
            self.__pageBP[key] = bp
            address = address + pageSize
        return bp

    # Hardware breakpoints.
    def define_hardware_breakpoint(
        self,
        dwThreadId,
        address,
        triggerFlag=BP_BREAK_ON_ACCESS,
        sizeFlag=BP_WATCH_DWORD,
        condition=True,
        action=None,
    ):
        """
        Creates a disabled hardware breakpoint at the given address.

        :see: :meth:`has_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`

        .. note:: Hardware breakpoints do not seem to work properly on VirtualBox.
            See `http://www.virtualbox.org/ticket/477 <http://www.virtualbox.org/ticket/477>`__.

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address to watch.
        :param int triggerFlag: Trigger of breakpoint. Must be one of the following:
            - :attr:`BP_BREAK_ON_EXECUTION`
                Break on code execution.
            - :attr:`BP_BREAK_ON_WRITE`
                Break on memory read or write.
            - :attr:`BP_BREAK_ON_ACCESS`
                Break on memory write.
        :param int sizeFlag: Size of breakpoint. Must be one of the following:
            - :attr:`BP_WATCH_BYTE`
                One (1) byte in size.
            - :attr:`BP_WATCH_WORD`
                Two (2) bytes in size.
            - :attr:`BP_WATCH_DWORD`
                Four (4) bytes in size.
            - :attr:`BP_WATCH_QWORD`
                Eight (8) bytes in size.
        :param callable condition: (Optional) Condition callback function.
            The callback signature is::

                def condition_callback(event):
                    return True     # returns True or False

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean
            (``True`` to dispatch the event, ``False`` otherwise).
        :param callable action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.

            The callback signature is::

                def action_callback(event):
                    pass        # no return value

            Where ``event`` is an :class:`~winappdbg.event.Event` object,
            and the return value is a boolean
            (``True`` to dispatch the event, ``False`` otherwise).

        :rtype:  :class:`HardwareBreakpoint`
        :return: The hardware breakpoint object.
        """
        bp = HardwareBreakpoint(address, triggerFlag, sizeFlag, condition, action)
        begin = bp.get_address()
        end = begin + bp.get_size()

        if dwThreadId in self.__hardwareBP:
            bpSet = self.__hardwareBP[dwThreadId]
            for oldbp in bpSet:
                old_begin = oldbp.get_address()
                old_end = old_begin + oldbp.get_size()
                if MemoryAddresses.do_ranges_intersect(begin, end, old_begin, old_end):
                    msg = "Already exists (TID %d) : %r" % (dwThreadId, oldbp)
                    raise KeyError(msg)
        else:
            bpSet = set()
            self.__hardwareBP[dwThreadId] = bpSet
        bpSet.add(bp)
        return bp

    # ------------------------------------------------------------------------------

    # Checking breakpoint definitions.

    def has_code_breakpoint(self, dwProcessId, address):
        """
        Checks if a code breakpoint is defined at the given address.

        :see: :meth:`define_code_breakpoint`, :meth:`get_code_breakpoint`, :meth:`erase_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`disable_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        :rtype:  bool
        :return: ``True`` if the breakpoint is defined, ``False`` otherwise.
        """
        return (dwProcessId, address) in self.__codeBP

    def has_page_breakpoint(self, dwProcessId, address):
        """
        Checks if a page breakpoint is defined at the given address.

        :see: :meth:`define_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`erase_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`disable_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        :rtype:  bool
        :return: ``True`` if the breakpoint is defined, ``False`` otherwise.
        """
        return (dwProcessId, address) in self.__pageBP

    def has_hardware_breakpoint(self, dwThreadId, address):
        """
        Checks if a hardware breakpoint is defined at the given address.

        :see: :meth:`define_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address of breakpoint.
        :rtype:  bool
        :return: ``True`` if the breakpoint is defined, ``False`` otherwise.
        """
        if dwThreadId in self.__hardwareBP:
            bpSet = self.__hardwareBP[dwThreadId]
            for bp in bpSet:
                if bp.get_address() == address:
                    return True
        return False

    # ------------------------------------------------------------------------------

    # Getting breakpoints.

    def get_code_breakpoint(self, dwProcessId, address):
        """
        Returns the internally used breakpoint object,
        for the code breakpoint defined at the given address.

        .. warning:: It's usually best to call the :class:`~winappdbg.debug.Debug` methods
            instead of accessing the breakpoint objects directly.

        :see: :meth:`define_code_breakpoint`, :meth:`has_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`disable_code_breakpoint`, :meth:`erase_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address where the breakpoint is defined.
        :rtype:  :class:`CodeBreakpoint`
        :return: The code breakpoint object.
        """
        key = (dwProcessId, address)
        if key not in self.__codeBP:
            msg = "No breakpoint at process %d, address %s"
            address = HexDump.address(address)
            raise KeyError(msg % (dwProcessId, address))
        return self.__codeBP[key]

    def get_page_breakpoint(self, dwProcessId, address):
        """
        Returns the internally used breakpoint object,
        for the page breakpoint defined at the given address.

        .. warning:: It's usually best to call the :class:`~winappdbg.debug.Debug` methods
            instead of accessing the breakpoint objects directly.

        :see: :meth:`define_page_breakpoint`, :meth:`has_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`disable_page_breakpoint`, :meth:`erase_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address where the breakpoint is defined.
        :rtype:  :class:`PageBreakpoint`
        :return: The page breakpoint object.
        """
        key = (dwProcessId, address)
        if key not in self.__pageBP:
            msg = "No breakpoint at process %d, address %s"
            address = HexDump.address(address)
            raise KeyError(msg % (dwProcessId, address))
        return self.__pageBP[key]

    def get_hardware_breakpoint(self, dwThreadId, address):
        """
        Returns the internally used breakpoint object,
        for the code breakpoint defined at the given address.

        .. warning:: It's usually best to call the :class:`~winappdbg.debug.Debug` methods
            instead of accessing the breakpoint objects directly.

        :see: :meth:`define_hardware_breakpoint`, :meth:`has_hardware_breakpoint`, :meth:`get_code_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address where the breakpoint is defined.
        :rtype:  :class:`HardwareBreakpoint`
        :return: The hardware breakpoint object.
        """
        if dwThreadId not in self.__hardwareBP:
            msg = "No hardware breakpoints set for thread %d"
            raise KeyError(msg % dwThreadId)
        for bp in self.__hardwareBP[dwThreadId]:
            if bp.is_here(address):
                return bp
        msg = "No hardware breakpoint at thread %d, address %s"
        raise KeyError(msg % (dwThreadId, HexDump.address(address)))

    # ------------------------------------------------------------------------------

    # Enabling and disabling breakpoints.

    def enable_code_breakpoint(self, dwProcessId, address):
        """
        Enables the code breakpoint at the given address.

        :see: :meth:`define_code_breakpoint`, :meth:`has_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`disable_code_breakpoint`, :meth:`erase_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_code_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.enable(p, None)  # XXX HACK thread is not used

    def enable_page_breakpoint(self, dwProcessId, address):
        """
        Enables the page breakpoint at the given address.

        :see: :meth:`define_page_breakpoint`, :meth:`has_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`disable_page_breakpoint`, :meth:`erase_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_page_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.enable(p, None)  # XXX HACK thread is not used

    def enable_hardware_breakpoint(self, dwThreadId, address):
        """
        Enables the hardware breakpoint at the given address.

        :see: :meth:`define_hardware_breakpoint`, :meth:`has_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`

        .. note:: Do not set hardware breakpoints while processing the system
            breakpoint event.

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address of breakpoint.
        """
        t = self.system.get_thread(dwThreadId)
        bp = self.get_hardware_breakpoint(dwThreadId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.enable(None, t)  # XXX HACK process is not used

    def enable_one_shot_code_breakpoint(self, dwProcessId, address):
        """
        Enables the code breakpoint at the given address for only one shot.

        :see: :meth:`define_code_breakpoint`, :meth:`has_code_breakpoint`, :meth:`get_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`disable_code_breakpoint`, :meth:`erase_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_code_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.one_shot(p, None)  # XXX HACK thread is not used

    def enable_one_shot_page_breakpoint(self, dwProcessId, address):
        """
        Enables the page breakpoint at the given address for only one shot.

        :see: :meth:`define_page_breakpoint`, :meth:`has_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`disable_page_breakpoint`, :meth:`erase_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_page_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.one_shot(p, None)  # XXX HACK thread is not used

    def enable_one_shot_hardware_breakpoint(self, dwThreadId, address):
        """
        Enables the hardware breakpoint at the given address for only one shot.

        :see: :meth:`define_hardware_breakpoint`, :meth:`has_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address of breakpoint.
        """
        t = self.system.get_thread(dwThreadId)
        bp = self.get_hardware_breakpoint(dwThreadId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.one_shot(None, t)  # XXX HACK process is not used

    def disable_code_breakpoint(self, dwProcessId, address):
        """
        Disables the code breakpoint at the given address.

        :see: :meth:`define_code_breakpoint`, :meth:`has_code_breakpoint`, :meth:`get_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`erase_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_code_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.disable(p, None)  # XXX HACK thread is not used

    def disable_page_breakpoint(self, dwProcessId, address):
        """
        Disables the page breakpoint at the given address.

        :see: :meth:`define_page_breakpoint`, :meth:`has_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`erase_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        p = self.system.get_process(dwProcessId)
        bp = self.get_page_breakpoint(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.disable(p, None)  # XXX HACK thread is not used

    def disable_hardware_breakpoint(self, dwThreadId, address):
        """
        Disables the hardware breakpoint at the given address.

        :see: :meth:`define_hardware_breakpoint`, :meth:`has_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`erase_hardware_breakpoint`

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address of breakpoint.
        """
        t = self.system.get_thread(dwThreadId)
        p = t.get_process()
        bp = self.get_hardware_breakpoint(dwThreadId, address)
        if bp.is_running():
            self.__del_running_bp(dwThreadId, bp)
        bp.disable(p, t)

    # ------------------------------------------------------------------------------

    # Undefining (erasing) breakpoints.

    def erase_code_breakpoint(self, dwProcessId, address):
        """
        Erases the code breakpoint at the given address.

        :see: :meth:`define_code_breakpoint`, :meth:`has_code_breakpoint`, :meth:`get_code_breakpoint`, :meth:`enable_code_breakpoint`, :meth:`enable_one_shot_code_breakpoint`, :meth:`disable_code_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        bp = self.get_code_breakpoint(dwProcessId, address)
        if not bp.is_disabled():
            self.disable_code_breakpoint(dwProcessId, address)
        del self.__codeBP[(dwProcessId, address)]

    def erase_page_breakpoint(self, dwProcessId, address):
        """
        Erases the page breakpoint at the given address.

        :see: :meth:`define_page_breakpoint`, :meth:`has_page_breakpoint`, :meth:`get_page_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`disable_page_breakpoint`

        :param int dwProcessId: Process global ID.
        :param int address: Memory address of breakpoint.
        """
        bp = self.get_page_breakpoint(dwProcessId, address)
        begin = bp.get_address()
        end = begin + bp.get_size()
        if not bp.is_disabled():
            self.disable_page_breakpoint(dwProcessId, address)
        address = begin
        pageSize = MemoryAddresses.pageSize
        while address < end:
            del self.__pageBP[(dwProcessId, address)]
            address = address + pageSize

    def erase_hardware_breakpoint(self, dwThreadId, address):
        """
        Erases the hardware breakpoint at the given address.

        :see: :meth:`define_hardware_breakpoint`, :meth:`has_hardware_breakpoint`, :meth:`get_hardware_breakpoint`, :meth:`enable_hardware_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`, :meth:`disable_hardware_breakpoint`

        :param int dwThreadId: Thread global ID.
        :param int address: Memory address of breakpoint.
        """
        bp = self.get_hardware_breakpoint(dwThreadId, address)
        if not bp.is_disabled():
            self.disable_hardware_breakpoint(dwThreadId, address)
        bpSet = self.__hardwareBP[dwThreadId]
        bpSet.remove(bp)
        if not bpSet:
            del self.__hardwareBP[dwThreadId]

    # ------------------------------------------------------------------------------

    # Listing breakpoints.

    def get_all_breakpoints(self):
        """
        Returns all breakpoint objects as a list of tuples.

        Each tuple contains:
         - Process global ID to which the breakpoint applies.
         - Thread global ID to which the breakpoint applies, or ``None``.
         - The :class:`Breakpoint` object itself.

        .. note:: If you're only interested in a specific breakpoint type, or in
            breakpoints for a specific process or thread, it's probably faster
            to call one of the following methods:
             - :meth:`get_all_code_breakpoints`
             - :meth:`get_all_page_breakpoints`
             - :meth:`get_all_hardware_breakpoints`
             - :meth:`get_process_code_breakpoints`
             - :meth:`get_process_page_breakpoints`
             - :meth:`get_process_hardware_breakpoints`
             - :meth:`get_thread_hardware_breakpoints`

        :rtype:  list of tuple( pid, tid, bp )
        :return: List of all breakpoints.
        """
        bplist = list()

        # Get the code breakpoints.
        for pid, bp in self.get_all_code_breakpoints():
            bplist.append((pid, None, bp))

        # Get the page breakpoints.
        for pid, bp in self.get_all_page_breakpoints():
            bplist.append((pid, None, bp))

        # Get the hardware breakpoints.
        for tid, bp in self.get_all_hardware_breakpoints():
            pid = self.system.get_thread(tid).get_pid()
            bplist.append((pid, tid, bp))

        # Return the list of breakpoints.
        return bplist

    def get_all_code_breakpoints(self):
        """
        :rtype:  list of tuple( int, :class:`CodeBreakpoint` )
        :return: All code breakpoints as a list of tuples (pid, bp).
        """
        return [(pid, bp) for ((pid, address), bp) in self.__codeBP.items()]

    def get_all_page_breakpoints(self):
        """
        :rtype:  list of tuple( int, :class:`PageBreakpoint` )
        :return: All page breakpoints as a list of tuples (pid, bp).
        """
        ##        return list( set( [ (pid, bp) for ((pid, address), bp) in self.__pageBP.items() ] ) )
        result = set()
        for (pid, address), bp in self.__pageBP.items():
            result.add((pid, bp))
        return list(result)

    def get_all_hardware_breakpoints(self):
        """
        :rtype:  list of tuple( int, :class:`HardwareBreakpoint` )
        :return: All hardware breakpoints as a list of tuples (tid, bp).
        """
        result = list()
        for tid, bplist in self.__hardwareBP.items():
            for bp in bplist:
                result.append((tid, bp))
        return result

    def get_process_breakpoints(self, dwProcessId):
        """
        Returns all breakpoint objects for the given process as a list of tuples.

        Each tuple contains:
         - Process global ID to which the breakpoint applies.
         - Thread global ID to which the breakpoint applies, or ``None``.
         - The :class:`Breakpoint` object itself.

        .. note:: If you're only interested in a specific breakpoint type, or in
            breakpoints for a specific process or thread, it's probably faster
            to call one of the following methods:
             - :meth:`get_all_code_breakpoints`
             - :meth:`get_all_page_breakpoints`
             - :meth:`get_all_hardware_breakpoints`
             - :meth:`get_process_code_breakpoints`
             - :meth:`get_process_page_breakpoints`
             - :meth:`get_process_hardware_breakpoints`
             - :meth:`get_thread_hardware_breakpoints`

        :param int dwProcessId: Process global ID.
        :rtype:  list of tuple( pid, tid, bp )
        :return: List of all breakpoints for the given process.
        """
        bplist = list()

        # Get the code breakpoints.
        for bp in self.get_process_code_breakpoints(dwProcessId):
            bplist.append((dwProcessId, None, bp))

        # Get the page breakpoints.
        for bp in self.get_process_page_breakpoints(dwProcessId):
            bplist.append((dwProcessId, None, bp))

        # Get the hardware breakpoints.
        for tid, bp in self.get_process_hardware_breakpoints(dwProcessId):
            bplist.append((dwProcessId, tid, bp))

        # Return the list of breakpoints.
        return bplist

    def get_process_code_breakpoints(self, dwProcessId):
        """
        :param int dwProcessId: Process global ID.
        :rtype:  list of :class:`CodeBreakpoint`
        :return: All code breakpoints for the given process.
        """
        return [
            bp for ((pid, address), bp) in self.__codeBP.items() if pid == dwProcessId
        ]

    def get_process_page_breakpoints(self, dwProcessId):
        """
        :param int dwProcessId: Process global ID.
        :rtype:  list of :class:`PageBreakpoint`
        :return: All page breakpoints for the given process.
        """
        return [
            bp for ((pid, address), bp) in self.__pageBP.items() if pid == dwProcessId
        ]

    def get_thread_hardware_breakpoints(self, dwThreadId):
        """
        :see: :meth:`get_process_hardware_breakpoints`

        :param int dwThreadId: Thread global ID.
        :rtype:  list of :class:`HardwareBreakpoint`
        :return: All hardware breakpoints for the given thread.
        """
        result = list()
        for tid, bplist in self.__hardwareBP.items():
            if tid == dwThreadId:
                for bp in bplist:
                    result.append(bp)
        return result

    def get_process_hardware_breakpoints(self, dwProcessId):
        """
        :see: :meth:`get_thread_hardware_breakpoints`

        :param int dwProcessId: Process global ID.
        :rtype:  list of tuple( int, :class:`HardwareBreakpoint` )
        :return: All hardware breakpoints for each thread in the given process
            as a list of tuples (tid, bp).
        """
        result = list()
        aProcess = self.system.get_process(dwProcessId)
        for dwThreadId in aProcess.iter_thread_ids():
            if dwThreadId in self.__hardwareBP:
                bplist = self.__hardwareBP[dwThreadId]
                for bp in bplist:
                    result.append((dwThreadId, bp))
        return result

    ##    def get_all_hooks(self):
    ##        """
    ##        :see: :meth:`get_process_hooks`
    ##
    ##        :rtype:  list of tuple( int, int, :class:`Hook` )
    ##        :return: All defined hooks as a list of tuples (pid, address, hook).
    ##        """
    ##        return [ (pid, address, hook) \
    ##            for ((pid, address), hook) in self.__hook_objects ]
    ##
    ##    def get_process_hooks(self, dwProcessId):
    ##        """
    ##        :see: :meth:`get_all_hooks`
    ##
    ##        :param int dwProcessId: Process global ID.
    ##
    ##        :rtype:  list of tuple( int, int, :class:`Hook` )
    ##        :return: All hooks for the given process as a list of tuples
    ##            (pid, address, hook).
    ##        """
    ##        return [ (pid, address, hook) \
    ##            for ((pid, address), hook) in self.__hook_objects \
    ##            if pid == dwProcessId ]

    # ------------------------------------------------------------------------------

    # Batch operations on all breakpoints.

    def enable_all_breakpoints(self):
        """
        Enables all disabled breakpoints in all processes.

        :see: :meth:`enable_code_breakpoint`, :meth:`enable_page_breakpoint`, :meth:`enable_hardware_breakpoint`
        """

        # disable code breakpoints
        for pid, bp in self.get_all_code_breakpoints():
            if bp.is_disabled():
                self.enable_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints
        for pid, bp in self.get_all_page_breakpoints():
            if bp.is_disabled():
                self.enable_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints
        for tid, bp in self.get_all_hardware_breakpoints():
            if bp.is_disabled():
                self.enable_hardware_breakpoint(tid, bp.get_address())

    def enable_one_shot_all_breakpoints(self):
        """
        Enables for one shot all disabled breakpoints in all processes.

        :see: :meth:`enable_one_shot_code_breakpoint`, :meth:`enable_one_shot_page_breakpoint`, :meth:`enable_one_shot_hardware_breakpoint`
        """

        # disable code breakpoints for one shot
        for pid, bp in self.get_all_code_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints for one shot
        for pid, bp in self.get_all_page_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints for one shot
        for tid, bp in self.get_all_hardware_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_hardware_breakpoint(tid, bp.get_address())

    def disable_all_breakpoints(self):
        """
        Disables all breakpoints in all processes.

        :see: :meth:`disable_code_breakpoint`, :meth:`disable_page_breakpoint`, :meth:`disable_hardware_breakpoint`
        """

        # disable code breakpoints
        for pid, bp in self.get_all_code_breakpoints():
            self.disable_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints
        for pid, bp in self.get_all_page_breakpoints():
            self.disable_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints
        for tid, bp in self.get_all_hardware_breakpoints():
            self.disable_hardware_breakpoint(tid, bp.get_address())

    def erase_all_breakpoints(self):
        """
        Erases all breakpoints in all processes.

        :see: :meth:`erase_code_breakpoint`, :meth:`erase_page_breakpoint`, :meth:`erase_hardware_breakpoint`
        """

        # This should be faster but let's not trust the GC so much :P
        # self.disable_all_breakpoints()
        # self.__codeBP       = dict()
        # self.__pageBP       = dict()
        # self.__hardwareBP   = dict()
        # self.__runningBP    = dict()
        # self.__hook_objects = dict()

        ##        # erase hooks
        ##        for (pid, address, hook) in self.get_all_hooks():
        ##            self.dont_hook_function(pid, address)

        # erase code breakpoints
        for pid, bp in self.get_all_code_breakpoints():
            self.erase_code_breakpoint(pid, bp.get_address())

        # erase page breakpoints
        for pid, bp in self.get_all_page_breakpoints():
            self.erase_page_breakpoint(pid, bp.get_address())

        # erase hardware breakpoints
        for tid, bp in self.get_all_hardware_breakpoints():
            self.erase_hardware_breakpoint(tid, bp.get_address())

    # ------------------------------------------------------------------------------

    # Batch operations on breakpoints per process.

    def enable_process_breakpoints(self, dwProcessId):
        """
        Enables all disabled breakpoints for the given process.

        :param int dwProcessId: Process global ID.
        """

        # enable code breakpoints
        for bp in self.get_process_code_breakpoints(dwProcessId):
            if bp.is_disabled():
                self.enable_code_breakpoint(dwProcessId, bp.get_address())

        # enable page breakpoints
        for bp in self.get_process_page_breakpoints(dwProcessId):
            if bp.is_disabled():
                self.enable_page_breakpoint(dwProcessId, bp.get_address())

        # enable hardware breakpoints
        if self.system.has_process(dwProcessId):
            aProcess = self.system.get_process(dwProcessId)
        else:
            aProcess = Process(dwProcessId)
            aProcess.scan_threads()
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_thread_hardware_breakpoints(dwThreadId):
                if bp.is_disabled():
                    self.enable_hardware_breakpoint(dwThreadId, bp.get_address())

    def enable_one_shot_process_breakpoints(self, dwProcessId):
        """
        Enables for one shot all disabled breakpoints for the given process.

        :param int dwProcessId: Process global ID.
        """

        # enable code breakpoints for one shot
        for bp in self.get_process_code_breakpoints(dwProcessId):
            if bp.is_disabled():
                self.enable_one_shot_code_breakpoint(dwProcessId, bp.get_address())

        # enable page breakpoints for one shot
        for bp in self.get_process_page_breakpoints(dwProcessId):
            if bp.is_disabled():
                self.enable_one_shot_page_breakpoint(dwProcessId, bp.get_address())

        # enable hardware breakpoints for one shot
        if self.system.has_process(dwProcessId):
            aProcess = self.system.get_process(dwProcessId)
        else:
            aProcess = Process(dwProcessId)
            aProcess.scan_threads()
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_thread_hardware_breakpoints(dwThreadId):
                if bp.is_disabled():
                    self.enable_one_shot_hardware_breakpoint(
                        dwThreadId, bp.get_address()
                    )

    def disable_process_breakpoints(self, dwProcessId):
        """
        Disables all breakpoints for the given process.

        :param int dwProcessId: Process global ID.
        """

        # disable code breakpoints
        for bp in self.get_process_code_breakpoints(dwProcessId):
            self.disable_code_breakpoint(dwProcessId, bp.get_address())

        # disable page breakpoints
        for bp in self.get_process_page_breakpoints(dwProcessId):
            self.disable_page_breakpoint(dwProcessId, bp.get_address())

        # disable hardware breakpoints
        if self.system.has_process(dwProcessId):
            aProcess = self.system.get_process(dwProcessId)
        else:
            aProcess = Process(dwProcessId)
            aProcess.scan_threads()
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_thread_hardware_breakpoints(dwThreadId):
                self.disable_hardware_breakpoint(dwThreadId, bp.get_address())

    def erase_process_breakpoints(self, dwProcessId):
        """
        Erases all breakpoints for the given process.

        :param int dwProcessId: Process global ID.
        """

        # disable breakpoints first
        # if an error occurs, no breakpoint is erased
        self.disable_process_breakpoints(dwProcessId)

        ##        # erase hooks
        ##        for address, hook in self.get_process_hooks(dwProcessId):
        ##            self.dont_hook_function(dwProcessId, address)

        # erase code breakpoints
        for bp in self.get_process_code_breakpoints(dwProcessId):
            self.erase_code_breakpoint(dwProcessId, bp.get_address())

        # erase page breakpoints
        for bp in self.get_process_page_breakpoints(dwProcessId):
            self.erase_page_breakpoint(dwProcessId, bp.get_address())

        # erase hardware breakpoints
        if self.system.has_process(dwProcessId):
            aProcess = self.system.get_process(dwProcessId)
        else:
            aProcess = Process(dwProcessId)
            aProcess.scan_threads()
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_thread_hardware_breakpoints(dwThreadId):
                self.erase_hardware_breakpoint(dwThreadId, bp.get_address())

    # ------------------------------------------------------------------------------

    # Internal handlers of debug events.

    def _notify_guard_page(self, event):
        """
        Notify breakpoints of a guard page exception event.

        :param event: Guard page exception event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handle, ``False`` otherwise.
        """
        address = event.get_fault_address()
        pid = event.get_pid()
        bCallHandler = True

        # Align address to page boundary.
        page_address = MemoryAddresses.align_address_to_page_start(address)

        # Do we have an active page breakpoint there?
        key = (pid, page_address)
        if key in self.__pageBP:
            bp = self.__pageBP[key]
            if bp.is_enabled() or bp.is_one_shot():
                # Breakpoint is ours.
                event.continueStatus = win32.DBG_CONTINUE
                ##                event.continueStatus = win32.DBG_EXCEPTION_HANDLED

                # Hit the breakpoint.
                bp.hit(event)

                # Remember breakpoints in RUNNING state.
                if bp.is_running():
                    tid = event.get_tid()
                    self.__add_running_bp(tid, bp)

                # Evaluate the breakpoint condition.
                bCondition = bp.eval_condition(event)

                # If the breakpoint is automatic, run the action.
                # If not, notify the user.
                if bCondition and bp.is_automatic():
                    bp.run_action(event)
                    bCallHandler = False
                else:
                    bCallHandler = bCondition

        # If we don't have a breakpoint here pass the exception to the debugee.
        # This is a normally occurring exception so we shouldn't swallow it.
        else:
            event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

        return bCallHandler

    def _notify_breakpoint(self, event):
        """
        Notify breakpoints of a breakpoint exception event.

        :param event: Breakpoint exception event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handle, ``False`` otherwise.
        """
        address = event.get_exception_address()
        pid = event.get_pid()
        bCallHandler = True

        # Do we have an active code breakpoint there?
        key = (pid, address)
        if key in self.__codeBP:
            bp = self.__codeBP[key]
            if not bp.is_disabled():
                # Change the program counter (PC) to the exception address.
                # This accounts for the change in PC caused by
                # executing the breakpoint instruction, no matter
                # the size of it.
                aThread = event.get_thread()
                aThread.set_pc(address)

                # Swallow the exception.
                event.continueStatus = win32.DBG_CONTINUE

                # Hit the breakpoint.
                bp.hit(event)

                # Remember breakpoints in RUNNING state.
                if bp.is_running():
                    tid = event.get_tid()
                    self.__add_running_bp(tid, bp)

                # Evaluate the breakpoint condition.
                bCondition = bp.eval_condition(event)

                # If the breakpoint is automatic, run the action.
                # If not, notify the user.
                if bCondition and bp.is_automatic():
                    bCallHandler = bp.run_action(event)
                else:
                    bCallHandler = bCondition

        # Handle the system breakpoint.
        # TODO: examine the stack trace to figure out if it's really a
        # system breakpoint or an antidebug trick. The caller should be
        # inside ntdll if it's legit.
        elif event.get_process().is_system_defined_breakpoint(address):
            event.continueStatus = win32.DBG_CONTINUE

        # In hostile mode, if we don't have a breakpoint here pass the
        # exception to the debugee. In normal mode assume all breakpoint
        # exceptions are to be handled by the debugger.
        else:
            if self.in_hostile_mode():
                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
            else:
                event.continueStatus = win32.DBG_CONTINUE

        return bCallHandler

    def _notify_single_step(self, event):
        """
        Notify breakpoints of a single step exception event.

        :param event: Single step exception event.
        :type event: :class:`~winappdbg.event.ExceptionEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handle, ``False`` otherwise.
        """
        tid = event.get_tid()
        aThread = event.get_thread()
        aProcess = event.get_process()
        bCallHandler = True
        bIsOurs = False

        # In hostile mode set the default to pass the exception to the debugee.
        # If we later determine the exception is ours, hide it instead.
        old_continueStatus = event.continueStatus
        try:
            if self.in_hostile_mode():
                event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

            # Single step support is implemented on x86/x64 architectures only.
            if self.system.arch not in (win32.ARCH_I386, win32.ARCH_AMD64):
                return bCallHandler

            # In hostile mode, read the last executed bytes to try to detect
            # some antidebug tricks. Skip this check in normal mode because
            # it'd slow things down.
            #
            # FIXME: weird opcode encodings may bypass this check!
            #
            # bFakeSingleStep: Ice Breakpoint undocumented instruction.
            # bHideTrapFlag: Don't let pushf instructions get the real value of
            #                the trap flag.
            # bNextIsPopFlags: Don't let popf instructions clear the trap flag.
            #
            bFakeSingleStep = False
            bLastIsPushFlags = False
            bNextIsPopFlags = False
            if self.in_hostile_mode():
                pc = aThread.get_pc()
                c = aProcess.read_char(pc - 1)
                if c == b"\xf1":  # int1
                    bFakeSingleStep = True
                elif c == b"\x9c":  # pushf
                    bLastIsPushFlags = True
                c = aProcess.peek_char(pc)
                if c == b"\x66":  # the only valid prefix for popf
                    c = aProcess.peek_char(pc + 1)
                if c == b"\x9d":  # popf
                    if bLastIsPushFlags:
                        bLastIsPushFlags = False  # they cancel each other out
                    else:
                        bNextIsPopFlags = True

            # When the thread is in tracing mode,
            # don't pass the exception to the debugee
            # and set the trap flag again.
            if self.is_tracing(tid):
                bIsOurs = True
                if not bFakeSingleStep:
                    event.continueStatus = win32.DBG_CONTINUE
                aThread.set_tf()

                # Don't let the debugee read or write the trap flag.
                # This code works in 32 and 64 bits thanks to the endianness.
                if bLastIsPushFlags or bNextIsPopFlags:
                    sp = aThread.get_sp()
                    flags = aProcess.read_dword(sp)
                    if bLastIsPushFlags:
                        flags &= ~Thread.Flags.Trap
                    else:  # if bNextIsPopFlags:
                        flags |= Thread.Flags.Trap
                    aProcess.write_dword(sp, flags)

            # Handle breakpoints in RUNNING state.
            running = self.__get_running_bp_set(tid)
            if running:
                bIsOurs = True
                if not bFakeSingleStep:
                    event.continueStatus = win32.DBG_CONTINUE
                bCallHandler = False
                while running:
                    try:
                        running.pop().hit(event)
                    except Exception as e:
                        warnings.warn(str(e), BreakpointWarning)

            # Handle hardware breakpoints.
            if tid in self.__hardwareBP:
                ctx = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
                Dr6 = ctx["Dr6"]
                ctx["Dr6"] = Dr6 & IntelDebugRegister.clearHitMask
                aThread.set_context(ctx)
                bFoundBreakpoint = False
                bCondition = False
                hwbpList = [bp for bp in self.__hardwareBP[tid]]
                for bp in hwbpList:
                    if bp not in self.__hardwareBP[tid]:
                        continue  # it was removed by a user-defined callback
                    slot = bp.get_slot()
                    if (slot is not None) and (Dr6 & IntelDebugRegister.hitMask[slot]):
                        if not bFoundBreakpoint:  # set before actions are called
                            if not bFakeSingleStep:
                                event.continueStatus = win32.DBG_CONTINUE
                        bFoundBreakpoint = True
                        bIsOurs = True
                        bp.hit(event)
                        if bp.is_running():
                            self.__add_running_bp(tid, bp)
                        bThisCondition = bp.eval_condition(event)
                        if bThisCondition and bp.is_automatic():
                            bp.run_action(event)
                            bThisCondition = False
                        bCondition = bCondition or bThisCondition
                if bFoundBreakpoint:
                    bCallHandler = bCondition

            # Always call the user-defined handler
            # when the thread is in tracing mode.
            if self.is_tracing(tid):
                bCallHandler = True

            # If we're not in hostile mode, by default we assume all single
            # step exceptions are caused by the debugger.
            if not bIsOurs and not self.in_hostile_mode():
                aThread.clear_tf()

        # If the user hit Control-C while we were inside the try block,
        # set the default continueStatus back.
        except:
            event.continueStatus = old_continueStatus
            raise

        return bCallHandler

    def _notify_load_dll(self, event):
        """
        Notify the loading of a DLL.

        :param event: Load DLL event.
        :type event: :class:`~winappdbg.event.LoadDLLEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handler, ``False`` otherwise.
        """
        self.__set_deferred_breakpoints(event)
        return True

    def _notify_unload_dll(self, event):
        """
        Notify the unloading of a DLL.

        :param event: Unload DLL event.
        :type event: :class:`~winappdbg.event.UnloadDLLEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handler, ``False`` otherwise.
        """
        self.__cleanup_module(event)
        return True

    def _notify_exit_thread(self, event):
        """
        Notify the termination of a thread.

        :param event: Exit thread event.
        :type event: :class:`~winappdbg.event.ExitThreadEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handler, ``False`` otherwise.
        """
        self.__cleanup_thread(event)
        return True

    def _notify_exit_process(self, event):
        """
        Notify the termination of a process.

        :param event: Exit process event.
        :type event: :class:`~winappdbg.event.ExitProcessEvent`
        :rtype:  bool
        :return: ``True`` to call the user-defined handler, ``False`` otherwise.
        """
        self.__cleanup_process(event)
        self.__cleanup_thread(event)
        return True

    # ------------------------------------------------------------------------------

    # This is the high level breakpoint interface. Here we don't have to care
    # about defining or enabling breakpoints, and many errors are ignored
    # (like for example setting the same breakpoint twice, here the second
    # breakpoint replaces the first, much like in WinDBG). It should be easier
    # and more intuitive, if less detailed. It also allows the use of deferred
    # breakpoints.

    # ------------------------------------------------------------------------------

    # Code breakpoints

    def __set_break(self, pid, address, action, oneshot):
        """
        Used by :meth:`break_at` and :meth:`stalk_at`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        :param callable action: (Optional) Action callback function.
            See :meth:`define_code_breakpoint` for more details.
        :param bool oneshot: ``True`` for one-shot breakpoints, ``False`` otherwise.
        :rtype:  :class:`Breakpoint`
        :return: Returns the new :class:`Breakpoint` object, or ``None`` if the label
            couldn't be resolved and the breakpoint was deferred. Deferred
            breakpoints are set when the DLL they point to is loaded.
        """
        label = address
        if not isinstance(address, int):
            try:
                address = self.system.get_process(pid).resolve_label(address)
                if not address:
                    raise Exception()
            except Exception:
                try:
                    deferred = self.__deferredBP[pid]
                except KeyError:
                    deferred = dict()
                    self.__deferredBP[pid] = deferred
                if label in deferred:
                    msg = "Redefined deferred code breakpoint at %s in process ID %d"
                    msg = msg % (label, pid)
                    warnings.warn(msg, BreakpointWarning)
                deferred[label] = (action, oneshot)
                return None
        if self.has_code_breakpoint(pid, address):
            bp = self.get_code_breakpoint(pid, address)
            if bp.get_action() != action:  # can't use "is not", fails for bound methods
                bp.set_action(action)
                msg = "Redefined code breakpoint at %s in process ID %d"
                msg = msg % (label, pid)
                warnings.warn(msg, BreakpointWarning)
        else:
            self.define_code_breakpoint(pid, address, True, action)
            bp = self.get_code_breakpoint(pid, address)
        if oneshot:
            if not bp.is_one_shot():
                self.enable_one_shot_code_breakpoint(pid, address)
        else:
            if not bp.is_enabled():
                self.enable_code_breakpoint(pid, address)
        return bp

    def __clear_break(self, pid, address):
        """
        Used by :meth:`dont_break_at` and :meth:`dont_stalk_at`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        """
        if not isinstance(address, int):
            unknown = True
            label = address
            try:
                deferred = self.__deferredBP[pid]
                del deferred[label]
                unknown = False
            except KeyError:
                ##                traceback.print_last()      # XXX DEBUG
                pass
            aProcess = self.system.get_process(pid)
            try:
                address = aProcess.resolve_label(label)
                if not address:
                    raise Exception()
            except Exception:
                ##                traceback.print_last()      # XXX DEBUG
                if unknown:
                    msg = "Can't clear unknown code breakpoint at %s in process ID %d"
                    msg = msg % (label, pid)
                    warnings.warn(msg, BreakpointWarning)
                return
        if self.has_code_breakpoint(pid, address):
            self.erase_code_breakpoint(pid, address)

    def __set_deferred_breakpoints(self, event):
        """
        Used internally. Sets all deferred breakpoints for a DLL when it's
        loaded.

        :param event: Load DLL event.
        :type event: :class:`~winappdbg.event.LoadDLLEvent`
        """
        pid = event.get_pid()
        try:
            deferred = self.__deferredBP[pid]
        except KeyError:
            return
        aProcess = event.get_process()
        for label, (action, oneshot) in deferred.items():
            try:
                address = aProcess.resolve_label(label)
            except Exception:
                continue
            del deferred[label]
            try:
                self.__set_break(pid, address, action, oneshot)
            except Exception:
                msg = "Can't set deferred breakpoint %s at process ID %d"
                msg = msg % (label, pid)
                warnings.warn(msg, BreakpointWarning)

    def get_all_deferred_code_breakpoints(self):
        """
        Returns a list of deferred code breakpoints.

        :rtype:  tuple of (int, str, callable, bool)
        :return: Tuple containing the following elements:
             - Process ID where to set the breakpoint.
             - Label pointing to the address where to set the breakpoint.
             - Action callback for the breakpoint.
             - ``True`` of the breakpoint is one-shot, ``False`` otherwise.
        """
        result = []
        for pid, deferred in self.__deferredBP.items():
            for label, (action, oneshot) in deferred.items():
                result.add((pid, label, action, oneshot))
        return result

    def get_process_deferred_code_breakpoints(self, dwProcessId):
        """
        Returns a list of deferred code breakpoints.

        :param int dwProcessId: Process ID.
        :rtype:  tuple of (int, str, callable, bool)
        :return: Tuple containing the following elements:
             - Label pointing to the address where to set the breakpoint.
             - Action callback for the breakpoint.
             - ``True`` of the breakpoint is one-shot, ``False`` otherwise.
        """
        return [
            (label, action, oneshot)
            for (label, (action, oneshot)) in self.__deferredBP.get(
                dwProcessId, {}
            ).items()
        ]

    def stalk_at(self, pid, address, action=None):
        """
        Sets a one shot code breakpoint at the given process and address.

        If instead of an address you pass a label, the breakpoint may be
        deferred until the DLL it points to is loaded.

        :see: :meth:`break_at`, :meth:`dont_stalk_at`

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        :param callable action: (Optional) Action callback function.
            See :meth:`define_code_breakpoint` for more details.
        :rtype:  bool
        :return: ``True`` if the breakpoint was set immediately, or ``False`` if
            it was deferred.
        """
        bp = self.__set_break(pid, address, action, oneshot=True)
        return bp is not None

    def break_at(self, pid, address, action=None):
        """
        Sets a code breakpoint at the given process and address.

        If instead of an address you pass a label, the breakpoint may be
        deferred until the DLL it points to is loaded.

        :see: :meth:`stalk_at`, :meth:`dont_break_at`

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        :param callable action: (Optional) Action callback function.
            See :meth:`define_code_breakpoint` for more details.
        :rtype:  bool
        :return: ``True`` if the breakpoint was set immediately, or ``False`` if
            it was deferred.
        """
        bp = self.__set_break(pid, address, action, oneshot=False)
        return bp is not None

    def dont_break_at(self, pid, address):
        """
        Clears a code breakpoint set by :meth:`break_at`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        """
        self.__clear_break(pid, address)

    def dont_stalk_at(self, pid, address):
        """
        Clears a code breakpoint set by :meth:`stalk_at`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        """
        self.__clear_break(pid, address)

    # ------------------------------------------------------------------------------

    # Function hooks

    def hook_function(
        self,
        pid,
        address,
        preCB=None,
        postCB=None,
        paramCount=None,
        signature=None,
        preCBArgs=None,
        postCBArgs=None,
    ):
        """
        Sets a function hook at the given address.

        If instead of an address you pass a label, the hook may be
        deferred until the DLL it points to is loaded.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        :param callable preCB: (Optional) Callback triggered on function entry.
            The signature for the callback should be something like this::

                def pre_LoadLibraryEx(event, ra, lpFilename, hFile, dwFlags):

                    # return address
                    ra = params[0]

                    # function arguments start from here...
                    szFilename = event.get_process().peek_string(lpFilename)

                    # (...)

            Note that all pointer types are treated like void pointers, so your
            callback won't get the string or structure pointed to by it, but
            the remote memory address instead. This is so to prevent the ctypes
            library from being "too helpful" and trying to dereference the
            pointer. To get the actual data being pointed to, use one of the
            :meth:`~winappdbg.process.Process.read` methods.
        :param callable postCB: (Optional) Callback triggered on function exit.
            The signature for the callback should be something like this::

                def post_LoadLibraryEx(event, return_value):

                    # (...)
        :param int paramCount:
            (Optional) Number of parameters for the ``preCB`` callback,
            not counting the return address. Parameters are read from
            the stack and assumed to be DWORDs in 32 bits and QWORDs in 64.

            This is a faster way to pull stack parameters in 32 bits, but in 64
            bits (or with some odd APIs in 32 bits) it won't be useful, since
            not all arguments to the hooked function will be of the same size.

            For a more reliable and cross-platform way of hooking use the
            ``signature`` argument instead.
        :param tuple signature:
            (Optional) Tuple of ``ctypes`` data types that constitute the
            hooked function signature. When the function is called, this will
            be used to parse the arguments from the stack. Overrides the
            ``paramCount`` argument.
        :rtype:  bool
        :return: ``True`` if the hook was set immediately, or ``False`` if
            it was deferred.
        """
        try:
            aProcess = self.system.get_process(pid)
        except KeyError:
            aProcess = Process(pid)
        arch = aProcess.get_arch()
        hookObj = HookFactory(
            preCB, postCB, paramCount, signature, arch, preCBArgs, postCBArgs
        )
        bp = self.break_at(pid, address, hookObj)
        return bp is not None

    def stalk_function(
        self, pid, address, preCB=None, postCB=None, paramCount=None, signature=None
    ):
        """
        Sets a one-shot function hook at the given address.

        If instead of an address you pass a label, the hook may be
        deferred until the DLL it points to is loaded.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        :param callable preCB: (Optional) Callback triggered on function entry.
            The signature for the callback should be something like this::

                def pre_LoadLibraryEx(event, ra, lpFilename, hFile, dwFlags):

                    # return address
                    ra = params[0]

                    # function arguments start from here...
                    szFilename = event.get_process().peek_string(lpFilename)

                    # (...)

            Note that all pointer types are treated like void pointers, so your
            callback won't get the string or structure pointed to by it, but
            the remote memory address instead. This is so to prevent the ctypes
            library from being "too helpful" and trying to dereference the
            pointer. To get the actual data being pointed to, use one of the
            :meth:`~winappdbg.process.Process.read` methods.
        :param callable postCB: (Optional) Callback triggered on function exit.
            The signature for the callback should be something like this::

                def post_LoadLibraryEx(event, return_value):

                    # (...)
        :param int paramCount:
            (Optional) Number of parameters for the ``preCB`` callback,
            not counting the return address. Parameters are read from
            the stack and assumed to be DWORDs in 32 bits and QWORDs in 64.

            This is a faster way to pull stack parameters in 32 bits, but in 64
            bits (or with some odd APIs in 32 bits) it won't be useful, since
            not all arguments to the hooked function will be of the same size.

            For a more reliable and cross-platform way of hooking use the
            ``signature`` argument instead.
        :param tuple signature:
            (Optional) Tuple of ``ctypes`` data types that constitute the
            hooked function signature. When the function is called, this will
            be used to parse the arguments from the stack. Overrides the
            ``paramCount`` argument.
        :rtype:  bool
        :return: ``True`` if the breakpoint was set immediately, or ``False`` if
            it was deferred.
        """
        try:
            aProcess = self.system.get_process(pid)
        except KeyError:
            aProcess = Process(pid)
        arch = aProcess.get_arch()
        hookObj = HookFactory(preCB, postCB, paramCount, signature, arch)
        bp = self.stalk_at(pid, address, hookObj)
        return bp is not None

    def dont_hook_function(self, pid, address):
        """
        Removes a function hook set by :meth:`hook_function`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        """
        self.dont_break_at(pid, address)

    # alias
    unhook_function = dont_hook_function

    def dont_stalk_function(self, pid, address):
        """
        Removes a function hook set by :meth:`stalk_function`.

        :param int pid: Process global ID.
        :param address:
            Memory address of code instruction to break at. It can be an
            integer value for the actual address or a string with a label
            to be resolved.
        :type address: int or str
        """
        self.dont_stalk_at(pid, address)

    # ------------------------------------------------------------------------------

    # Variable watches

    def __set_variable_watch(self, tid, address, size, action):
        """
        Used by :meth:`watch_variable` and :meth:`stalk_variable`.

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to watch.
        :param int size: Size of variable to watch. The only supported sizes are:
            byte (1), word (2), dword (4) and qword (8).
        :param callable action: (Optional) Action callback function.
            See :meth:`define_hardware_breakpoint` for more details.
        :rtype:  :class:`HardwareBreakpoint`
        :return: Hardware breakpoint at the requested address.
        """

        # TODO
        # We should merge the breakpoints instead of overwriting them.
        # We'll have the same problem as watch_buffer and we'll need to change
        # the API again.

        # This check relies on being subclassed by Debug.
        if not getattr(self, "_hw_bp_available", True):
            raise NotImplementedError("Hardware breakpoints not available")

        if size == 1:
            sizeFlag = self.BP_WATCH_BYTE
        elif size == 2:
            sizeFlag = self.BP_WATCH_WORD
        elif size == 4:
            sizeFlag = self.BP_WATCH_DWORD
        elif size == 8:
            sizeFlag = self.BP_WATCH_QWORD
        else:
            raise ValueError("Bad size for variable watch: %r" % size)

        if self.has_hardware_breakpoint(tid, address):
            warnings.warn(
                "Hardware breakpoint in thread %d at address %s was overwritten!"
                % (
                    tid,
                    HexDump.address(address, self.system.get_thread(tid).get_bits()),
                ),
                BreakpointWarning,
            )

            bp = self.get_hardware_breakpoint(tid, address)
            if (
                bp.get_trigger() != self.BP_BREAK_ON_ACCESS
                or bp.get_watch() != sizeFlag
            ):
                self.erase_hardware_breakpoint(tid, address)
                self.define_hardware_breakpoint(
                    tid, address, self.BP_BREAK_ON_ACCESS, sizeFlag, True, action
                )
                bp = self.get_hardware_breakpoint(tid, address)

        else:
            self.define_hardware_breakpoint(
                tid, address, self.BP_BREAK_ON_ACCESS, sizeFlag, True, action
            )
            bp = self.get_hardware_breakpoint(tid, address)

        return bp

    def __clear_variable_watch(self, tid, address):
        """
        Used by :meth:`dont_watch_variable` and :meth:`dont_stalk_variable`.

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to stop watching.
        """
        if self.has_hardware_breakpoint(tid, address):
            self.erase_hardware_breakpoint(tid, address)

    def watch_variable(self, tid, address, size, action=None):
        """
        Sets a hardware breakpoint at the given thread, address and size.

        :see: :meth:`dont_watch_variable`

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to watch.
        :param int size: Size of variable to watch. The only supported sizes are:
            byte (1), word (2), dword (4) and qword (8).
        :param callable action: (Optional) Action callback function.
            See :meth:`define_hardware_breakpoint` for more details.
        """
        bp = self.__set_variable_watch(tid, address, size, action)
        if not bp.is_enabled():
            self.enable_hardware_breakpoint(tid, address)

    def stalk_variable(self, tid, address, size, action=None):
        """
        Sets a one-shot hardware breakpoint at the given thread,
        address and size.

        :see: :meth:`dont_watch_variable`

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to watch.
        :param int size: Size of variable to watch. The only supported sizes are:
            byte (1), word (2), dword (4) and qword (8).
        :param callable action: (Optional) Action callback function.
            See :meth:`define_hardware_breakpoint` for more details.
        """
        bp = self.__set_variable_watch(tid, address, size, action)
        if not bp.is_one_shot():
            self.enable_one_shot_hardware_breakpoint(tid, address)

    def dont_watch_variable(self, tid, address):
        """
        Clears a hardware breakpoint set by :meth:`watch_variable`.

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to stop watching.
        """
        self.__clear_variable_watch(tid, address)

    def dont_stalk_variable(self, tid, address):
        """
        Clears a hardware breakpoint set by :meth:`stalk_variable`.

        :param int tid: Thread global ID.
        :param int address: Memory address of variable to stop watching.
        """
        self.__clear_variable_watch(tid, address)

    # ------------------------------------------------------------------------------

    # Buffer watches

    def __set_buffer_watch(self, pid, address, size, action, bOneShot):
        """
        Used by :meth:`watch_buffer` and :meth:`stalk_buffer`.

        :param int pid: Process global ID.
        :param int address: Memory address of buffer to watch.
        :param int size: Size in bytes of buffer to watch.
        :param callable action: (Optional) Action callback function.
            See :meth:`define_page_breakpoint` for more details.
        :param bool bOneShot:
            ``True`` to set a one-shot breakpoint,
            ``False`` to set a normal breakpoint.
        """

        # Check the size isn't zero or negative.
        if size < 1:
            raise ValueError("Bad size for buffer watch: %r" % size)

        # Check if the address is on the stack of the current thread.
        # This is because the OS may silently ignore setting guard pages
        # on the stack, as it's already using them for stack growth.
        # TODO: do this by checking all threads in the target process.
        try:
            aThread = self.lastEvent.get_thread()
            stack_min, stack_max = aThread.get_stack_range()
            if address >= stack_min and address < stack_max:
                text = "Buffer at address 0x%x is on the stack of thread %d. "
                text += "The OS may ignore this memory watchpoint."
                text = text % (address, aThread.get_tid())
                warnings.warn(text, BreakpointWarning)
        except Exception:
            pass

        # Create the buffer watch identifier.
        bw = BufferWatch(pid, address, address + size, action, bOneShot)

        # Get the base address and size in pages required for this buffer.
        base = MemoryAddresses.align_address_to_page_start(address)
        limit = MemoryAddresses.align_address_to_page_end(address + size)

        try:
            # For each page:
            #  + if a page breakpoint exists reuse it
            #  + if it doesn't exist define it

            bset = set()  # all breakpoints used
            nset = set()  # newly defined breakpoints
            cset = set()  # condition objects

            page_addr = base
            pageSize = MemoryAddresses.pageSize
            while page_addr < limit:
                # If a breakpoints exists, reuse it.
                if self.has_page_breakpoint(pid, page_addr):
                    bp = self.get_page_breakpoint(pid, page_addr)
                    if bp not in bset:
                        condition = bp.get_condition()
                        if condition not in cset:
                            if not isinstance(condition, _BufferWatchCondition):
                                # this shouldn't happen unless you tinkered
                                # with it or defined your own page breakpoints
                                # manually.
                                msg = "Can't watch buffer at page %s"
                                msg = msg % HexDump.address(page_addr)
                                raise RuntimeError(msg)
                            cset.add(condition)
                        bset.add(bp)

                # If it doesn't, define it.
                else:
                    condition = _BufferWatchCondition()
                    bp = self.define_page_breakpoint(
                        pid, page_addr, 1, condition=condition
                    )
                    bset.add(bp)
                    nset.add(bp)
                    cset.add(condition)

                # Next page.
                page_addr = page_addr + pageSize

            # For each breakpoint, enable it if needed.
            aProcess = self.system.get_process(pid)
            for bp in bset:
                if bp.is_disabled() or bp.is_one_shot():
                    bp.enable(aProcess, None)

        # On error...
        except:
            # Erase the newly defined breakpoints.
            for bp in nset:
                try:
                    self.erase_page_breakpoint(pid, bp.get_address())
                except:
                    pass

            # Pass the exception to the caller
            raise

        # For each condition object, add the new buffer.
        for condition in cset:
            condition.add(bw)

        # Return the buffer watch identifier.
        return bw

    def __clear_buffer_watch_old_method(self, pid, address, size):
        """
        Used by :meth:`dont_watch_buffer` and :meth:`dont_stalk_buffer`.

        .. warning:: Deprecated since WinAppDbg 1.5.

        :param int pid: Process global ID.
        :param int address: Memory address of buffer to stop watching.
        :param int size: Size in bytes of buffer to stop watching.
        """
        warnings.warn("Deprecated since WinAppDbg 1.5", DeprecationWarning)

        # Check the size isn't zero or negative.
        if size < 1:
            raise ValueError("Bad size for buffer watch: %r" % size)

        # Get the base address and size in pages required for this buffer.
        base = MemoryAddresses.align_address_to_page_start(address)
        limit = MemoryAddresses.align_address_to_page_end(address + size)

        # For each page, get the breakpoint and it's condition object.
        # For each condition, remove the buffer.
        # For each breakpoint, if no buffers are on watch, erase it.
        cset = set()  # condition objects
        page_addr = base
        pageSize = MemoryAddresses.pageSize
        while page_addr < limit:
            if self.has_page_breakpoint(pid, page_addr):
                bp = self.get_page_breakpoint(pid, page_addr)
                condition = bp.get_condition()
                if condition not in cset:
                    if not isinstance(condition, _BufferWatchCondition):
                        # this shouldn't happen unless you tinkered with it
                        # or defined your own page breakpoints manually.
                        continue
                    cset.add(condition)
                    condition.remove_last_match(address, size)
                    if condition.count() == 0:
                        try:
                            self.erase_page_breakpoint(pid, bp.get_address())
                        except WindowsError:
                            pass
            page_addr = page_addr + pageSize

    def __clear_buffer_watch(self, bw):
        """
        Used by :meth:`dont_watch_buffer` and :meth:`dont_stalk_buffer`.

        :param bw: Buffer watch identifier.
        :type bw: :class:`BufferWatch`
        """

        # Get the PID and the start and end addresses of the buffer.
        pid = bw.pid
        start = bw.start
        end = bw.end

        # Get the base address and size in pages required for the buffer.
        base = MemoryAddresses.align_address_to_page_start(start)
        limit = MemoryAddresses.align_address_to_page_end(end)

        # For each page, get the breakpoint and it's condition object.
        # For each condition, remove the buffer.
        # For each breakpoint, if no buffers are on watch, erase it.
        cset = set()  # condition objects
        page_addr = base
        pageSize = MemoryAddresses.pageSize
        while page_addr < limit:
            if self.has_page_breakpoint(pid, page_addr):
                bp = self.get_page_breakpoint(pid, page_addr)
                condition = bp.get_condition()
                if condition not in cset:
                    if not isinstance(condition, _BufferWatchCondition):
                        # this shouldn't happen unless you tinkered with it
                        # or defined your own page breakpoints manually.
                        continue
                    cset.add(condition)
                    condition.remove(bw)
                    if condition.count() == 0:
                        try:
                            self.erase_page_breakpoint(pid, bp.get_address())
                        except WindowsError:
                            msg = "Cannot remove page breakpoint at address %s"
                            msg = msg % HexDump.address(bp.get_address())
                            warnings.warn(msg, BreakpointWarning)
            page_addr = page_addr + pageSize

    def watch_buffer(self, pid, address, size, action=None):
        """
        Sets a page breakpoint and notifies when the given buffer is accessed.

        :see: :meth:`dont_watch_variable`

        :param int pid: Process global ID.
        :param int address: Memory address of buffer to watch.
        :param int size: Size in bytes of buffer to watch.
        :param callable action: (Optional) Action callback function.
            See :meth:`define_page_breakpoint` for more details.
        :rtype:  :class:`BufferWatch`
        :return: Buffer watch identifier.
        """
        return self.__set_buffer_watch(pid, address, size, action, False)

    def stalk_buffer(self, pid, address, size, action=None):
        """
        Sets a one-shot page breakpoint and notifies
        when the given buffer is accessed.

        :see: :meth:`dont_watch_variable`

        :param int pid: Process global ID.
        :param int address: Memory address of buffer to watch.
        :param int size: Size in bytes of buffer to watch.
        :param callable action: (Optional) Action callback function.
            See :meth:`define_page_breakpoint` for more details.
        :rtype:  :class:`BufferWatch`
        :return: Buffer watch identifier.
        """
        return self.__set_buffer_watch(pid, address, size, action, True)

    def dont_watch_buffer(self, bw, *argv, **argd):
        """
        Clears a page breakpoint set by :meth:`watch_buffer`.

        :param bw:
            Buffer watch identifier returned by :meth:`watch_buffer`.
        :type bw: :class:`BufferWatch`
        """

        # The sane way to do it.
        if not (argv or argd):
            self.__clear_buffer_watch(bw)

        # Backwards compatibility with WinAppDbg 1.4.
        else:
            argv = list(argv)
            argv.insert(0, bw)
            if "pid" in argd:
                argv.insert(0, argd.pop("pid"))
            if "address" in argd:
                argv.insert(1, argd.pop("address"))
            if "size" in argd:
                argv.insert(2, argd.pop("size"))
            if argd:
                raise TypeError("Wrong arguments for dont_watch_buffer()")
            try:
                pid, address, size = argv
            except ValueError:
                raise TypeError("Wrong arguments for dont_watch_buffer()")
            self.__clear_buffer_watch_old_method(pid, address, size)

    def dont_stalk_buffer(self, bw, *argv, **argd):
        """
        Clears a page breakpoint set by :meth:`stalk_buffer`.

        :param bw:
            Buffer watch identifier returned by :meth:`stalk_buffer`.
        :type bw: :class:`BufferWatch`
        """
        self.dont_watch_buffer(bw, *argv, **argd)

    # ------------------------------------------------------------------------------

    # Tracing

    # XXX TODO
    # Add "action" parameter to tracing mode

    def __start_tracing(self, thread):
        """
        :param thread: Thread to start tracing.
        :type thread: :class:`~winappdbg.thread.Thread`
        """
        tid = thread.get_tid()
        if tid not in self.__tracing:
            thread.set_tf()
            self.__tracing.add(tid)

    def __stop_tracing(self, thread):
        """
        :param thread: Thread to stop tracing.
        :type thread: :class:`~winappdbg.thread.Thread`
        """
        tid = thread.get_tid()
        if tid in self.__tracing:
            self.__tracing.remove(tid)
            if thread.is_alive():
                thread.clear_tf()

    def is_tracing(self, tid):
        """
        :param int tid: Thread global ID.
        :rtype:  bool
        :return: ``True`` if the thread is being traced, ``False`` otherwise.
        """
        return tid in self.__tracing

    def get_traced_tids(self):
        """
        Retrieves the list of global IDs of all threads being traced.

        :rtype:  list of int
        :return: List of thread global IDs.
        """
        tids = list(self.__tracing)
        tids.sort()
        return tids

    def start_tracing(self, tid):
        """
        Start tracing mode in the given thread.

        :param int tid: Global ID of thread to start tracing.
        """
        if not self.is_tracing(tid):
            thread = self.system.get_thread(tid)
            self.__start_tracing(thread)

    def stop_tracing(self, tid):
        """
        Stop tracing mode in the given thread.

        :param int tid: Global ID of thread to stop tracing.
        """
        if self.is_tracing(tid):
            thread = self.system.get_thread(tid)
            self.__stop_tracing(thread)

    def start_tracing_process(self, pid):
        """
        Start tracing mode for all threads in the given process.

        :param int pid: Global ID of process to start tracing.
        """
        for thread in self.system.get_process(pid).iter_threads():
            self.__start_tracing(thread)

    def stop_tracing_process(self, pid):
        """
        Stop tracing mode for all threads in the given process.

        :param int pid: Global ID of process to stop tracing.
        """
        for thread in self.system.get_process(pid).iter_threads():
            self.__stop_tracing(thread)

    def start_tracing_all(self):
        """
        Start tracing mode for all threads in all debugees.
        """
        for pid in self.get_debugee_pids():
            self.start_tracing_process(pid)

    def stop_tracing_all(self):
        """
        Stop tracing mode for all threads in all debugees.
        """
        for pid in self.get_debugee_pids():
            self.stop_tracing_process(pid)

    # ------------------------------------------------------------------------------

    # Break on LastError values (only available since Windows Server 2003)

    def break_on_error(self, pid, errorCode):
        """
        Sets or clears the system breakpoint for a given Win32 error code.

        Use :meth:`~winappdbg.process.Process.is_system_defined_breakpoint` to tell if a breakpoint
        exception was caused by a system breakpoint or by the application
        itself (for example because of a failed assertion in the code).

        .. note:: This functionality is only available since Windows Server 2003.
            In 2003 it only breaks on error values set externally to the
            kernel32.dll library, but this was fixed in Windows Vista.

        .. warning:: This method will fail if the debug symbols for ntdll (kernel32
            in Windows 2003) are not present. For more information see:
            :meth:`~winappdbg.system.System.fix_symbol_store_path`.

        :see: `http://www.nynaeve.net/?p=147 <http://www.nynaeve.net/?p=147>`__

        :param int pid: Process ID.
        :param int errorCode: Win32 error code to stop on. Set to ``0`` or
            ``ERROR_SUCCESS`` to clear the breakpoint instead.
        :raises NotImplementedError:
            The functionality is not supported in this system.
        :raises WindowsError:
            An error occurred while processing this request.
        """
        aProcess = self.system.get_process(pid)
        address = aProcess.get_break_on_error_ptr()
        if not address:
            raise NotImplementedError(
                "The functionality is not supported in this system."
            )
        aProcess.write_dword(address, errorCode)

    def dont_break_on_error(self, pid):
        """
        Alias to ``break_on_error(pid, ERROR_SUCCESS)``.

        :param int pid: Process ID.
        :raises NotImplementedError:
            The functionality is not supported in this system.
        :raises WindowsError:
            An error occurred while processing this request.
        """
        self.break_on_error(pid, 0)

    # ------------------------------------------------------------------------------

    # Simplified symbol resolving, useful for hooking functions

    def resolve_exported_function(self, pid, modName, procName):
        """
        Resolves the exported DLL function for the given process.

        :param int pid: Process global ID.
        :param str modName: Name of the module that exports the function.
        :param str procName: Name of the exported function to resolve.
        :rtype:  int or None
        :return: On success, the address of the exported function.
            On failure, returns ``None``.
        """
        aProcess = self.system.get_process(pid)
        aModule = aProcess.get_module_by_name(modName)
        if not aModule:
            aProcess.scan_modules()
            aModule = aProcess.get_module_by_name(modName)
        if aModule:
            address = aModule.resolve(procName)
            return address
        return None

    def resolve_label(self, pid, label):
        """
        Resolves a label for the given process.

        :param int pid: Process global ID.
        :param str label: Label to resolve.
        :rtype:  int
        :return: Memory address pointed to by the label.
        :raises ValueError: The label is malformed or impossible to resolve.
        :raises RuntimeError: Cannot resolve the module or function.
        """
        return self.get_process(pid).resolve_label(label)
