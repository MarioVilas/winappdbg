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
Breakpoints library.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/HowBreakpointsWork}

@group Breakpoints: Breakpoint, CodeBreakpoint, PageBreakpoint, HardwareBreakpoint
@group Debug registers manipulation: DebugRegister
@group API hooking action stub: ApiHook
@group Breakpoint container capabilities: BreakpointContainer
"""

__all__ = [

    # Base class for breakpoints
    'Breakpoint',

    # Breakpoint implementations
    'CodeBreakpoint',
    'PageBreakpoint',
    'HardwareBreakpoint',

    # Debug registers manipulation
    'DebugRegister',

    # API hooking action stub
    'ApiHook',

    # Breakpoint container capabilities
    'BreakpointContainer',

    ]

from system import processidparam, threadidparam
import win32

#==============================================================================

class Breakpoint (object):
    """
    Base class for breakpoints.
    Here's the breakpoints state machine.
    
    @see: L{CodeBreakpoint}, L{PageBreakpoint}, L{HardwareBreakpoint}
    
    @group Breakpoint states:
        DISABLED, ENABLED, ONESHOT, RUNNING
    @group State machine:
        hit, disable, enable, one_shot, running,
        is_disabled, is_enabled, is_one_shot, is_running,
        get_state, get_state_name
    @group Information:
        get_address, get_size, is_here, is_active
    @group Conditional breakpoints:
        is_conditional, is_unconditional,
        get_condition, set_condition, eval_condition
    @group Automatic breakpoints:
        is_automatic, is_interactive,
        get_action, set_action, run_action
    
    @cvar DISABLED: Disabled S{->} Enabled, OneShot, Running
    @cvar ENABLED:  Enabled  S{->} Disabled, Running
    @cvar ONESHOT:  OneShot  S{->} Disabled
    @cvar RUNNING:  Running  S{->} Enabled, Disabled
    
    @type DISABLED: int
    @type ENABLED:  int
    @type ONESHOT:  int
    @type RUNNING:  int
    
    @type stateNames: dict E{lb} int S{->} str E{rb}
    @cvar stateNames: User-friendly names for each breakpoint state.
    
    @type typeName: str
    @cvar typeName: User friendly breakpoint type string.
    """

    # I don't think transitions Enabled <-> OneShot should be allowed... plus
    #  it would require special handling to avoid setting the same bp twice

    DISABLED    = 0
    ENABLED     = 1
    ONESHOT     = 2
    RUNNING     = 3

    typeName    = 'breakpoint'

    stateNames  = {
        DISABLED    :   'disabled',
        ENABLED     :   'enabled',
        ONESHOT     :   'one shot',
        RUNNING     :   'running',
    }

    def __init__(self, address, size = 1, condition = True, action = None):
        """
        Breakpoint object.
        
        @type  address: 
        @param address: Memory address for breakpoint.
        
        @type  size: 
        @param size: Size of breakpoint in bytes (defaults to 1).
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
            
            The callback signature is::
                
                def condition_callback(event):
                    return True     # returns True or False
            
            Where B{event} is an L{Event} object,
            and the return value is a boolean
            (True to dispatch the event, False otherwise).
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            
            The callback signature is::
                
                def action_callback(event):
                    pass        # no return value
            
            Where B{event} is an L{Event} object.
        """
        self.__address   = address
        self.__size      = size
        self.__state     = self.DISABLED

        self.set_condition(condition)
        self.set_action(action)

    def __repr__(self):
        if self.is_disabled():
            state = 'Disabled'
        else:
            state = 'Active (%s)' % self.get_state_name()
        if self.get_condition() is True:
            condition = 'unconditional'
        else:
            condition = 'conditional'
        name = self.typeName
        size = self.get_size()
        if size == 1:
            address = "0x%.08x" % self.get_address()
        else:
            begin   = self.get_address()
            end     = begin + size
            address = "range 0x%.08x-0x%.08x" % (begin, end)
        msg = "<%s %s %s at remote address %s>"
        msg = msg % (state, condition, name, address)
        return msg

#------------------------------------------------------------------------------

    def is_disabled(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is in DISABLED state.
        """
        return self.get_state() == self.DISABLED

    def is_enabled(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is in ENABLED state.
        """
        return self.get_state() == self.ENABLED

    def is_one_shot(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is in ONESHOT state.
        """
        return self.get_state() == self.ONESHOT

    def is_running(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is in RUNNING state.
        """
        return self.get_state() == self.RUNNING

    def is_active(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is in ENABLED or ONESHOT state.
        """
        return self.get_state() in (self.ENABLED, self.ONESHOT)

    def is_here(self, address):
        """
        @rtype:  bool
        @return: True if the address is within the range of the breakpoint.
        """
        begin = self.get_address()
        end   = begin + self.get_size()
        return begin <= address < end

    def get_address(self):
        """
        @rtype:  int
        @return: The target memory address for the breakpoint.
        """
        return self.__address

    def get_size(self):
        """
        @rtype:  int
        @return: The size in bytes of the breakpoint.
        """
        return self.__size

    def get_state(self):
        """
        @rtype:  int
        @return: The current state of the breakpoint
            (L{DISABLED}, L{ENABLED}, L{ONESHOT}, L{RUNNING}).
        """
        return self.__state

    def get_state_name(self):
        """
        @rtype:  str
        @return: The name of the current state of the breakpoint.
        """
        return self.stateNames[ self.get_state() ]

#------------------------------------------------------------------------------

    def is_conditional(self):
        """
        @see: L{__init__}
        @rtype:  bool
        @return: True if the breakpoint is has a condition callback defined.
        """
        return self.__condition is not True

    def is_unconditional(self):
        """
        @rtype:  bool
        @return: True if the breakpoint is doesn't have a condition callback defined.
        """
        return self.__condition is True

    def get_condition(self):
        """
        @rtype:  bool, function
        @return: Returns the condition callback for conditional breakpoints.
            Returns True for unconditional breakpoints.
        """
        return self.__condition

    def set_condition(self, condition = True):
        """
        Sets a new condition callback for the breakpoint.
        
        @see: L{__init__}
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
        """
        if condition in (False, None):
            condition = True
        self.__condition = condition

    def eval_condition(self, event):
        """
        Evaluates the breakpoint condition, if any was set.
        
        @type  event: L{Event}
        @param event: Debug event triggered by the breakpoint.
        
        @rtype:  bool
        @return: True to dispatch the event, False otherwise.
        """
        if self.__condition in (True, False, None):
            return self.__condition
        return self.__condition(event)

#------------------------------------------------------------------------------

    def is_automatic(self):
        """
        @rtype:  bool
        @return: True if the breakpoint has an action callback defined.
        """
        return self.__action is not None

    def is_interactive(self):
        """
        @rtype:  bool
        @return: True if the breakpoint doesn't have an action callback defined.
        """
        return self.__action is None

    def get_action(self):
        """
        @rtype:  bool, function
        @return: Returns the action callback for automatic breakpoints.
            Returns None for interactive breakpoints.
        """
        return self.__action

    def set_action(self, action = None):
        """
        Sets a new action callback for the breakpoint.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
        """
        self.__action = action

    def run_action(self, event):
        """
        Executes the breakpoint action callback, if any was set.
        
        @type  event: L{Event}
        @param event: Debug event triggered by the breakpoint.
        """
        if self.__action is not None:
            return bool( self.__action(event) )
        return True

#------------------------------------------------------------------------------

    def __bad_transition(self, state):
        """
        Raise an exception for an invalid state transition.
        
        @see: L{stateNames}
        
        @type  state: int
        @param state: Intended breakpoint state.
        
        @raise Exception: Always.
        """
        statemsg = ""
        oldState = self.stateNames[ self.get_state() ]
        newState = self.stateNames[ state ]
        msg = "Invalid state transition (%s -> %s)" \
              " for breakpoint at address 0x%08x"
        msg = msg % (oldState, newState, self.get_address())
        raise Exception, msg

    def disable(self, aProcess, aThread):
        """
        Transition to Disabled state.
          - Enabled, OneShot, Running S{->} Disabled
          - Can be forced by the user.
          - Transition from running state may require special handling
            by the breakpoint implementation class.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__state not in (self.ENABLED, self.ONESHOT, self.RUNNING):
            self.__bad_transition(self.DISABLED)
        self.__state = self.DISABLED

    def enable(self, aProcess, aThread):
        """
        Transition to Enabled state.
          - Disabled, Running S{->} Enabled
          - Can be forced by the user.
          - Transition from running state may require special handling
            by the breakpoint implementation class.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__state not in (self.DISABLED, self.RUNNING):
            self.__bad_transition(self.DISABLED)
        self.__state = self.ENABLED

    def one_shot(self, aProcess, aThread):
        """
        Transition to OneShot state.
          - Disabled S{->} OneShot
          - Can be forced by the user.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__state != self.DISABLED:
            self.__bad_transition(self.ONESHOT)
        self.__state = self.ONESHOT

    def running(self, aProcess, aThread):
        """
        Transition to Running state.
          - Enabled S{->} Running
          - Only occurs on breakpoint hit.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__state != self.ENABLED:
            self.__bad_transition(self.RUNNING)
        self.__state = self.RUNNING

    def hit(self, event):
        """
        Notify a breakpoint that it's been hit.
        This triggers the corresponding state transition.
        
        @type  event: L{Event}
        @param event: Debug event to handle (depends on the breakpoint type).
        
        @raise AssertionError: Disabled breakpoints can't be hit.
        """
        aProcess = event.get_process()
        aThread  = event.get_thread()
        state    = self.get_state()

        if state == self.ENABLED:
            self.running(aProcess, aThread)

        elif state == self.RUNNING:
            self.enable(aProcess, aThread)

        elif state == self.ONESHOT:
            self.disable(aProcess, aThread)

        elif state == self.DISABLED:
            # this should not happen
            msg = "Hit a disabled breakpoint at address 0x%08x"
            msg = msg % self.get_address()
            raise AssertionError, msg

#==============================================================================

class CodeBreakpoint (Breakpoint):
    """
    Code execution breakpoints (using an int3 opcode).
    
    @see: L{Debug.break_at}
    
    @type int3: str
    @cvar int3: Breakpoint instruction for Intel x86 processors.
    """

    typeName = 'code breakpoint'
    int3     = '\xCC'

    def __init__(self, address, condition = True, action = None):
        """
        Code breakpoint object.
        
        @see: L{Breakpoint.__init__}
        
        @type  address: int
        @param address: Memory address for breakpoint.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
        """
        Breakpoint.__init__(self, address, len(self.int3), condition, action)
        self.__previousValue = self.int3

    def __set_bp(self, aProcess):
        """
        Write a breakpoint instruction in the target address.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        """
        self.__previousValue = aProcess.read(self.get_address(), 1)
        aProcess.write(self.get_address(), self.int3)

    def __clear_bp(self, aProcess):
        """
        Restore the original byte at the target address.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        """
        aProcess.write(self.get_address(), self.__previousValue)

    def disable(self, aProcess, aThread):
        self.__clear_bp(aProcess)
        if self.is_running():
            aThread.clear_tf()
        super(CodeBreakpoint, self).disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        self.__set_bp(aProcess)
        super(CodeBreakpoint, self).enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        self.__set_bp(aProcess)
        super(CodeBreakpoint, self).one_shot(aProcess, aThread)

    # FIXME race condition here
    # If another thread runs on over the target address while
    # the breakpoint is in RUNNING state, we'll miss it. There
    # is a solution to this but it's somewhat complicated, so
    # I'm leaving it for the next version of the debugger. :(
    def running(self, aProcess, aThread):
        self.__clear_bp(aProcess)
        aThread.set_tf()
        super(CodeBreakpoint, self).running(aProcess, aThread)

#==============================================================================

class PageBreakpoint (Breakpoint):
    """
    Page access breakpoint (using guard pages).
    
    @see: L{Debug.watch_buffer}
    
    @type pageSize: int
    @cvar pageSize: Page size in bytes. Defaults to 0x1000 but it's
        automatically updated on runtime when importing the module.
    """

    typeName = 'page breakpoint'
    pageSize = 0x1000

    # Try to update the pageSize value on runtime,
    # ignoring exceptions on failure.
    try:
        pageSize = win32.GetSystemInfo().dwPageSize
    except WindowsError:
        pass

    @classmethod
    def align_address_to_page_start(cls, address):
        """
        Align the given address to the start of the page it occupies.
        
        @type  address: int
        @param address: Memory address.
        
        @rtype:  int
        @return: Aligned memory address.
        """
        return address - ( address % cls.pageSize )

    @classmethod
    def align_address_to_page_end(cls, address):
        """
        Align the given address to the end of the page it occupies.
        
        @type  address: int
        @param address: Memory address.
        
        @rtype:  int
        @return: Aligned memory address.
        """
        return address + cls.pageSize - ( address % cls.pageSize )

    @classmethod
    def align_address_range(cls, begin, end):
        """
        Align the given address range to the start and end of the page(s) it occupies.
        
        @type  begin: int
        @param begin: Memory address of the beginning of the buffer.
        
        @type  end: int
        @param end: Memory address of the end of the buffer.
        
        @rtype:  tuple( int, int )
        @return: Aligned memory addresses.
        """
        if end > begin:
            begin, end = end, begin
        return (
            cls.align_address_to_page_start(begin),
            cls.align_address_to_page_end(end)
            )

    @classmethod
    def get_buffer_size_in_pages(cls, address, size):
        """
        Get the number of pages in use by the given buffer.
        
        @type  address: int
        @param address: Aligned memory address.
        
        @type  size: int
        @param size: Buffer size.
        
        @rtype:  int
        @return: Buffer size in number of pages.
        """
        if size < 0:
            size    = -size
            address = address - size
        begin, end = cls.align_address_range(address, address + size)
        return (end - begin) / cls.pageSize

#------------------------------------------------------------------------------

    def __init__(self, address, pages = 1, condition = True, action = None):
        """
        Page breakpoint object.
        
        @see: L{Breakpoint.__init__}
        
        @type  address: int
        @param address: Memory address for breakpoint.
        
        @type  pages: int
        @param address: Size of breakpoint in pages.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
        """
        Breakpoint.__init__(self, address, pages * self.pageSize, condition,
                                                                        action)
##        if (address & 0x00000FFF) != 0:
        if long(address) / self.pageSize != float(address) / self.pageSize:
            msg   = "Address of page breakpoint "               \
                    "must be aligned to a page size boundary "  \
                    "(value 0x%.08x received)" % address
            raise ValueError, msg

    def get_size_in_pages(self):
        """
        @rtype:  int
        @return: The size in pages of the breakpoint.
        """
        # The size is always a multiple of the page size.
        return self.get_size() / self.pageSize

    def __set_bp(self, aProcess):
        """
        Set the target pages as guard pages.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        """
        lpAddress    = self.get_address()
        dwSize       = self.get_size()
        flNewProtect = aProcess.mquery(lpAddress).Protect
        flNewProtect = flNewProtect | win32.PAGE_GUARD
        aProcess.mprotect(lpAddress, dwSize, flNewProtect)

    def __clear_bp(self, aProcess):
        """
        Restore the original permissions of the target pages.
        
        @type  aProcess: L{Process}
        @param aProcess: Process object.
        """
        lpAddress    = self.get_address()
        flNewProtect = aProcess.mquery(lpAddress).Protect
        flNewProtect = flNewProtect & (0xFFFFFFFF ^ win32.PAGE_GUARD)
        aProcess.mprotect(lpAddress, self.get_size(), flNewProtect)

    def disable(self, aProcess, aThread):
        self.__clear_bp(aProcess)
        if self.is_running():
            aThread.clear_tf()
        super(PageBreakpoint, self).disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        self.__set_bp(aProcess)
        super(PageBreakpoint, self).enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        self.__set_bp(aProcess)
        super(PageBreakpoint, self).one_shot(aProcess, aThread)

    def running(self, aProcess, aThread):
        aThread.set_tf()
        super(PageBreakpoint, self).running(aProcess, aThread)

#==============================================================================

class DebugRegister (object):
    """
    Class to manipulate debug registers.
    Used by L{HardwareBreakpoint}.
    
    @group Trigger flags used by HardwareBreakpoint:
        BREAK_ON_EXECUTION, BREAK_ON_WRITE, BREAK_ON_ACCESS, BREAK_ON_IO_ACCESS
    @group Size flags used by HardwareBreakpoint:
        WATCH_BYTE, WATCH_WORD, WATCH_DWORD, WATCH_QWORD
    @group Bitwise masks for Dr7:
        enableMask, disableMask, triggerMask, watchMask, clearMask
    @group Bitwise masks for Dr6:
        hitMask
    
    @type BREAK_ON_EXECUTION: int
    @cvar BREAK_ON_EXECUTION: Break on execution.
    
    @type BREAK_ON_WRITE: int
    @cvar BREAK_ON_WRITE: Break on write.
    
    @type BREAK_ON_ACCESS: int
    @cvar BREAK_ON_ACCESS: Break on read or write.
    
    @type BREAK_ON_IO_ACCESS: int
    @cvar BREAK_ON_IO_ACCESS: Not used by current hardware.
    
    @type WATCH_BYTE: int
    @cvar WATCH_BYTE: Watch a byte.
    
    @type WATCH_WORD: int
    @cvar WATCH_WORD: Watch a word.
    
    @type WATCH_DWORD: int
    @cvar WATCH_DWORD: Watch a double word.
    
    @type WATCH_QWORD: int
    @cvar WATCH_QWORD: Watch one quad word.
    
    @type enableMask: 4-tuple of integers
    @cvar enableMask:
        Enable bit on Dr7 for each slot.
        Works as a bitwise-OR mask.
    
    @type disableMask: 4-tuple of integers
    @cvar disableMask:
        Mask of the enable bit on Dr7 for each slot.
        Works as a bitwise-AND mask.
    
    @type triggerMask: 4-tuple of 2-tuples of integers
    @cvar triggerMask:
        Trigger bits on Dr7 for each trigger flag value.
        Each 2-tuple has the bitwise-OR mask and the bitwise-AND mask.
    
    @type watchMask: 4-tuple of 2-tuples of integers
    @cvar watchMask:
        Watch bits on Dr7 for each watch flag value.
        Each 2-tuple has the bitwise-OR mask and the bitwise-AND mask.
    
    @type clearMask: 4-tuple of integers
    @cvar clearMask:
        Mask of all important bits on Dr7 for each slot.
        Works as a bitwise-AND mask.
    
    @type hitMask: 4-tuple of integers
    @cvar hitMask:
        Hit bit on Dr6 for each slot.
        Works as a bitwise-AND mask.
    """

    BREAK_ON_EXECUTION  = 0
    BREAK_ON_WRITE      = 1
    BREAK_ON_ACCESS     = 3
    BREAK_ON_IO_ACCESS  = 2

    WATCH_BYTE  = 0
    WATCH_WORD  = 1
    WATCH_DWORD = 3
    WATCH_QWORD = 2

#------------------------------------------------------------------------------

    # http://en.wikipedia.org/wiki/Debug_register

    # DR7 - Debug control
    #
    # The low-order eight bits of DR7 (0,2,4,6 and 1,3,5,7) selectively enable
    # the four address breakpoint conditions. There are two levels of enabling:
    # the local (0,2,4,6) and global (1,3,5,7) levels. The local enable bits
    # are automatically reset by the processor at every task switch to avoid
    # unwanted breakpoint conditions in the new task. The global enable bits
    # are not reset by a task switch; therefore, they can be used for
    # conditions that are global to all tasks.
    #
    # Bits 16-17 (DR0), 20-21 (DR1), 24-25 (DR2), 28-29 (DR3), define when
    # breakpoints trigger. Each breakpoint has a two-bit entry that specifies
    # whether they break on execution (00b), data write (01b), data read or
    # write (11b). 10b is defined to mean break on IO read or write but no
    # hardware supports it. Bits 18-19 (DR0), 22-23 (DR1), 26-27 (DR2), 30-31
    # (DR3), define how large area of memory is watched by breakpoints. Again
    # each breakpoint has a two-bit entry that specifies whether they watch
    # one (00b), two (01b), eight (10b) or four (11b) bytes.

    # This could easily be calculated on runtime in only one method,
    # but it's faster to have it precalculated like this.

    # Dr7 |= enableMask[register]
    enableMask = (
        1 << 0,     # Dr0 (bit 0)
        1 << 2,     # Dr1 (bit 2)
        1 << 4,     # Dr2 (bit 4)
        1 << 6,     # Dr3 (bit 6)
    )

    # Dr7 &= disableMask[register]
    disableMask = tuple( [0xFFFFFFFF ^ x for x in enableMask] )
    del x

    # orMask, andMask = triggerMask[register][trigger]
    # Dr7 = (Dr7 & andMask) | orMask    # to set
    # Dr7 = Dr7 & andMask               # to remove
    triggerMask = (
        # Dr0 (bits 16-17)
        (
            ((0 << 16), (3 << 16) ^ 0xFFFFFFFF),    # execute
            ((1 << 16), (3 << 16) ^ 0xFFFFFFFF),    # write
            ((2 << 16), (3 << 16) ^ 0xFFFFFFFF),    # io read
            ((3 << 16), (3 << 16) ^ 0xFFFFFFFF),    # access
        ),
        # Dr1 (bits 20-21)
        (
            ((0 << 20), (3 << 20) ^ 0xFFFFFFFF),    # execute
            ((1 << 20), (3 << 20) ^ 0xFFFFFFFF),    # write
            ((2 << 20), (3 << 20) ^ 0xFFFFFFFF),    # io read
            ((3 << 20), (3 << 20) ^ 0xFFFFFFFF),    # access
        ),
        # Dr2 (bits 24-25)
        (
            ((0 << 24), (3 << 24) ^ 0xFFFFFFFF),    # execute
            ((1 << 24), (3 << 24) ^ 0xFFFFFFFF),    # write
            ((2 << 24), (3 << 24) ^ 0xFFFFFFFF),    # io read
            ((3 << 24), (3 << 24) ^ 0xFFFFFFFF),    # access
        ),
        # Dr3 (bits 28-29)
        (
            ((0 << 28), (3 << 28) ^ 0xFFFFFFFF),    # execute
            ((1 << 28), (3 << 28) ^ 0xFFFFFFFF),    # write
            ((2 << 28), (3 << 28) ^ 0xFFFFFFFF),    # io read
            ((3 << 28), (3 << 28) ^ 0xFFFFFFFF),    # access
        ),
    )

    # orMask, andMask = watchMask[register][watch]
    # Dr7 = (Dr7 & andMask) | orMask    # to set
    # Dr7 = Dr7 & andMask               # to remove
    watchMask = (
        # Dr0 (bits 18-19)
        (
            ((0 << 18), (3 << 18) ^ 0xFFFFFFFF),    # byte
            ((1 << 18), (3 << 18) ^ 0xFFFFFFFF),    # word
            ((2 << 18), (3 << 18) ^ 0xFFFFFFFF),    # qword
            ((3 << 18), (3 << 18) ^ 0xFFFFFFFF),    # dword
        ),
        # Dr1 (bits 22-23)
        (
            ((0 << 23), (3 << 23) ^ 0xFFFFFFFF),    # byte
            ((1 << 23), (3 << 23) ^ 0xFFFFFFFF),    # word
            ((2 << 23), (3 << 23) ^ 0xFFFFFFFF),    # qword
            ((3 << 23), (3 << 23) ^ 0xFFFFFFFF),    # dword
        ),
        # Dr2 (bits 26-27)
        (
            ((0 << 26), (3 << 26) ^ 0xFFFFFFFF),    # byte
            ((1 << 26), (3 << 26) ^ 0xFFFFFFFF),    # word
            ((2 << 26), (3 << 26) ^ 0xFFFFFFFF),    # qword
            ((3 << 26), (3 << 26) ^ 0xFFFFFFFF),    # dword
        ),
        # Dr3 (bits 30-31)
        (
            ((0 << 30), (3 << 31) ^ 0xFFFFFFFF),    # byte
            ((1 << 30), (3 << 31) ^ 0xFFFFFFFF),    # word
            ((2 << 30), (3 << 31) ^ 0xFFFFFFFF),    # qword
            ((3 << 30), (3 << 31) ^ 0xFFFFFFFF),    # dword
        ),
    )

    # Dr7 = Dr7 & clearMask[register]
    clearMask = (
        0xFFFFFFFF ^ ( (1 << 0) + (3 << 16) + (3 << 18) ),  # Dr0
        0xFFFFFFFF ^ ( (1 << 2) + (3 << 20) + (3 << 22) ),  # Dr1
        0xFFFFFFFF ^ ( (1 << 4) + (3 << 24) + (3 << 26) ),  # Dr2
        0xFFFFFFFF ^ ( (1 << 6) + (3 << 28) + (3 << 30) ),  # Dr3
    )

    # DR6 - Debug status
    #
    # The debug status register permits the debugger to determine which debug
    # conditions have occurred. When the processor detects an enabled debug
    # exception, it sets the low-order bits of this register (0,1,2,3) before
    # entering the debug exception handler.
    #
    # Note that the bits of DR6 are never cleared by the processor. To avoid
    # any confusion in identifying the next debug exception, the debug handler
    # should move zeros to DR6 immediately before returning.

    # bool(Dr6 & hitMask[register])
    hitMask = (
        (1 << 0),   # Dr0
        (1 << 1),   # Dr1
        (1 << 2),   # Dr2
        (1 << 3),   # Dr3
    )

#------------------------------------------------------------------------------

    @classmethod
    def clear_bp(cls, ctx, register):
        """
        Clear a hardware breakpoint.
        
        @see: find_slot, set_bp
        
        @type  ctx: dict
        @param ctx: Thread context dictionary.
        
        @type  register: int
        @param register: Slot (debug register) for hardware breakpoint.
        """
        ctx['Dr7'] &= cls.clearMask[register]
        ctx['Dr%d' % register] = 0

    @classmethod
    def set_bp(cls, ctx, register, address, trigger, watch):
        """
        Set a hardware breakpoint.
        
        @see: clear_bp, find_slot
        
        @type  ctx: dict
        @param ctx: Thread context dictionary.
        
        @type  register: int
        @param register: Slot (debug register).
        
        @type  address: int
        @param address: Memory address.
        
        @type  trigger: int
        @param trigger: Trigger flag.
        
        @type  watch: int
        @param watch: Watch flag.
        """
        Dr7 = ctx['Dr7']
        Dr7 |= cls.enableMask[register]
        orMask, andMask = cls.triggerMask[register][trigger]
        Dr7 &= andMask
        Dr7 |= orMask
        orMask, andMask = cls.watchMask[register][watch]
        Dr7 &= andMask
        Dr7 |= orMask
        ctx['Dr7'] = Dr7
        ctx['Dr%d' % register] = address

    @classmethod
    def find_slot(cls, ctx):
        """
        Find an empty slot to set a hardware breakpoint.
        
        @see: clear_bp, set_bp
        
        @type  ctx: dict
        @param ctx: Thread context dictionary.
        
        @rtype:  int
        @return: Slot (debug register) for hardware breakpoint.
        """
        Dr7  = ctx['Dr7']
        slot = 0
        for m in cls.enableMask:
            if (Dr7 & m) == 0:
                return slot
            slot += 1
        return None

#==============================================================================

class HardwareBreakpoint (Breakpoint):
    """
    Hardware breakpoint (using debug registers).
    
    @see: L{Debug.watch_variable}
    @group Trigger flags:
        BREAK_ON_EXECUTION, BREAK_ON_WRITE, BREAK_ON_ACCESS, BREAK_ON_IO_ACCESS
    @group Watch size flags:
        WATCH_BYTE, WATCH_WORD, WATCH_DWORD, WATCH_QWORD
    
    @type BREAK_ON_EXECUTION: int
    @cvar BREAK_ON_EXECUTION: Break on execution.
    
    @type BREAK_ON_WRITE: int
    @cvar BREAK_ON_WRITE: Break on write.
    
    @type BREAK_ON_ACCESS: int
    @cvar BREAK_ON_ACCESS: Break on read or write.
    
    @type BREAK_ON_IO_ACCESS: int
    @cvar BREAK_ON_IO_ACCESS: Not used by current hardware.
    
    @type WATCH_BYTE: int
    @cvar WATCH_BYTE: Watch a byte.
    
    @type WATCH_WORD: int
    @cvar WATCH_WORD: Watch a word.
    
    @type WATCH_DWORD: int
    @cvar WATCH_DWORD: Watch a double word.
    
    @type WATCH_QWORD: int
    @cvar WATCH_QWORD: Watch one quad word.
    
    @type validTriggers: tuple
    @cvar validTriggers: Valid trigger flag values.
    
    @type validWatchSizes: tuple
    @cvar validWatchSizes: Valid watch flag values.
    """

    typeName = 'hardware breakpoint'

    BREAK_ON_EXECUTION  = DebugRegister.BREAK_ON_EXECUTION
    BREAK_ON_WRITE      = DebugRegister.BREAK_ON_WRITE
    BREAK_ON_ACCESS     = DebugRegister.BREAK_ON_ACCESS
    BREAK_ON_IO_ACCESS  = DebugRegister.BREAK_ON_IO_ACCESS

    WATCH_BYTE  = DebugRegister.WATCH_BYTE
    WATCH_WORD  = DebugRegister.WATCH_WORD
    WATCH_DWORD = DebugRegister.WATCH_DWORD
    WATCH_QWORD = DebugRegister.WATCH_QWORD

    validTriggers = (
        BREAK_ON_EXECUTION,
        BREAK_ON_WRITE,
        BREAK_ON_ACCESS,
        BREAK_ON_IO_ACCESS,     # not supported by hardware
    )

    validWatchSizes = (
        WATCH_BYTE,
        WATCH_WORD,
        WATCH_DWORD,
        WATCH_QWORD,
    )

    def __init__(self, address,                 triggerFlag = BREAK_ON_ACCESS,
                                                   sizeFlag = WATCH_DWORD,
                                                  condition = True,
                                                     action = None):
        """
        Hardware breakpoint object.
        
        @see: L{Breakpoint.__init__}
        
        @type  address: int
        @param address: Memory address for breakpoint.
        
        @type  triggerFlag: int
        @param triggerFlag: Trigger of breakpoint. Must be one of the following:
            
             - L{BREAK_ON_EXECUTION}
               
               Break on code execution.
            
             - L{BREAK_ON_WRITE}
               
               Break on memory read or write.
            
             - L{BREAK_ON_ACCESS}
               
               Break on memory write.
        
        @type  sizeFlag: int
        @param sizeFlag: Size of breakpoint. Must be one of the following:
            
             - L{WATCH_BYTE}
               
               One (1) byte in size.
            
             - L{WATCH_WORD}
               
               Two (2) bytes in size.
            
             - L{WATCH_DWORD}
               
               Four (4) bytes in size.
            
             - L{WATCH_QWORD}
               
               Eight (8) bytes in size.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
        """
        if   sizeFlag == self.WATCH_BYTE:
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
            raise ValueError, msg

        if triggerFlag not in self.validTriggers:
            msg = "Invalid trigger flag for hardware breakpoint (%s)"
            msg = msg % repr(triggerFlag)
            raise ValueError, msg

        Breakpoint.__init__(self, address, size, condition, action)
        self.__trigger  = triggerFlag
        self.__watch    = sizeFlag
        self.__slot     = None

    def __clear_bp(self, aThread):
        """
        Clear this breakpoint from the debug registers.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__slot is None:
            raise Exception, "Already disabled: %r" % self
        aThread.suspend()
        ctx = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
        DebugRegister.clear_bp(ctx, self.__slot)
        self.__slot = None
        aThread.set_context(ctx)
        aThread.resume()

    def __set_bp(self, aThread):
        """
        Set this breakpoint in the debug registers.
        
        @type  aThread: L{Thread}
        @param aThread: Thread object.
        """
        if self.__slot is not None:
            raise Exception, "Already enabled: %r" % self
        aThread.suspend()
        ctx = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
        self.__slot = DebugRegister.find_slot(ctx)
        if self.__slot is None:
            msg = "No available hardware breakpoint slots for thread ID %d"
            msg = msg % aThread.get_tid()
            raise RuntimeError, msg
        DebugRegister.set_bp(ctx, self.__slot, self.get_address(),
                                               self.__trigger, self.__watch)
        aThread.set_context(ctx)
        aThread.resume()

    def get_slot(self):
        """
        @rtype:  int
        @return: The debug register number used by this breakpoint,
        or None if the breakpoint is not active.
        """
        return self.__slot

    def get_trigger(self):
        """
        @see: L{validTriggers}
        @rtype:  int
        @return: The breakpoint trigger flag.
        """
        return self.__trigger

    def get_watch(self):
        """
        @see: L{validWatchSizes}
        @rtype:  int
        @return: The breakpoint watch flag.
        """
        return self.__watch

    def disable(self, aProcess, aThread):
        self.__clear_bp(aThread)
        if self.is_running():
            aThread.clear_tf()
        super(HardwareBreakpoint, self).disable(aProcess, aThread)

    def enable(self, aProcess, aThread):
        self.__set_bp(aThread)
        super(HardwareBreakpoint, self).enable(aProcess, aThread)

    def one_shot(self, aProcess, aThread):
        self.__set_bp(aThread)
        super(HardwareBreakpoint, self).one_shot(aProcess, aThread)

    def running(self, aProcess, aThread):
        self.__clear_bp(aThread)
        aThread.set_tf()
        super(HardwareBreakpoint, self).running(aProcess, aThread)

#==============================================================================

# For a more complete support of API hooking, check out Universal Hooker at:
# http://oss.coresecurity.com/projects/uhooker.htm
class ApiHook(object):
    """
    Stub that handles pre and post API hook callbacks.
    
    @see: L{Debug.break_at_exported_symbol}
    """

    def __init__(self, eventHandler, procName, paramCount = 0):
        """
        @type  eventHandler: L{EventHandler}
        @param eventHandler: Event handler instance.
        
        @type  procName: str
        @param procName: Procedure name.
            The pre and post callbacks will be deduced from it.
            
            For example, if the procedure is "LoadLibraryEx" the callback
            routines will be "pre_LoadLibraryEx" and "post_LoadLibraryEx".
            
            The signature for the callbacks can be something like this::
                
                def pre_LoadLibraryEx(event, *params):
                    ra   = params[0]        # return address
                    argv = params[1:]       # function parameters
                    
                    # (...)
                
                def post_LoadLibraryEx(event, return_value):
                    
                    # (...)
            
            But if you passed the right number of arguments, you can also
            use a signature like this::
                
                def pre_LoadLibraryEx(event, ra, lpFilename, hFile, dwFlags):
                    szFilename = event.get_process().peek_string(lpFilename)
                    
                    # (...)
        
        @type  paramCount: int
        @param paramCount: (Optional) Number of parameters for the callback.
            Parameters are read from the stack and assumed to be DWORDs.
            The first parameter of the pre callback is always the return address.
        """
        self.procName   = procName
        self.paramCount = paramCount + 1
        self.preCB      = getattr(eventHandler, 'pre_%s' % procName, None)
        self.postCB     = getattr(eventHandler, 'post_%s' % procName, None)

    # FIXME
    #
    # By using break_at() to set a process-wide breakpoint on the function's
    # return address, we might hit a race condition when more than one thread
    # is being debugged.
    #
    # Hardware breakpoints should be used instead. But since a thread can run
    # out of those, we need to fall back to this method when needed.
    def __call__(self, event):
        """
        Handles the breakpoint event on the entry of the API function.
        
        @type  event: L{Event}
        @param event: Breakpoint hit event.
        """

        # Set a one shot code breakpoint at the return address.
        pid     = event.get_pid()
        aThread = event.get_thread()
        params  = aThread.get_stack_dwords(self.paramCount)
        if len(params) != self.paramCount:
            msg = "%s got %d arguments, expected %d"
            msg = msg % (self.procName, len(params), self.paramCount)
            raise RuntimeError, msg
        if params and self.postCB is not None:
            event.debug.stalk_at(pid, params[0], self.__postCallAction)

        # Call the "pre" handler.
        self.__callHandler(self.preCB, event, *params)

    def __postCallAction(self, event):
        """
        Handles the breakpoint event on the return from the API function.
        
        @type  event: L{Event}
        @param event: Breakpoint hit event.
        """

        # Remove the one shot code breakpoint at the return address.
        pid     = event.get_pid()
        address = event.get_exception_address()
        event.debug.erase_code_breakpoint(pid, address)

        # Call the "post" handler.
        aThread = event.get_thread()
        ctx     = aThread.get_context(win32.CONTEXT_INTEGER)
        retval  = ctx['Eax']
        self.__callHandler(self.postCB, event, retval)

    def __callHandler(self, callback, event, *params):
        """
        Calls a "pre" or "post" handler, if set.
        
        @type  callback: function
        @param callback: Callback function to call.
        
        @type  event: L{Event}
        @param event: Breakpoint hit event.
        
        @type  params: tuple
        @param params: Parameters for the callback function.
        """
        if callback is not None:
            callback(event, *params)

    def hook(self, debug, pid, modName):
        """
        Install the API hook on a given process and module.
        
        @warning: Do not call from an API hook callback.
        
        @type  debug: L{Debug}
        @param debug: Debug object.
        
        @type  pid: int
        @param pid: Process ID.
        
        @type  modName: str
        @param modName: Module name.
        """
        debug.hook_exported_symbol(pid, modName, self.procName, self)

    def unhook(self, debug, pid, modName):
        """
        Remove the API hook from the given process and module.
        
        @warning: Do not call from an API hook callback.
        
        @type  debug: L{Debug}
        @param debug: Debug object.
        
        @type  pid: int
        @param pid: Process ID.
        
        @type  modName: str
        @param modName: Module name.
        """
        debug.unhook_exported_symbol(pid, modName, self.procName)

#==============================================================================

class BreakpointContainer (object):
    """
    Encapsulates the capability to contain Breakpoint objects.
    
    @group Simple breakpoint use:
        break_at, stalk_at, watch_variable, watch_buffer,
        dont_break_at, dont_stalk_at, dont_watch_variable, dont_watch_buffer
    
    @group Symbols:
        resolve_exported_symbol,
        break_at_exported_symbol, dont_break_at_exported_symbol,
        break_at_address_list, break_at_symbol_list
    
    @group Advanced breakpoint use:
        define_code_breakpoint,
        define_page_breakpoint,
        define_hardware_breakpoint,
        erase_code_breakpoint,
        erase_page_breakpoint,
        erase_hardware_breakpoint,
        enable_code_breakpoint,
        enable_page_breakpoint,
        enable_hardware_breakpoint,
        enable_one_shot_code_breakpoint,
        enable_one_shot_page_breakpoint,
        enable_one_shot_hardware_breakpoint,
        disable_code_breakpoint,
        disable_page_breakpoint,
        disable_hardware_breakpoint
    
    @group Listing breakpoints:
        get_all_breakpoints,
        get_all_code_breakpoints,
        get_all_page_breakpoints,
        get_all_hardware_breakpoints,
        get_process_code_breakpoints,
        get_process_page_breakpoints,
        get_process_hardware_breakpoints,
        get_thread_hardware_breakpoints
    
    @group Batch operations on breakpoints:
        enable_all_breakpoints,
        enable_one_shot_all_breakpoints,
        disable_all_breakpoints,
        erase_all_breakpoints,
        enable_process_breakpoints,
        enable_one_shot_process_breakpoints,
        disable_process_breakpoints,
        erase_process_breakpoints
    
    @group Breakpoint types:
        BP_TYPE_ANY, BP_TYPE_CODE, BP_TYPE_PAGE, BP_TYPE_HARDWARE
    @group Breakpoint states:
        BP_STATE_DISABLED, BP_STATE_ENABLED, BP_STATE_ONESHOT, BP_STATE_RUNNING
    @group Memory breakpoint trigger flags:
        BP_BREAK_ON_EXECUTION, BP_BREAK_ON_WRITE, BP_BREAK_ON_ACCESS
    @group Memory breakpoint size flags:
        BP_WATCH_BYTE, BP_WATCH_WORD, BP_WATCH_DWORD, BP_WATCH_QWORD
    
    @type BP_TYPE_ANY: int
    @cvar BP_TYPE_ANY: To get all breakpoints
    @type BP_TYPE_CODE: int
    @cvar BP_TYPE_CODE: To get code breakpoints only
    @type BP_TYPE_PAGE: int
    @cvar BP_TYPE_PAGE: To get page breakpoints only
    @type BP_TYPE_HARDWARE: int
    @cvar BP_TYPE_HARDWARE: To get hardware breakpoints only
    
    @type BP_STATE_DISABLED: int
    @cvar BP_STATE_DISABLED: Breakpoint is disabled.
    @type BP_STATE_ENABLED: int
    @cvar BP_STATE_ENABLED: Breakpoint is enabled.
    @type BP_STATE_ONESHOT: int
    @cvar BP_STATE_ONESHOT: Breakpoint is enabled for one shot.
    @type BP_STATE_RUNNING: int
    @cvar BP_STATE_RUNNING: Breakpoint is running (recently hit).
    
    @type BP_BREAK_ON_EXECUTION: int
    @cvar BP_BREAK_ON_EXECUTION: Break on code execution.
    @type BP_BREAK_ON_WRITE: int
    @cvar BP_BREAK_ON_WRITE: Break on memory write.
    @type BP_BREAK_ON_ACCESS: int
    @cvar BP_BREAK_ON_ACCESS: Break on memory read or write.
    """

    # Breakpoint types
    BP_TYPE_ANY             = 0     # to get all breakpoints
    BP_TYPE_CODE            = 1
    BP_TYPE_PAGE            = 2
    BP_TYPE_HARDWARE        = 3

    # Breakpoint states
    BP_STATE_DISABLED       = Breakpoint.DISABLED
    BP_STATE_ENABLED        = Breakpoint.ENABLED
    BP_STATE_ONESHOT        = Breakpoint.ONESHOT
    BP_STATE_RUNNING        = Breakpoint.RUNNING

    # Memory breakpoint trigger flags
    BP_BREAK_ON_EXECUTION   = HardwareBreakpoint.BREAK_ON_EXECUTION
    BP_BREAK_ON_WRITE       = HardwareBreakpoint.BREAK_ON_WRITE
    BP_BREAK_ON_IO_ACCESS   = HardwareBreakpoint.BREAK_ON_IO_ACCESS
    BP_BREAK_ON_ACCESS      = HardwareBreakpoint.BREAK_ON_ACCESS

    # Memory breakpoint size flags
    BP_WATCH_BYTE           = HardwareBreakpoint.WATCH_BYTE
    BP_WATCH_WORD           = HardwareBreakpoint.WATCH_WORD
    BP_WATCH_QWORD          = HardwareBreakpoint.WATCH_QWORD
    BP_WATCH_DWORD          = HardwareBreakpoint.WATCH_DWORD

    def __init__(self):
        self.__codeBP     = dict()  # (pid, address) -> CodeBreakpoint
        self.__pageBP     = dict()  # (pid, address) -> PageBreakpoint
        self.__hardwareBP = dict()  # tid -> [ HardwareBreakpoint ]
        self.__runningBP  = dict()  # tid -> set( Breakpoint )

#------------------------------------------------------------------------------

    def __has_running_bp(self, tid):
        return self.__runningBP.has_key(tid) and self.__runningBP[tid]

    def __pop_running_bp(self, tid):
        return self.__runningBP[tid].pop()

    def __add_running_bp(self, tid, bp):
        if not self.__runningBP.has_key(tid):
            self.__runningBP[tid] = set()
        self.__runningBP[tid].add(bp)

    def __del_running_bp(self, tid, bp):
        self.__runningBP[tid].remove(bp)
        if not self.__runningBP[tid]:
            del self.__runningBP[tid]

    def __del_running_bp_from_all_threads(self, bp):
        for (tid, bpset) in self.__runningBP.iteritems():
            if bp in bpset:
                bpset.remove(bp)

    def __ranges_intersect(self, begin, end, old_begin, old_end):
        return  (old_begin <= begin < old_end) or \
                (old_begin < end <= old_end)   or \
                (begin <= old_begin < end)     or \
                (begin < old_end <= end)

    def __get_code_bp(self, pid, address):
        key = (pid, address)
        if not self.__codeBP.has_key(key):
            msg = "No breakpoint at process %d, address %.08x"
            raise KeyError, msg % (pid, address)
        return self.__codeBP[key]

    def __get_page_bp(self, pid, address):
        key = (pid, address)
        if not self.__pageBP.has_key(key):
            msg = "No breakpoint at process %d, address %.08x"
            raise KeyError, msg % (pid, address)
        return self.__pageBP[key]

    def __get_hardware_bp(self, tid, address):
        if not self.__hardwareBP.has_key(tid):
            msg = "No hardware breakpoints set for thread %d"
            raise KeyError, msg % tid
        for bp in self.__hardwareBP[tid]:
            if bp.is_here(address):
                return bp
        msg = "No hardware breakpoint at thread %d, address %.08x"
        raise KeyError, msg % (dwThreadId, address)

#------------------------------------------------------------------------------

    @processidparam
    def define_code_breakpoint(self, dwProcessId, address,   condition = True,
                                                                action = None):
        """
        Creates a disabled code breakpoint at the given address.
        
        @see:
            L{enable_code_breakpoint},
            L{enable_one_shot_code_breakpoint},
            L{disable_code_breakpoint},
            L{erase_code_breakpoint}
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of the code instruction to break at.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
            
            The callback signature is::
                
                def condition_callback(event):
                    return True     # returns True or False
            
            Where B{event} is an L{Event} object,
            and the return value is a boolean
            (True to dispatch the event, False otherwise).
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            
            The callback signature is::
                
                def action_callback(event):
                    pass        # no return value
            
            Where B{event} is an L{Event} object.
        
        @rtype:  L{CodeBreakpoint}
        @return: The code breakpoint object.
        """
        process = self.system.get_process(dwProcessId)
        bp = CodeBreakpoint(address, condition, action)

        key = (dwProcessId, bp.get_address())
        if self.__codeBP.has_key(key):
            msg = "Already exists (PID %d) : %r"
            raise KeyError, msg % (dwProcessId, self.__codeBP[key])
        self.__codeBP[key] = bp
        return bp

    @processidparam
    def define_page_breakpoint(self, dwProcessId, address,       pages = 1,
                                                             condition = True,
                                                                action = None):
        """
        Creates a disabled page breakpoint at the given address.
        
        @see:
            L{enable_page_breakpoint},
            L{enable_one_shot_page_breakpoint},
            L{disable_page_breakpoint},
            L{erase_page_breakpoint}
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of the first page to watch.
        
        @type  pages: int
        @param pages: Number of pages to watch.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
            
            The callback signature is::
                
                def condition_callback(event):
                    return True     # returns True or False
            
            Where B{event} is an L{Event} object,
            and the return value is a boolean
            (True to dispatch the event, False otherwise).
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            
            The callback signature is::
                
                def action_callback(event):
                    pass        # no return value
            
            Where B{event} is an L{Event} object.
        
        @rtype:  L{PageBreakpoint}
        @return: The page breakpoint object.
        """
        process = self.system.get_process(dwProcessId)
        bp      = PageBreakpoint(address, pages, condition, action)
        begin   = bp.get_address()
        end     = begin + bp.get_size()

        for address in xrange(begin, end, bp.pageSize):
            key = (dwProcessId, address)
            if self.__pageBP.has_key(key):
                msg = "Already exists (PID %d) : %r"
                msg = msg % (dwProcessId, self.__pageBP[key])
                raise KeyError, msg

        for address in xrange(begin, end, bp.pageSize):
            key = (dwProcessId, address)
            self.__pageBP[key] = bp
        return bp

    @threadidparam
    def define_hardware_breakpoint(self, dwThreadId, address,
                                              triggerFlag = BP_BREAK_ON_ACCESS,
                                                 sizeFlag = BP_WATCH_DWORD,
                                                condition = True,
                                                   action = None):
        """
        Creates a disabled hardware breakpoint at the given address.
        
        @see:
            L{enable_hardware_breakpoint},
            L{enable_one_shot_hardware_breakpoint},
            L{disable_hardware_breakpoint},
            L{erase_hardware_breakpoint}
        
        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.
        
        @type  address: int
        @param address: Memory address to watch.
        
        @type  triggerFlag: int
        @param triggerFlag: Trigger of breakpoint. Must be one of the following:
            
             - L{BP_BREAK_ON_EXECUTION}
               
               Break on code execution.
            
             - L{BP_BREAK_ON_WRITE}
               
               Break on memory read or write.
            
             - L{BP_BREAK_ON_ACCESS}
               
               Break on memory write.
        
        @type  sizeFlag: int
        @param sizeFlag: Size of breakpoint. Must be one of the following:
            
             - L{BP_WATCH_BYTE}
               
               One (1) byte in size.
            
             - L{BP_WATCH_WORD}
               
               Two (2) bytes in size.
            
             - L{BP_WATCH_DWORD}
               
               Four (4) bytes in size.
            
             - L{BP_WATCH_QWORD}
               
               Eight (8) bytes in size.
        
        @type    condition: function
        @keyword condition: (Optional) Condition callback function.
            
            The callback signature is::
                
                def condition_callback(event):
                    return True     # returns True or False
            
            Where B{event} is an L{Event} object,
            and the return value is a boolean
            (True to dispatch the event, False otherwise).
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            If specified, the event is handled by this callback instead of
            being dispatched normally.
            
            The callback signature is::
                
                def action_callback(event):
                    pass        # no return value
            
            Where B{event} is an L{Event} object.
        
        @rtype:  L{PageBreakpoint}
        @return: The page breakpoint object.
        """
        thread  = self.system.get_thread(dwThreadId)
        bp      = HardwareBreakpoint(address, triggerFlag, sizeFlag, condition,
                                                                        action)
        begin   = bp.get_address()
        end     = begin + bp.get_size()

        if self.__hardwareBP.has_key(dwThreadId):
            bpSet = self.__hardwareBP[dwThreadId]
            for oldbp in bpSet:
                old_begin = oldbp.get_address()
                old_end   = old_begin + oldbp.get_size()
                if self.__ranges_intersect(begin, end, old_begin, old_end):
                    msg = "Already exists (TID %d) : %r" % (dwThreadId, oldbp)
                    raise KeyError, msg
        else:
            bpSet = set()
            self.__hardwareBP[dwThreadId] = bpSet
        bpSet.add(bp)
        return bp

#------------------------------------------------------------------------------

    @processidparam
    def erase_code_breakpoint(self, dwProcessId, address):
        """
        Erases the code breakpoint at the given address.
        
        @see:
            L{define_code_breakpoint},
            L{enable_code_breakpoint},
            L{enable_one_shot_code_breakpoint},
            L{disable_code_breakpoint}
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        bp = self.__get_code_bp(dwProcessId, address)
        if bp.is_active():
            self.disable_code_breakpoint(dwProcessId, address)
        del self.__codeBP[ (dwProcessId, address) ]

    @processidparam
    def erase_page_breakpoint(self, dwProcessId, address):
        """
        Erases the page breakpoint at the given address.
        
        @see:
            L{define_page_breakpoint},
            L{enable_page_breakpoint},
            L{enable_one_shot_page_breakpoint},
            L{disable_page_breakpoint}
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        bp    = self.__get_page_bp(dwProcessId, address)
        begin = bp.get_address()
        end   = begin + bp.get_size()
        if bp.is_active():
            self.disable_page_breakpoint(dwProcessId, address)
        for address in xrange(begin, end, bp.pageSize):
            del self.__pageBP[ (dwProcessId, address) ]

    @threadidparam
    def erase_hardware_breakpoint(self, dwThreadId, address):
        """
        Erases the hardware breakpoint at the given address.
        
        @see:
            L{define_hardware_breakpoint},
            L{enable_hardware_breakpoint},
            L{enable_one_shot_hardware_breakpoint},
            L{disable_hardware_breakpoint}
        
        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        bp = self.__get_hardware_bp(dwThreadId, address)
        if bp.is_active():
            self.disable_hardware_breakpoint(dwProcessId, address)
        bpSet = self.__hardwareBP[dwThreadId]
        bpSet.remove(bp)
        if not bpSet:
            del self.__hardwareBP[dwThreadId]

#------------------------------------------------------------------------------

    @processidparam
    def enable_code_breakpoint(self, dwProcessId, address):
        """
        Enables the code breakpoint at the given address.
        
        @see:
            L{define_code_breakpoint},
            L{enable_one_shot_code_breakpoint},
            L{disable_code_breakpoint}
            L{erase_code_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_code_bp(dwProcessId, address)
        bp.enable(p, None)

    @processidparam
    def enable_page_breakpoint(self, dwProcessId, address):
        """
        Enables the page breakpoint at the given address.
        
        @see:
            L{define_page_breakpoint},
            L{enable_one_shot_page_breakpoint},
            L{disable_page_breakpoint}
            L{erase_page_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_page_bp(dwProcessId, address)
        bp.enable(p, None)

    @threadidparam
    def enable_hardware_breakpoint(self, dwThreadId, address):
        """
        Enables the hardware breakpoint at the given address.
        
        @see:
            L{define_hardware_breakpoint},
            L{enable_one_shot_hardware_breakpoint},
            L{disable_hardware_breakpoint}
            L{erase_hardware_breakpoint},
        
        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        t  = self.system.get_thread(dwThreadId)
        p  = t.get_process()
        bp = self.__get_hardware_bp(dwThreadId, address)
        bp.enable(p, t)

    @processidparam
    def enable_one_shot_code_breakpoint(self, dwProcessId, address):
        """
        Enables the code breakpoint at the given address for only one shot.
        
        @see:
            L{define_code_breakpoint},
            L{enable_code_breakpoint},
            L{disable_code_breakpoint}
            L{erase_code_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_code_bp(dwProcessId, address)
        bp.one_shot(p, None)

    @processidparam
    def enable_one_shot_page_breakpoint(self, dwProcessId, address):
        """
        Enables the page breakpoint at the given address for only one shot.
        
        @see:
            L{define_page_breakpoint},
            L{enable_page_breakpoint},
            L{disable_page_breakpoint}
            L{erase_page_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_page_bp(dwProcessId, address)
        bp.one_shot(p, None)

    @threadidparam
    def enable_one_shot_hardware_breakpoint(self, dwThreadId, address):
        """
        Enables the hardware breakpoint at the given address for only one shot.
        
        @see:
            L{define_hardware_breakpoint},
            L{enable_hardware_breakpoint},
            L{disable_hardware_breakpoint}
            L{erase_hardware_breakpoint},
        
        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        t  = self.system.get_thread(dwThreadId)
        bp = self.__get_hardware_bp(dwThreadId, address)
        bp.one_shot(None, t)

    @processidparam
    def disable_code_breakpoint(self, dwProcessId, address):
        """
        Disables the code breakpoint at the given address.
        
        @see:
            L{define_code_breakpoint},
            L{enable_code_breakpoint}
            L{enable_one_shot_code_breakpoint},
            L{erase_code_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_code_bp(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.disable(p, None)

    @processidparam
    def disable_page_breakpoint(self, dwProcessId, address):
        """
        Disables the page breakpoint at the given address.
        
        @see:
            L{define_page_breakpoint},
            L{enable_page_breakpoint}
            L{enable_one_shot_page_breakpoint},
            L{erase_page_breakpoint},
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        p  = self.system.get_process(dwProcessId)
        bp = self.__get_page_bp(dwProcessId, address)
        if bp.is_running():
            self.__del_running_bp_from_all_threads(bp)
        bp.disable(p, None)

    @threadidparam
    def disable_hardware_breakpoint(self, dwThreadId, address):
        """
        Disables the hardware breakpoint at the given address.
        
        @see:
            L{define_hardware_breakpoint},
            L{enable_hardware_breakpoint}
            L{enable_one_shot_hardware_breakpoint},
            L{erase_hardware_breakpoint},
        
        @type  dwThreadId: int
        @param dwThreadId: Thread global ID.
        
        @type  address: int
        @param address: Memory address of breakpoint.
        """
        t  = self.system.get_thread(dwThreadId)
        p  = t.get_process()
        bp = self.__get_hardware_bp(dwThreadId, address)
        if bp.is_running():
            self.__del_running_bp(dwThreadId, bp)
        bp.disable(p, t)

#------------------------------------------------------------------------------

    def get_all_breakpoints(self):
        """
        Returns all breakpoint objects as a list of tuples.
        
        Each tuple contains:
         - Process global ID to which the breakpoint applies.
         - Thread global ID to which the breakpoint applies, or None.
         - The L{Breakpoint} object itself.
        
        @note: If you're only interested in a specific breakpoint type, or in
            breakpoints for a specific process or thread, it's probably faster
            to call one of the following methods:
             - L{get_all_code_breakpoints}
             - L{get_all_page_breakpoints}
             - L{get_all_hardware_breakpoints}
             - L{get_process_code_breakpoints}
             - L{get_process_page_breakpoints}
             - L{get_process_hardware_breakpoints}
             - L{get_thread_hardware_breakpoints}
        
        @rtype:  list of tuple( pid, tid, bp )
        @return: List of all breakpoints.
        """
        
        # Get the code breakpoints.
        for (pid, bp) in self.get_all_code_breakpoints():
            bplist.append( (pid, None, bp) )
        
        # Get the page breakpoints.
        for (pid, bp) in self.get_all_page_breakpoints():
            bplist.append( (pid, None, bp) )
        
        # Get the hardware breakpoints.
        for (tid, bp) in self.get_all_hardware_breakpoints():
            pid = self.system.get_thread(tid).get_pid()
            bplist.append( (pid, tid, bp) )
        
        # Return the list of breakpoints.
        return bplist

    def get_all_code_breakpoints(self):
        """
        @rtype:  list of tuple( int, L{CodeBreakpoint} )
        @return: All code breakpoints as a list of tuples (pid, bp).
        """
        return [ (pid, bp) for ((pid, address), bp) in self.__codeBP.iteritems() ]

    @processidparam
    def get_all_page_breakpoints(self):
        """
        @rtype:  list of tuple( int, L{PageBreakpoint} )
        @return: All page breakpoints as a list of tuples (pid, bp).
        """
##        return list( set( [ (pid, bp) for ((pid, address), bp) in self.__pageBP.itervalues() ] ) )
        result = set()
        for ((pid, address), bp) in self.__pageBP.itervalues():
            result.add( (pid, bp) )
        return list(result)

    @threadidparam
    def get_all_hardware_breakpoints(self):
        """
        @rtype:  list of tuple( int, L{HardwareBreakpoint} )
        @return: All hardware breakpoints as a list of tuples (tid, bp).
        """
        result = list()
        for (tid, bplist) in self.__hardwareBP.iteritems():
            for bp in bplist:
                result.append( (tid, bp) )
        return result

    @processidparam
    def get_process_code_breakpoints(self, dwProcessId):
        """
        @rtype:  list of L{CodeBreakpoint}
        @return: All code breakpoints for the given process.
        """
        result = list()
        for ((pid, address), bp) in self.__codeBP.iteritems():
            if pid == dwProcessId:
                result.append(bp)
        return result

    @processidparam
    def get_process_page_breakpoints(self, dwProcessId):
        """
        @rtype:  list of L{PageBreakpoint}
        @return: All page breakpoints for the given process.
        """
        result = list()
        for ((pid, address), bp) in self.__pageBP.itervalues():
            if pid == dwProcessId:
                result.append(bp)
        return result

    @threadidparam
    def get_thread_hardware_breakpoints(self, dwThreadId):
        """
        @see: get_process_hardware_breakpoints
        @rtype:  list of L{HardwareBreakpoint}
        @return: All hardware breakpoints for the given thread.
        """
        result = list()
        for (tid, bplist) in self.__hardwareBP.iteritems():
            if tid == dwThreadId:
                for bp in bplist:
                    result.append(bp)
        return result

    @processidparam
    def get_process_hardware_breakpoints(self, dwProcessId):
        """
        @see: get_thread_hardware_breakpoints
        @rtype:  list of tuple( int, L{HardwareBreakpoint} )
        @return: All hardware breakpoints for each thread in the given process
            as a list of tuples (tid, bp).
        """
        result = list()
        aProcess = self.system.get_process(dwProcessId)
        for tid in aProcess.iter_thread_ids():
            if self.__hardwareBP.has_key(tid):
                bplist = self.__hardwareBP[tid]
                for bp in bplist:
                    result.append( (tid, bp) )
        return result

#------------------------------------------------------------------------------

    def enable_all_breakpoints(self):
        """
        Enables all disabled breakpoints in all processes.
        
        @see:
            enable_code_breakpoint,
            enable_page_breakpoint,
            enable_hardware_breakpoint
        """

        # disable code breakpoints
        for (pid, bp) in self.get_all_code_breakpoints():
            if bp.is_disabled():
                self.enable_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints
        for (pid, bp) in self.get_all_page_breakpoints():
            if bp.is_disabled():
                self.enable_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints
        for (tid, bp) in self.get_all_hardware_breakpoints():
            if bp.is_disabled():
                self.enable_hardware_breakpoint(tid, bp.get_address())

    def enable_one_shot_all_breakpoints(self):
        """
        Enables for one shot all disabled breakpoints in all processes.
        
        @see:
            enable_one_shot_code_breakpoint,
            enable_one_shot_page_breakpoint,
            enable_one_shot_hardware_breakpoint
        """

        # disable code breakpoints for one shot
        for (pid, bp) in self.get_all_code_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints for one shot
        for (pid, bp) in self.get_all_page_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints for one shot
        for (tid, bp) in self.get_all_hardware_breakpoints():
            if bp.is_disabled():
                self.enable_one_shot_hardware_breakpoint(tid, bp.get_address())

    def disable_all_breakpoints(self):
        """
        Disables all breakpoints in all processes.
        
        @see:
            disable_code_breakpoint,
            disable_page_breakpoint,
            disable_hardware_breakpoint
        """

        # disable code breakpoints
        for (pid, bp) in self.get_all_code_breakpoints():
            self.disable_code_breakpoint(pid, bp.get_address())

        # disable page breakpoints
        for (pid, bp) in self.get_all_page_breakpoints():
            self.disable_page_breakpoint(pid, bp.get_address())

        # disable hardware breakpoints
        for (tid, bp) in self.get_all_hardware_breakpoints():
            self.disable_hardware_breakpoint(tid, bp.get_address())

    def erase_all_breakpoints(self):
        """
        Erases all breakpoints in all processes.
        
        @see:
            erase_code_breakpoint,
            erase_page_breakpoint,
            erase_hardware_breakpoint
        """

        # XXX HACK
        # With this trick we get to do it faster,
        # but I'm leaving the "nice" version commented out below,
        # just in case something breaks because of this.
        self.disable_all_breakpoints()
        self.__codeBP       = dict()
        self.__pageBP       = dict()
        self.__hardwareBP   = dict()
        self.__runningBP    = dict()

##        # erase code breakpoints
##        for (pid, bp) in self.get_all_code_breakpoints():
##            self.erase_code_breakpoint(pid, bp.get_address())
##
##        # erase page breakpoints
##        for (pid, bp) in self.get_all_page_breakpoints():
##            self.erase_page_breakpoint(pid, bp.get_address())
##
##        # erase hardware breakpoints
##        for (tid, bp) in self.get_all_hardware_breakpoints():
##            self.erase_hardware_breakpoint(tid, bp.get_address())

#------------------------------------------------------------------------------

    def enable_process_breakpoints(self, dwProcessId):
        """
        Enables all disabled breakpoints for the given process.
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        """

        # enable code breakpoints
        for bp in self.get_code_breakpoints_for_process(dwProcessId):
            if bp.is_disabled():
                self.enable_code_breakpoint(dwProcessId, bp.get_address())

        # enable page breakpoints
        for bp in self.get_page_breakpoints_for_process(dwProcessId):
            if bp.is_disabled():
                self.enable_page_breakpoint(dwProcessId, bp.get_address())

        # enable hardware breakpoints
        aProcess = self.system.get_process(dwProcessId)
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_hardware_breakpoints_for_thread(dwThreadId):
                if bp.is_disabled():
                    self.enable_hardware_breakpoint(dwThreadId, bp.get_address())

    def enable_one_shot_process_breakpoints(self, dwProcessId):
        """
        Enables for one shot all disabled breakpoints for the given process.
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        """

        # enable code breakpoints for one shot
        for bp in self.get_code_breakpoints_for_process(dwProcessId):
            if bp.is_disabled():
                self.enable_one_shot_code_breakpoint(dwProcessId, bp.get_address())

        # enable page breakpoints for one shot
        for bp in self.get_page_breakpoints_for_process(dwProcessId):
            if bp.is_disabled():
                self.enable_one_shot_page_breakpoint(dwProcessId, bp.get_address())

        # enable hardware breakpoints for one shot
        aProcess = self.system.get_process(dwProcessId)
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_hardware_breakpoints_for_thread(dwThreadId):
                if bp.is_disabled():
                    self.enable_one_shot_hardware_breakpoint(dwThreadId, bp.get_address())

    def disable_process_breakpoints(self, dwProcessId):
        """
        Disables all breakpoints for the given process.
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        """

        # disable code breakpoints
        for bp in self.get_code_breakpoints_for_process(dwProcessId):
            self.disable_code_breakpoint(dwProcessId, bp.get_address())

        # disable page breakpoints
        for bp in self.get_page_breakpoints_for_process(dwProcessId):
            self.disable_page_breakpoint(dwProcessId, bp.get_address())

        # disable hardware breakpoints
        aProcess = self.system.get_process(dwProcessId)
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_hardware_breakpoints_for_thread(dwThreadId):
                self.disable_hardware_breakpoint(dwThreadId, bp.get_address())

    def erase_process_breakpoints(self, dwProcessId):
        """
        Erases all breakpoints for the given process.
        
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.
        """

        # disable breakpoints first
        # if an error occurs, no breakpoint is erased
        self.disable_breakpoints_for_process(dwProcessId)

        # erase code breakpoints
        for bp in self.get_code_breakpoints_for_process(dwProcessId):
            self.erase_code_breakpoint(dwProcessId, bp.get_address())

        # erase page breakpoints
        for bp in self.get_page_breakpoints_for_process(dwProcessId):
            self.erase_page_breakpoint(dwProcessId, bp.get_address())

        # erase hardware breakpoints
        aProcess = self.system.get_process(dwProcessId)
        for aThread in aProcess.iter_threads():
            dwThreadId = aThread.get_tid()
            for bp in self.get_hardware_breakpoints_for_thread(dwThreadId):
                self.erase_hardware_breakpoint(dwThreadId, bp.get_address())

#------------------------------------------------------------------------------

    def notify_guard_page(self, event):
        """
        Notify breakpoints of a guard page exception event.
        
        @type  event: L{ExceptionEvent}
        @param event: Guard page exception event.
        """
        address         = event.get_exception_information(1)
        pid             = event.get_pid()
        bCallHandler    = True

        # Align address to page boundary
        address = address & 0xFFFFF000

        # Do we have a page breakpoint there?
        key = (pid, address)
        if self.__pageBP.has_key(key):
            bp = self.__pageBP[key]

            # Breakpoint is ours.
            event.continueStatus = win32.DBG_CONTINUE

            # Ignore disabled and running breakpoints.
            # (See notify_breakpoint)
            if not bp.is_active():
                bCallHandler = False
            else:

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

        return bCallHandler

    def notify_breakpoint(self, event):
        """
        Notify breakpoints of a breakpoint exception event.
        
        @type  event: L{ExceptionEvent}
        @param event: Breakpoint exception event.
        """
        address         = event.get_exception_address()
        pid             = event.get_pid()
        bCallHandler    = True

        # Do we have a code breakpoint there?
        key = (pid, address)
        if self.__codeBP.has_key(key):
            bp = self.__codeBP[key]

            # Breakpoint is ours.
            event.continueStatus = win32.DBG_CONTINUE

            # Ignore disabled and running breakpoints.
            # This condition is caused by a debug event that was
            # queued right before the breakpoint changed its state.
            # It would be better handled if there was some kind of
            # look-ahead for debug events...
            if not bp.is_active():
                bCallHandler = False
            else:

                # Hit the breakpoint.
                bp.hit(event)

                # Change the EIP to the exception address.
                #
                # This accounts for the change in EIP caused by
                # executing the breakpoint instruction, no matter
                # the size of it.
                #
                # I think this should be in the CodeBreakpoint
                # class... but I don't want to have to pass the
                # event object to the state changers.
                #
                aThread = event.get_thread()
                aThread.set_pc(address)

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
        elif address == event.get_process().get_system_breakpoint():
            event.continueStatus = win32.DBG_CONTINUE

        return bCallHandler

    def notify_single_step(self, event):
        """
        Notify breakpoints of a single step exception event.
        
        @type  event: L{ExceptionEvent}
        @param event: Single step exception event.
        """
        pid             = event.get_pid()
        tid             = event.get_tid()
        bCallHandler    = True

        # Handle breakpoints in RUNNING state.
        while self.__has_running_bp(tid):
            event.continueStatus = win32.DBG_CONTINUE
            bCallHandler = False
            bp = self.__pop_running_bp(tid)
            bp.hit(event)

        # Handle hardware breakpoints.
        if self.__hardwareBP.has_key(tid):
            aThread = event.get_thread()
            ctx     = aThread.get_context(win32.CONTEXT_DEBUG_REGISTERS)
            Dr6     = ctx['Dr6']
            ctx['Dr6'] = Dr6 & 15
            aThread.set_context(ctx)
            bFoundBreakpoint = False
            bCondition       = False
            for bp in self.__hardwareBP[tid]:
                slot = bp.get_slot()
                if (slot is not None) and (Dr6 & DebugRegister.hitMask[slot]):
                    bFoundBreakpoint = True
                    bp.hit(event)
                    if bp.is_running():
                        self.__add_running_bp(tid, bp)
                    bCondition = bp.eval_condition(event) or bCondition 
                    if bCondition and bp.is_automatic():
                        bCondition = bp.run_action(event)
            if bFoundBreakpoint:
                bCallHandler = bCondition
                event.continueStatus = win32.DBG_CONTINUE

        return bCallHandler

    def notify_exit_thread(self, event):
        """
        Notify the termination of a thread.
        
        @type  event: L{ExitThreadEvent}
        @param event: Exit thread event.
        """
        tid = event.get_tid()
        if self.__runningBP.has_key(tid):
            del self.__runningBP[tid]
        if self.__hardwareBP.has_key(tid):
            del self.__hardwareBP[tid]
        return True

    def notify_exit_process(self, event):
        """
        Notify the termination of a process.
        
        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.
        """
        pid = event.get_pid()
        for (bp_pid, bp_address) in self.__codeBP.keys():
            if bp_pid == pid:
                del self.__codeBP[(bp_pid, bp_address)]
        for (bp_pid, bp_address) in self.__pageBP.keys():
            if bp_pid == pid:
                del self.__pageBP[(bp_pid, bp_address)]
        return True

#------------------------------------------------------------------------------

    @processidparam
    def resolve_exported_symbol(self, pid, modName, procName):
        """
        Resolves the exported DLL function for the given process.
        
        @see: hook_exported_symbol, unhook_exported_symbol
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  modName: str
        @param modName: Name of the module that exports the symbol.
        
        @type  procName: str
        @param procName: Name of the exported symbol to resolve.
        
        @rtype:  int, None
        @return: On success, the address of the exported symbol.
            On failure, returns None.
        """
        aProcess = self.system.get_process(pid)
        aModule = aProcess.get_module_from_name(modName)
        if not aModule:
            aProcess.scan_modules()
            aModule = aProcess.get_module_from_name(modName)
        if aModule:
            address = aModule.resolve_exported_symbol(procName)
            return address
        return None

    @processidparam
    def break_at_exported_symbol(self, pid, modName, procName, action = None):
        """
        Sets a code breakpoint at the given exported DLL function.
        
        @see: L{break_at}, L{dont_break_at_exported_symbol}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  modName: str
        @param modName: Name of the module that exports the symbol.
        
        @type  procName: str
        @param procName: Name of the exported symbol to hook.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        
        @rtype:  int
        @return: The address of the exported symbol.
        
        @raise RuntimeError: When the exported symbol can't be found.
        """
        address = self.resolve_exported_symbol(pid, modName, procName)
        if address is None:
            raise RuntimeError, "Exported symbol not found: %s" % procName
        self.break_at(pid, address, action)
        return address

    @processidparam
    def dont_break_at_exported_symbol(self, pid, modName, procName):
        """
        Clears a code breakpoint at the given exported DLL function.
        
        @see: L{break_at}, L{break_at_exported_symbol}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  modName: str
        @param modName: Name of the module that exports the symbol.
        
        @type  procName: str
        @param procName: Name of the exported symbol to hook.
        
        @raise RuntimeError: When the exported symbol can't be found.
        """
        address = self.resolve_exported_symbol(pid, modName, procName)
        if address is None:
            raise RuntimeError, "Exported symbol not found: %s" % procName
        self.dont_break_at(pid, address)

    @processidparam
    def stalk_at(self, pid, address, action = None):
        """
        Sets a one shot code breakpoint at the given process and address.
        
        @see: L{break_at}, L{dont_stalk_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address: int
        @param address: Memory address of code instruction to break at.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        """
        self.define_code_breakpoint(pid, address, True, action)
        self.enable_one_shot_code_breakpoint(pid, address)

    @processidparam
    def break_at(self, pid, address, action = None):
        """
        Sets a code breakpoint at the given process and address.
        
        @see: L{stalk_at}, L{dont_break_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address: int
        @param address: Memory address of code instruction to break at.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        """
        self.define_code_breakpoint(pid, address, True, action)
        self.enable_code_breakpoint(pid, address)

    @processidparam
    def dont_break_at(self, pid, address):
        """
        Clears a code breakpoint set by L{break_at} or L{stalk_at}.
        
        @see: L{dont_break_at_exported_symbol}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address: int
        @param address: Memory address of code instruction to break at.
        """
        self.erase_code_breakpoint(pid, address)

    dont_stalk_at = dont_break_at

    @processidparam
    def break_at_address_list(self, pid, address_list, action = None):
        """
        Sets code breakpoints at the given list of addresses.
        
        @see: L{break_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address_list: list( int )
        @param address_list:
            List of memory addresses of code instructions to break at.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        """
        for address in address_list:
            self.break_at(pid, address, action)

    @processidparam
    def stalk_at_address_list(self, pid, address_list, action = None):
        """
        Sets one-shot code breakpoints at the given list of addresses.
        
        @see: L{stalk_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address_list: list( int )
        @param address_list:
            List of memory addresses of code instructions to break at.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        """
        for address in address_list:
            self.stalk_at(pid, address, action)

    def __split_symbol(self, symbol):
        """
        Splits the module and procedure from an exported symbol name.
        
        @type  symbol: str
        @param symbol: Symbol to split
        
        @rtype:  tuple( str, str )
        @return: Tuple containing the module and procedure names.
        """
        if '!' in symbol:
            pos       = symbol.find('!')
            module    = symbol[         : pos ]
            procedure = symbol[ pos + 1 :     ]
        else:
            module    = '*'
            procedure = symbol
        return ( module.strip(), procedure.strip() )

    def __break_or_stalk_at_symbol_list(self, pid, symbol_list, action = None,
                                                  only_for_this_module = None,
                                                                bBreak = True):
        """
        Internally used by break_at_symbol_list() and stalk_at_symbol_list().
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  symbol_list: list( str )
        @param symbol_list: List of target exported symbols.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
        
        @type    only_for_this_module: L{Module}
        @keyword only_for_this_module: (Optional)
            Only apply for symbols that can be resolved on the given module.
            Skip all other symbols.
        
        @type    bBreak: bool
        @keyword bBreak: True to L{break_at}, False to L{stalk_at}.
        
        @rtype:  set( int )
        @return: All resolved symbols where a code breakpoint was set.
        """
        aProcess = self.system.get_process(pid)
        resolved = set()
        if bBreak:
            method = self.break_at
        else:
            method = self.stalk_at

        # Filter symbols by module.
        if only_for_this_module:
            aModule = aProcess.get_module_from_name(only_for_this_module)
            for symbol in symbol_list:
                (module, procedure) = self.__split_symbol(symbol)

                # Discard symbols belonging to other modules.
                if module != '*' and module != only_for_this_module:
                    continue

                # Resolve the symbol.
                address = aModule.resolve_exported_symbol(procedure)
                
                # Discard missing or repeated symbols.
                if address is None or address in resolved:
                    continue
                
                # Remember resolved symbols.
                resolved.add(address)
                
                # Set the breakpoint.
                method(pid, address, action)

        # Resolve symbols in all modules.
        else:
            for symbol in symbol_list:
                (module, procedure) = self.__split_symbol(symbol)

                # Resolve the symbol in all known modules.
                if module == '*':
                    procedure = symbol
                    for aModule in aProcess.iter_modules():
                        address = aModule.resolve_exported_symbol(procedure)
                        if address is None or address in resolved:
                            continue
                        resolved.add(address)
                        method(pid, address, action)

                # Resolve the symbol in the module it belongs to.
                else:
                    aModule = aProcess.get_module_from_name(module)
                    if aModule is None:
                        aProcess.scan_modules()
                        aModule = aProcess.get_module_from_name(module)
                    if aModule is not None:
                        address = aModule.resolve_exported_symbol(procedure)
                        if address is None or address in resolved:
                            continue
                        resolved.add(address)
                        method(pid, address, action)

        # Return the resolved symbols.
        return resolved

    @processidparam
    def break_at_symbol_list(self, pid, symbol_list,            action = None,
                                                  only_for_this_module = None):
        """
        Sets code breakpoints at the given exported symbols.
        
        @see: L{break_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  symbol_list: list( str )
        @param symbol_list: List of target exported symbols.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        
        @type    only_for_this_module: L{Module}
        @keyword only_for_this_module: (Optional)
            Only apply for symbols that can be resolved on the given module.
            Skip all other symbols.
        
        @rtype:  set( int )
        @return: All resolved symbols where a code breakpoint was set.
        """
        return self.__break_or_stalk_at_symbol_list(pid, symbol_list, action,
                                          only_for_this_module, bBreak = True)

    @processidparam
    def stalk_at_symbol_list(self, pid, symbol_list,            action = None,
                                                  only_for_this_module = None):
        """
        Sets one-shot code breakpoints at the given exported symbols.
        
        @see: L{break_at}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  symbol_list: list( str )
        @param symbol_list: List of target exported symbols.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_code_breakpoint} for more details.
        
        @type    only_for_this_module: L{Module}
        @keyword only_for_this_module: (Optional)
            Only apply for symbols that can be resolved on the given module.
            Skip all other symbols.
        
        @rtype:  set( int )
        @return: All resolved symbols where a code breakpoint was set.
        """
        return self.__break_or_stalk_at_symbol_list(pid, symbol_list, action,
                                          only_for_this_module, bBreak = False)

    @threadidparam
    def watch_variable(self, tid, address, size, action = None):
        """
        Sets a hardware breakpoint at the given thread, address and size.
        
        @see: L{dont_watch_variable}
        
        @type  tid: int
        @param tid: Thread global ID.
        
        @type  address: int
        @param address: Memory address of variable to watch.
        
        @type  size: int
        @param size: Size of variable to watch. The only supported sizes are:
            byte (1), word (2), dword (4) and qword (8).
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_hardware_breakpoint} for more details.
        """
        if size == 1:
            sizeFlag = self.BP_WATCH_BYTE
        elif size == 2:
            sizeFlag = self.BP_WATCH_WORD
        elif size == 4:
            sizeFlag = self.BP_WATCH_DWORD
        elif size == 8:
            sizeFlag = self.BP_WATCH_QWORD
        else:
            raise ValueError, "Bad size for variable watch: %r" % size
        self.define_hardware_breakpoint(tid, address,
                   self.BP_BREAK_ON_ACCESS, sizeFlag, True, action)
        self.enable_hardware_breakpoint(tid, address)

    @threadidparam
    def dont_watch_variable(self, tid, address):
        """
        Clears a hardware breakpoint set by L{watch_variable}.
        
        @see: L{watch_variable}
        
        @type  tid: int
        @param tid: Thread global ID.
        
        @type  address: int
        @param address: Memory address of variable to watch.
        """
        self.erase_hardware_breakpoint(tid, address)

    # TODO
    # Check for overlapping page breakpoints.
    @processidparam
    def watch_buffer(self, pid, address, size, action = None):
        """
        Sets a page breakpoint and notifis when the given buffer is accessed.
        
        @see: L{dont_watch_variable}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address: int
        @param address: Memory address of buffer to watch.
        
        @type  size: int
        @param size: Size in bytes of buffer to watch.
        
        @type    action: function
        @keyword action: (Optional) Action callback function.
            
            See L{define_page_breakpoint} for more details.
        """
        if size < 1:
            raise ValueError, "Bad size for buffer watch: %r" % size
        base        = PageBreakpoint.align_address_start(address)
        pages       = PageBreakpoint.get_buffer_size_in_pages(address, size)
        condition   = self.WatchBufferCondition(address, size)
        self.define_page_breakpoint(pid, base, pages, condition, action)
        self.enable_page_breakpoint(pid, base)

    @processidparam
    def dont_watch_buffer(self, pid, address):
        """
        Clears a page breakpoint set by L{watch_buffer}.
        
        @see: L{watch_buffer}
        
        @type  pid: int
        @param pid: Process global ID.
        
        @type  address: int
        @param address: Memory address of buffer to watch.
        """
        base = PageBreakpoint.align_address_start(address)
        self.erase_page_breakpoint(pid, base)

    class WatchBufferCondition(object):
        """
        Simple check for buffer size in page breakpoints.
        
        @see: L{Debug.watch_buffer}
        """
        
        def __init__(self, ptr, size):
            """
            @type ptr: int
            @param ptr: Address of buffer.
            
            @type  size: int
            @param size: Size of buffer in bytes.
            """
            self.min = ptr
            self.max = ptr + size
        
        def __call__(self, event):
            """
            Breakpoint condition callback.
            
            @type  event: L{ExceptionEvent}
            @param event: Guard page exception event.
            
            @rtype:  bool
            @return: True if the address being accessed belongs to the buffer.
            """
            address = event.get_exception_information(1)
            return self.min <= address < self.max
