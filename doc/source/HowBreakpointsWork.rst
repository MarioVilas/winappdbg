.. _how-breakpoints-work:

A closer look at how breakpoints work
*************************************

This wiki page aims at giving a more detailed explanation on how breakpoints really work, behind the simplified *break_at*, *stalk_at*, *watch_variable* and *watch_buffer* interface provided by the *Debug* objects. With this you can fine-tune the use of breakpoints in your programs.

Breakpoint types
----------------

*Debug* objects support three kinds of breakpoints: :ref:`code <code-breakpoints>` breakpoints, :ref:`page <page-breakpoints>` breakpoints and :ref:`hardware <hardware-breakpoints>` breakpoints. Each kind of breakpoint causes an exception to be raised in the debugee. These exceptions are caught and handled automatically by the debugger.

Breakpoints have to be defined first and enabled later. The rationale behind this is that you can define as many breakpoints as you want, and then switch them on and off as you need to without having to delete them. This leads to a more efficient use of resources, and is consistent with what one expects of debuggers.

Code breakpoints are defined by the **define_code_breakpoint** method, enabled by the **enable_code_breakpoint** method. You can guess what are the methods to disable and erase code breakpoints. :)

Similarly, page breakpoints are defined by **define_page_breakpoint**, hardware breakpoints are defined by **define_hardware_breakpoint**, and so on.

.. _code-breakpoints:

Code breakpoints
++++++++++++++++

*Code* breakpoints are implemented by inserting an `int3 instruction <https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3>`_ (\xCC) at the address specified. When a thread tries to execute this instruction, a breakpoint exception is generated. It's global to the process because it overwrites the code to break at.

When hit, code breakpoints trigger a **breakpoint** event at your :ref:`event handler <the-eventhandler-class>`.

Let's look at the signature of *define_code_breakpoint*:

.. literalinclude:: ../../winappdbg/breakpoint.py
   :start-after: # Code breakpoints.
   :end-before: """

Where **dwProcessId** is the Id of the process where we want to set the breakpoint and **address** is the location of the breakpoint in the process memory. The other two parameters are optional and will be :ref:`explained later <conditional-and-automatic-breakpoints>`.

.. _page-breakpoints:

Page breakpoints
++++++++++++++++

*Page* breakpoints are implemented by changing the `access permissions <https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex>`_ of a given memory page. This causes a guard page exception to be generated when the given page is accessed anywhere in the code of the process.

When hit, page breakpoints trigger a **guard_page** event at your :ref:`event handler <the-eventhandler-class>`.

Let's see the signature of *define_page_breakpoint*:

.. literalinclude:: ../../winappdbg/breakpoint.py
   :start-after: # Page breakpoints.
   :end-before: """

Where **dwProcessId** is the same. But now **address** needs to be page-aligned and **pages** is the number of pages covered by the breakpoint. This is because `VirtualProtectEx() <https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex>`_ works only with entire pages, you can't change the access permissions on individual bytes.

.. _hardware-breakpoints:

Hardware breakpoints
++++++++++++++++++++

*Hardware* breakpoints are implemented by writing to the `debug registers <https://en.wikipedia.org/wiki/Debug_register>`_ (DR0-DR7) of a given thread, causing a single step exception to be generated when the given address is accessed anywhere in the code for that thread only. It's important to remember the debug registers have different values for each thread, so this can't be done global to the process (you can set the same breakpoint in all the threads, though).

When hit, hardware breakpoints trigger a **single_step** event at your :ref:`event handler <the-eventhandler-class>`.

The signature of *define_hardware_breakpoint* is this:

.. literalinclude:: ../../winappdbg/breakpoint.py
   :start-after: # Hardware breakpoints.
   :end-before: """

Seems a little more complicated than the others. :)

The first difference we see is the *dwProcessId* parameter has been replaced by **dwThreadId**. This is because hardware breakpoints are only applicable to single threads, not to the entire process.

The **address** is any address in the process memory, even if it's unmapped. This can be useful to set breakpoints on DLL libraries before they are loaded (as long as they don't get `relocated <https://en.wikipedia.org/wiki/Portable_Executable#Relocations>`_).

The **triggerFlag** parameter is used to specify exactly what event will trigger this breakpoint. There are four constants available:

.. only:: html

    +---------------------------------+---------------------------------------------+
    | *Constant*                      | *Meaning*                                   |
    +=================================+=============================================+
    | **Debug.BP_BREAK_ON_EXECUTION** | Break when executing on *address*.          |
    +---------------------------------+---------------------------------------------+
    | **Debug.BP_BREAK_ON_WRITE**     | Break when writing to *address*.            |
    +---------------------------------+---------------------------------------------+
    | **Debug.BP_BREAK_ON_ACCESS**    | Break when reading or writing to *address*. |
    +---------------------------------+---------------------------------------------+
    | **Debug.BP_BREAK_ON_IO_ACCESS** | *(Not currently used by today's hardware.)* |
    +---------------------------------+---------------------------------------------+

.. only:: latex

     * **Debug.BP_BREAK_ON_EXECUTION**:
        Break when executing on *address*.

     * **Debug.BP_BREAK_ON_WRITE**:
        Break when writing to *address*.

     * **Debug.BP_BREAK_ON_ACCESS**:
        Break when reading or writing to *address*.

The **sizeFlag** parameter says how large is the memory region to watch. There are again four constants:

.. only:: html

    +--------------------------+----------------------------------------------------+
    | *Constant*               | *Meaning*                                          |
    +==========================+====================================================+
    | **Debug.BP_WATCH_BYTE**  | Applies to 1 byte from *address*.                  |
    +--------------------------+----------------------------------------------------+
    | **Debug.BP_WATCH_WORD**  | Applies to 2 bytes (a word) from *address*.        |
    +--------------------------+----------------------------------------------------+
    | **Debug.BP_WATCH_DWORD** | Applies to 4 bytes (a double word) from *address*. |
    +--------------------------+----------------------------------------------------+
    | **Debug.BP_WATCH_QWORD** | Applies to 8 bytes (a quad word) from *address*.   |
    +--------------------------+----------------------------------------------------+

.. only:: latex

     * **Debug.BP_WATCH_BYTE**:
        Applies to 1 byte from *address*.

     * **Debug.BP_WATCH_WORD**:
        Applies to 2 bytes (a word) from *address*.

     * **Debug.BP_WATCH_DWORD**:
        Applies to 4 bytes (a double word) from *address*.

     * **Debug.BP_WATCH_QWORD**:
        Applies to 8 bytes (a quad word) from *address*.

Since x86 processors only have enough room for **four** hardware breakpoints in the debug registers, you can **only enable four of them at a time for a single thread**. You can define as many as you want, though, provided you only keep a maximum of four enabled breakpoints per thread at any time.

.. _conditional-and-automatic-breakpoints:

Conditional and automatic breakpoints
-------------------------------------

We have seen above that all the methods to define breakpoins have the optional parameters **condition** and **action**. But what do they mean?

The *condition* parameter
+++++++++++++++++++++++++

The **condition** parameter determines if the breakpoint is *conditional* or *unconditional*.

If it's set to *True* (the default value) the breakpoint is **unconditional**. Unconditional breakpoints always call the corresponding method of the event handler.

And if it's set to a **function** (or any other callable Python object), the breakpoint is **conditional**. Conditional breakpoints, when hit, call the *condition* callback. If this callback returns *True* the event handler method is also called, otherwise it isn't. This allows you to set breakpoints that will only trigger an event under specific conditions (for example, only stop the execution when *EAX* equals *0x100*, ignore it otherwise).

::

    # condition callback
    def eax_is_100(event):

      aThread = event.get_thread()
      Eax     = aThread.get_context()['Eax']

      if Eax == 0x100:

        # We are interested on this!
        return True

      # False alarm, ignore it...
      return False

    # Will only break when eax is 100 in that process at that address
    def break_when_eax_is_100(debug, pid, address):
      debug.define_code_breakpoint(pid, address, condition = eax_is_100)
      debug.enable_code_breakpoint(pid, address)

The *action* parameter
++++++++++++++++++++++

The **action** parameter allows you to set another callback. When not used, the breakpoint is **interactive**, meaning when it's hit (and it's condition callback returns *True*) the event handler method is called. But when it's used, the breakpoint is **automatic**, and that means this callback is called **instead** of the event handler method.

Automatic breakpoints are useful for setting tasks to be done "behind the back" of the event handler, so they don't have to be treated as special cases by your event handler routines.

::

    # action callback
    def change_eax_value(event):

      # Get the thread that hit the breakpoint
      aThread = event.get_process()

      # Set a new value for the EAX register
      aThread.set_register('Eax', 0xBAADF00D)

    # Will automatically change the return value of the function
    def auto_change_return_value(debug, pid, address):
      # 'address' must be the location of the 'ret' instruction
      debug.define_code_breakpoint(pid, address, action = change_eax_value)
      debug.enable_code_breakpoint(pid, address)

Breakpoints can be both *conditional* and *automatic*. Here is another example reusing the code above:

::

    # Will automatically change the return value of the function,
    # but only when the original value was 0x100
    def conditionally_change_return_value(debug, pid, address):
        # 'address' must be the location of the 'ret' instruction
        debug.define_code_breakpoint(pid, address, condition = eax_is_100,
                                                      action = change_eax_value)
        debug.enable_code_breakpoint(pid, address)

One-shot breakpoints
--------------------

Breakpoints of all types can also be **one-shot**. This means they're automatically disabled after being hit. This is useful for one time events, for example a debugger might want to set a one-shot breakpoint at the next instruction for tracing. You could also set one-shot breakpoints to do code coverage, where multiple executions of the same code are not relevant.

Note that one-shot breakpoints are only **disabled**, not deleted, so you can enable them again. Any disabled breakpoint can be enabled again, as a normal breakpoint or as one-shot, independently of how it's been used before.

To set one-shot breakpoints, after defining them use one of the **enable_one_shot_code_breakpoint**, **enable_one_shot_page_breakpoint** or **enable_one_shot_hardware_breakpoint** methods to enable it.

::

    # Will automatically change the return value of the function,
    # but only when the original value was 0x100,
    # and only the next time the function is called
    def conditionally_change_return_value(debug, pid, address):
        # 'address' must be the location of the 'ret' instruction
        debug.define_code_breakpoint(pid, address, condition = eax_is_100,
                                                      action = change_eax_value)
        debug.enable_one_shot_code_breakpoint(pid, address)

Batch operations on breakpoints
-------------------------------

The following methods are provided for working on all breakpoints at once:

.. only:: html

    +-------------------------------------+-----------------------------------------------------------------+
    | *Method*                            | *Description*                                                   |
    +=====================================+=================================================================+
    | **enable_all_breakpoints**          | Enables all disabled breakpoints in all processes.              |
    +-------------------------------------+-----------------------------------------------------------------+
    | **enable_one_shot_all_breakpoints** | Enables for one shot all disabled breakpoints in all processes. |
    +-------------------------------------+-----------------------------------------------------------------+
    | **disable_all_breakpoints**         | Disables all breakpoints in all processes.                      |
    +-------------------------------------+-----------------------------------------------------------------+
    | **erase_all_breakpoints**           | Erases all breakpoints in all processes.                        |
    +-------------------------------------+-----------------------------------------------------------------+

.. only:: latex

     * **enable_all_breakpoints**:
        Enables all disabled breakpoints in all processes.

     * **enable_one_shot_all_breakpoints**:
        Enables for one shot all disabled breakpoints in all processes.

     * **disable_all_breakpoints**:
        Disables all breakpoints in all processes.

     * **erase_all_breakpoints**:
        Erases all breakpoints in all processes.

These methods work with all breakpoints of a single process:

.. only:: html

    +-----------------------------------------+----------------------------------------------------------------------+
    | *Method*                                | *Description*                                                        |
    +=========================================+======================================================================+
    | **enable_process_breakpoints**          | Enables all disabled breakpoints for the given process.              |
    +-----------------------------------------+----------------------------------------------------------------------+
    | **enable_one_shot_process_breakpoints** | Enables for one shot all disabled breakpoints for the given process. |
    +-----------------------------------------+----------------------------------------------------------------------+
    | **disable_process_breakpoints**         | Disables all breakpoints for the given process.                      |
    +-----------------------------------------+----------------------------------------------------------------------+
    | **erase_process_breakpoints**           | Erases all breakpoints for the given process.                        |
    +-----------------------------------------+----------------------------------------------------------------------+

.. only:: latex

     * **enable_process_breakpoints**:
        Enables all disabled breakpoints for the given process.

     * **enable_one_shot_process_breakpoints**:
        Enables for one shot all disabled breakpoints for the given process.

     * **disable_process_breakpoints**:
        Disables all breakpoints for the given process.

     * **erase_process_breakpoints**:
        Erases all breakpoints for the given process.

Accessing the breakpoint objects
--------------------------------

For even more fine-tuning you might also want to access the *Breakpoint* objects directly. The **get_code_breakpoint** method retrieves a code breakpoint in a process, **get_page_breakpoint** works for page breakpoints in a process, and **get_hardware_breakpoint** gets the hardware breakpoint in a thread.

While it's always safe to request information from a *Breakpoint* object, it may not be so when modifying it, so be careful what methods you call. The following methods are safe to call:

.. only:: html

    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | *Method*                        | *Description*                                                                                                                                    |
    +=================================+==================================================================================================================================================+
    | **is_disabled**                 | If *True*, breakpoint is disabled.                                                                                                               |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_running**                  | If *True*, breakpoint was recently hit.                                                                                                          |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_here**                     | Returns *True* if the breakpoint is within the given address range.                                                                              |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_address**                 | Returns the breakpoint location.                                                                                                                 |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_size**                    | Returns the breakpoint size in bytes.                                                                                                            |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_conditional**              | If True, the breakpoint is conditional.                                                                                                          |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_condition**               | Returns the breakpoint *condition* parameter.                                                                                                    |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **set_condition**               | Changes the breakpoint *condition* parameter.                                                                                                    |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_automatic**                | If True, the breakpoint is automatic.                                                                                                            |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_action**                  | Returns the breakpoint *action* parameter.                                                                                                       |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **set_action**                  | Changes the breakpoint *action* parameter.                                                                                                       |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_slot**                    | *(For hardware breakpoints only)* Returns the debug register number used by this breakpoint, or *None* if the breakpoint is disabled or running. |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_trigger**                 | *(For hardware breakpoints only)* Returns the *trigger* parameter.                                                                               |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_watch**                   | *(For hardware breakpoints only)* Returns the *watch* parameter.                                                                                 |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_size_in_pages**           | *(For page breakpoints only)* Get the number of pages covered by the breakpoint.                                                                 |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **align_address_to_page_start** | *(Static, for page breakpoints only)* Align the given address to the start of the page it occupies.                                              |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **align_address_to_page_end**   | *(Static, for page breakpoints only)* Align the given address to the end of the page it occupies.                                                |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_buffer_size_in_pages**    | *(Static, for page breakpoints only)* Get the number of pages in use by the given buffer.                                                        |
    +---------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **is_disabled**:
        If *True*, breakpoint is disabled.

     * **is_running**:
        If *True*, breakpoint was recently hit.

     * **is_here**:
        Returns *True* if the breakpoint is within the given address range.

     * **get_address**:
        Returns the breakpoint location.

     * **get_size**:
        Returns the breakpoint size in bytes.

     * **is_conditional**:
        If True, the breakpoint is conditional.

     * **get_condition**:
        Returns the breakpoint *condition* parameter.

     * **set_condition**:
        Changes the breakpoint *condition* parameter.

     * **is_automatic**:
        If True, the breakpoint is automatic.

     * **get_action**:
        Returns the breakpoint *action* parameter.

     * **set_action**:
        Changes the breakpoint *action* parameter.

     * **get_slot**:
        *(For hardware breakpoints only)* Returns the debug register number used by this breakpoint, or *None* if the breakpoint is disabled or running.

     * **get_trigger**:
        *(For hardware breakpoints only)* Returns the *trigger* parameter.

     * **get_watch**:
        *(For hardware breakpoints only)* Returns the *watch* parameter.

     * **get_size_in_pages**:
        *(For page breakpoints only)* Get the number of pages covered by the breakpoint.

     * **align_address_to_page_start**:
        *(Static, for page breakpoints only)* Align the given address to the start of the page it occupies.

     * **align_address_to_page_end**:
        *(Static, for page breakpoints only)* Align the given address to the end of the page it occupies.

     * **get_buffer_size_in_pages**:
        *(Static, for page breakpoints only)* Get the number of pages in use by the given buffer.

Listing the breakpoints
-----------------------

*Debug* objects also allow you to retrieve lists of defined breakpoints, filtered by different criteria. This listing methods return lists of tuples, and inside this tuples are the *Breakpoint* objects described earlier.

The following table describes the listing methods and what they return, where **pid** is a process ID, **tid** is a thread ID and **bp** is a *Breakpoint* object.

.. only:: html

    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | Method                               | Description                                                                                          |
    +======================================+======================================================================================================+
    | **get_all_code_breakpoints**         | Returns all code breakpoints as a list of tuples (pid, bp).                                          |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_all_page_breakpoints**         | Returns all page breakpoints as a list of tuples (pid, bp).                                          |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_all_hardware_breakpoints**     | Returns all hardware breakpoints as a list of tuples (tid, bp).                                      |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_process_code_breakpoints**     | Returns all code breakpoints for the given process.                                                  |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_process_page_breakpoints**     | Returns all page breakpoints for the given process.                                                  |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_thread_hardware_breakpoints**  | Returns all hardware breakpoints for the given thread.                                               |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+
    | **get_process_hardware_breakpoints** | Returns all hardware breakpoints for each thread in the given process as a list of tuples (tid, bp). |
    +--------------------------------------+------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **get_all_code_breakpoints**:
        Returns all code breakpoints as a list of tuples (pid, bp).

     * **get_all_page_breakpoints**:
        Returns all page breakpoints as a list of tuples (pid, bp).

     * **get_all_hardware_breakpoints**:
        Returns all hardware breakpoints as a list of tuples (tid, bp).

     * **get_process_code_breakpoints**:
        Returns all code breakpoints for the given process.

     * **get_process_page_breakpoints**:
        Returns all page breakpoints for the given process.

     * **get_thread_hardware_breakpoints**:
        Returns all hardware breakpoints for the given thread.

     * **get_process_hardware_breakpoints**:
        Returns all hardware breakpoints for each thread in the given process as a list of tuples (tid, bp).
