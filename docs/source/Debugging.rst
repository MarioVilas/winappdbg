.. _debugging:

Debugging
*********

Debugging operations are performed by the :ref:`Debug <the-debug-class>` class. You can receive notification of debugging events by passing a custom event handler to the *Debug* object when creating it - each event is represented by an :ref:`Event <the-event-class>` object. Custom event handlers can also be subclasses of the :ref:`EventHandler <the-eventhandler-class>` class.

*Debug* objects can also set :ref:`breakpoints, watches and hooks <breakpoints-watches-and-hooks>` and support the use of :ref:`labels <labels>`.

.. _the-debug-class:

The Debug class
---------------

A *Debug* object provides methods to launch new processes, attach to and detach from existing processes, and manage breakpoints. It also contains a *System* snapshot to instrument debugged processes - this snapshot is updated automatically for processes being debugged.

When you're finished using the *Debug* object, you must either call its *stop()* method from a *finally* block, or put the *Debug* object inside a *with* statement.

.. note::
   In previous examples we have used a **System.request_debug_privileges()** call to get debug privileges. When using the *Debug* class we don't need to do that - it's taken care of automatically in the constructor.

Example #1: starting a new process and waiting for it to finish
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/01_start.py>`

.. literalinclude:: ../../examples/debugging/01_start.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.

Example #2: attaching to a process and waiting for it to finish
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/02_attach.py>`

.. literalinclude:: ../../examples/debugging/02_attach.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.

Example #3: attaching to a process by filename
++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/03_find_and_attach.py>`

.. literalinclude:: ../../examples/debugging/03_find_and_attach.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.

Example #4: killing the debugged process when the debugger is closed
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/04_kill_on_exit.py>`

.. literalinclude:: ../../examples/debugging/04_kill_on_exit.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.

.. _the-interactive-debugger:

The interactive debugger
------------------------

The *Debug* class also contains an implementation of a simple console debugger. It can come in handy when testing your scripts, or to manually handle unexpected situations.

Example #5: running an interactive debugger session
+++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/05_interactive.py>`

.. literalinclude:: ../../examples/debugging/05_interactive.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

.. _the-event-class:

The Event class
---------------

So far we have seen how to attach to or start processes. But a debugger also needs to react to events that happen in the debugee, and this is done by passing a callback function as the **eventHandler** parameter when instancing the *Debug* object. This callback, when called, will receive as parameter an **Event** object which describes the event and contains a reference to the *Debug* object itself.

Every *Event* object has the following set of common methods to get information from them:

.. only:: html

    +---------------------------+---------------------------------------------------------------+
    | Method                    | Description                                                   |
    +===========================+===============================================================+
    | **get_event_name**        | Returns the name of the event.                                |
    +---------------------------+---------------------------------------------------------------+
    | **get_event_description** | Returns a user-friendly description of the event.             |
    +---------------------------+---------------------------------------------------------------+
    | **get_event_code**        | Returns the event code constant, as defined by the Win32 API. |
    +---------------------------+---------------------------------------------------------------+
    | **get_pid**               | Returns the ID of the process where the event occurred.       |
    +---------------------------+---------------------------------------------------------------+
    | **get_tid**               | Returns the ID of the thread where the event occurred.        |
    +---------------------------+---------------------------------------------------------------+
    | **get_process**           | Returns the Process object.                                   |
    +---------------------------+---------------------------------------------------------------+
    | **get_thread**            | Returns the Thread object.                                    |
    +---------------------------+---------------------------------------------------------------+

.. only:: latex

     * **get_event_name**: Returns the name of the event.

     * **get_event_description**: Returns a user-friendly description of the event.

     * **get_event_code**: Returns the event code constant, as defined by the Win32 API.

     * **get_pid**: Returns the ID of the process where the event occurred.

     * **get_tid**: Returns the ID of the thread where the event occurred.

     * **get_process**: Returns the Process object.

     * **get_thread**: Returns the Thread object.

Then depending on the event type, you can get more information that's specific to each type.

.. only:: html

    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Method                            | Applicable events                             | Description                                                                                                                                                                                       |
    +===================================+===============================================+===================================================================================================================================================================================================+
    | **get_filename**                  | Process creation and destruction,             | Returns the filename of the EXE or DLL.                                                                                                                                                           |
    |                                   | DLL library load and unload.                  |                                                                                                                                                                                                   |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_exit_code**                 | Process and thread destruction.               | Returns the exit code of the process or thread.                                                                                                                                                   |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_exception_name**            | Exceptions.                                   | Returns the Win32 API constant name for the exception code.                                                                                                                                       |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_exception_code**            | Exceptions.                                   | Returns the Win32 API constant value for the exception code.                                                                                                                                      |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_exception_address**         | Exceptions.                                   | Returns the memory address where the exception has occurred. For exceptions not involving memory operations, the current execution pointer is returned.                                           |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_system_defined_exception**   | Exceptions.                                   | Returns *True* if the exception was caused by the operating system rather than the application code.                                                                                              |
    |                                   |                                               | Most notably, one such exception is always raised when attaching to a process, and then running a process from the debugger (right after process initialization is complete).                     |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_first_chance**               | Exceptions.                                   | If *True*, the exception hasn't been passed yet to the exception handlers of the debuggee. If *False*, the exception was passed to the exception handlers but none of them could handle it.       |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **is_nested**                     | Exceptions.                                   | If *True*, the exception was raised when handing at least one more exception.                                                                                                                     |
    |                                   |                                               | Many exceptions can be nested that way. Call **get_nexted_exceptions** to get a list of those nested exceptions.                                                                                  |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **get_fault_address**             | Exceptions caused by invalid memory access.   | Returns the memory address where the invalid access has occurred.                                                                                                                                 |
    +-----------------------------------+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **get_filename**:
        Returns the filename of the EXE or DLL.

        **Applicable events:** Process creation and destruction, DLL library load and unload.

     * **get_exit_code**:
        Returns the exit code of the process or thread.

        **Applicable events:** Process and thread destruction.

     * **get_exception_name**:
        Returns the Win32 API constant name for the exception code.

        **Applicable events:** Exceptions.

     * **get_exception_code**:
        Returns the Win32 API constant value for the exception code.

        **Applicable events:** Exceptions.

     * **get_exception_address**:
        Returns the memory address where the exception has occurred.

        For exceptions not involving memory operations, the current execution pointer is returned.

        **Applicable events:** Exceptions.

     * **is_system_defined_exception**:
        Returns *True* if the exception was caused by the operating system rather than the application code.

        Most notably, one such exception is always raised when attaching to a process, and then running a process from the debugger (right after process initialization is complete).

        **Applicable events:** Exceptions.

     * **is_first_chance**:
        If *True*, the exception hasn't been passed yet to the exception handlers of the debuggee.

        If *False*, the exception was passed to the exception handlers but none of them could handle it.

        **Applicable events:** Exceptions.

     * *is_nested**:
        If *True*, the exception was raised when handing at least one more exception.

        Many exceptions can be nested that way. Call **get_nexted_exceptions** to get a list of those nested exceptions.

        **Applicable events:** Exceptions.

     * **get_fault_address**:
        Returns the memory address where the invalid access has occurred.

        **Applicable events:** Exceptions caused by invalid memory access.

Example #6: handling debug events
+++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/06_debug_events.py>`

.. literalinclude:: ../../examples/debugging/06_debug_events.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

.. _the-crash-and-crashdao-classes:

The Crash and CrashDAO classes
------------------------------

Crashes are exceptions a program can't recover from (also known as second-chance exceptions or last chance exceptions). A **crash dump** is a collection of information from a crash in a program that can (hopefully!) help you reproduce or fix the bug that caused it in the first place.

**WinAppDbg** provides the *Crash* class to generate and manipulate crash dumps. When instancing a *Crash* object only the most basic information is collected, you have to call the *fetch_extra_data* method to collect more data. This lets you control which information to gather and when - for example you may be interested in gathering more information only under certain conditions, or for certain kinds of exceptions.

*Crash* objects also support :ref:`heuristic signatures <signature>` that can be used to try to determine whether two crashes were caused by the same bug, in order to discard duplicates. It can also try to guess how exploitable would the found crashes be, using similar heuristics to those of `!exploitable <https://web.archive.org/web/20210413145507/https://archive.codeplex.com/?p=msecdbg>`_.

Now, the next step would be storing the crash dump somewhere for later examination. The most crude way to do this is using the standard *pickle* module. This is easy and guaranteed to work, but not very comfortable! Crash dumps stored that way are hard to read outside Python.

A more flexible way to store crash dumps is using the *CrashDAO* class. It uses `SQLAlchemy <https://www.sqlalchemy.org/>`_ and `PyMongo <https://pymongo.readthedocs.io/en/stable/>`_ to connect to MongoDB or any supported SQL database, create the required tables if needed, and store multiple crash dumps in it. This is the preferred method, since it's easier to access and manipulate the information outside Python, and you can store crashes from multiple machines into the same database.

Example #7: saving crash dumps
++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/07_crash_dump.py>`

.. literalinclude:: ../../examples/debugging/07_crash_dump.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

.. _the-eventhandler-class:

The EventHandler class
----------------------

Using a callback function is not very flexible when your code is too large. For that reason, the **EventHandler** class is provided.

Instead of a function, you can define a subclass of *EventHandler* where each method of your class should match an event - for example, to receive notification on new DLL libraries being loaded, define the *load_dll* method in your class. If you don't want to receive notifications on a specific event, simply don't define the method in your class.

These are the most important event notification methods:

.. only:: html

    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Notification name   | What does it mean?                                    | When is it received?                                                                                                                                       |
    +=====================+=======================================================+============================================================================================================================================================+
    | **create_process**  | The debugger has attached to a new process.           | When attaching to a process, when starting a new process for debugging, or when the debugee starts a new process and the *bFollow* flag was set to *True*. |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **exit_process**    | A debugee process has finished executing.             | When a process terminates by itself or when the *Process.kill* method is called.                                                                           |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **create_thread**   | A debugee process has started a new thread.           | When the process creates a new thread or when the *Process.start_thread* method is called.                                                                 |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **exit_thread**     | A thread in a debugee process has finished executing. | When a thread terminates by itself or when the *Thread.kill* method is called.                                                                             |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **load_dll**        | A module in a debugee process was loaded.             | When a process loads a DLL module by itself or when the *Process.inject_dll* method is called.                                                             |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **unload_dll**      | A module in a debugee process was unloaded.           | When a process unloads a DLL module by itself.                                                                                                             |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **exception**       | An exception was raised by the debugee.               | When a hardware fault is triggered or when the process calls `RaiseException() <http://msdn.microsoft.com/en-us/library/ms680552(VS.85).aspx>`_.           |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **output_string**   | The debuggee has sent a debug string.                 | When the process calls `OutputDebugString() <http://msdn.microsoft.com/en-us/library/windows/desktop/aa363362(v=vs.85).aspx>`_.                            |
    +---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **create_process**:

        *What does it mean?*: The debugger has attached to a new process.

        *When is it received?*: When attaching to a process, when starting a new process for debugging, or when the debugee starts a new process and the *bFollow* flag was set to *True*.

     * **exit_process**:

        *What does it mean?*: A debugee process has finished executing.

        *When is it received?*: When a process terminates by itself or when the *Process.kill* method is called.

     * **create_thread**:

        *What does it mean?*: A debugee process has started a new thread.

        *When is it received?*: When the process creates a new thread or when the *Process.start_thread* method is called.

     * **exit_thread**:

        *What does it mean?*: A thread in a debugee process has finished executing.

        *When is it received?*: When a thread terminates by itself or when the *Thread.kill* method is called.

     * **load_dll**:

        *What does it mean?*: A module in a debugee process was loaded.

        *When is it received?*: When a process loads a DLL module by itself or when the *Process.inject_dll* method is called.

     * **unload_dll**:

        *What does it mean?*: A module in a debugee process was unloaded.

        *When is it received?*: When a process unloads a DLL module by itself.

     * **exception**:

        *What does it mean?*: An exception was raised by the debugee.

        *When is it received?*: When a hardware fault is triggered or when the process calls `RaiseException() <http://msdn.microsoft.com/en-us/library/ms680552(VS.85).aspx>`_.

     * **output_string**:

        *What does it mean?*: The debuggee has sent a debug string.

        *When is it received?*: When the process calls `OutputDebugString() <http://msdn.microsoft.com/en-us/library/windows/desktop/aa363362(v=vs.85).aspx>`_.

The event handler can also receive notifications for specific exceptions as a different event. When you define the method for that exception, it takes precedence over the more generic *exception* method.

These are the most important exception notification methods:

.. only:: html

    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Notification name    | What does it mean?                                       | When is it received                                                                                                                                                                                                                                                                     |
    +======================+==========================================================+=========================================================================================================================================================================================================================================================================================+
    | **access_violation** | An access violation exception was raised by the debugee. | When the debuggee tries to access invalid memory.                                                                                                                                                                                                                                       |
    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **ms_vc_exception**  | A C++ exception was raised by the debugee.               | When the debuggee calls RaiseException() with a custom exception code. This is what the implementation of throw() of the Visual Studio runtime does.                                                                                                                                    |
    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **breakpoint**       | A breakpoint exception was raised by the debugee.        | When a hardware fault is triggered by the `int3 opcode <https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3>`_, when the process calls `DebugBreak() <http://msdn.microsoft.com/en-us/library/ms679297(VS.85).aspx>`_, or when a code breakpoint set by your program is triggered. |
    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **single_step**      | A single step exception was raised by the debugee.       | When a hardware fault is triggered by the `trap flag <http://maven.smith.edu/~thiebaut/ArtOfAssembly/CH17/CH17-2.html#HEADING2-10>`_ or the `icebp opcode <http://www.rcollins.org/secrets/opcodes/ICEBP.html>`_, or when a hardware breakpoint set by your program is triggered.       |
    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **guard_page**       | A guard page exception was raised by the debugee.        | When a `guard page <https://docs.microsoft.com/es-es/windows/win32/memory/creating-guard-pages>`_ is hit or when a page breakpoint set by your program is triggered.                                                                                                                    |
    +----------------------+----------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

    **access_violation**:

        *What does it mean?*: An access violation exception was raised by the debugee.

        *When is it received?*: When the debuggee tries to access invalid memory.

    **ms_vc_exception**:

        *What does it mean?*: A C++ exception was raised by the debugee.

        *When is it received?*: When the debuggee calls RaiseException() with a custom exception code. This is what the implementation of throw() of the Visual Studio runtime does.

    **breakpoint**:

        *What does it mean?*: A breakpoint exception was raised by the debugee.

        *When is it received?*: When a hardware fault is triggered by the `int3 opcode <https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3>`_, when the process calls `DebugBreak() <http://msdn.microsoft.com/en-us/library/ms679297(VS.85).aspx>`_, or when a code breakpoint set by your program is triggered.

    **single_step**:

        *What does it mean?*: A single step exception was raised by the debugee.

        *When is it received?*: When a hardware fault is triggered by the `trap flag <http://maven.smith.edu/~thiebaut/ArtOfAssembly/CH17/CH17-2.html#HEADING2-10>`_ or the `icebp opcode <http://www.rcollins.org/secrets/opcodes/ICEBP.html>`_, or when a hardware breakpoint set by your program is triggered.

    **guard_page**:

        *What does it mean?*: A guard page exception was raised by the debugee.

        *When is it received?*: When a `guard page <https://docs.microsoft.com/es-es/windows/win32/memory/creating-guard-pages>`_ is hit or when a page breakpoint set by your program is triggered.

In addition to all this, the *EventHandler* class provides a simple method for API hooking: the **apiHooks** class property. This property is a dictionary of tuples, specifying which API calls to hook on what DLL libraries, and what parameters does each call take (using ctypes definitions). That's it! The *EventHandler* class will automatically hooks this APIs for you when the corresponding library is loaded, and a method of your subclass will be called when entering and leaving the API function.

.. note::

    One thing to be careful with when hooking API functions: all pointers should be declared as having the void type. Otherwise ctypes gets too "helpful" and tries to access the memory pointed to by them... and crashes, since those pointers only work in the debugged process.

Example #8: tracing execution
+++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/08_tracing.py>`

.. literalinclude:: ../../examples/debugging/08_tracing.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #9: intercepting API calls
++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/09_api_hook.py>`

.. literalinclude:: ../../examples/debugging/09_api_hook.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

The EventSift class
-------------------

If you're debugging more than one process at a time, keeping track of everything can be trickier. For that reason there's also a class called **EventSift**. You can wrap your *EventHandler* class with it to create a new *EventHandler* instance for each debugged process.

That way, your *EventHandler* can be written as if only a single process was being debugged, but you can attach to as many processes as you want. Each *EventHandler* will only "see" its own debugee.

Example #10: sifting events per process
+++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/10_event_sifting.py>`

.. literalinclude:: ../../examples/debugging/10_event_sifting.py
   :start-after: from winappdbg
   :end-before: # When invoked from the command line,

.. _breakpoints-watches-and-hooks:

Breakpoints, watches and hooks
------------------------------

A *Debug* object provides a small set of methods to set breakpoints, watches and hooks. These methods in turn use an underlying, more sophisticated interface that is described at the wiki page HowBreakpointsWork.

The **break_at** method sets a code breakpoint at the given address. Every time the code is run by any thread, a callback function is called. This is useful to know when certain parts of the debugee's code are being run (for example, set it at the beginning of a function to see how many times it's called).

The **hook_function** method sets a code breakpoint at the beginning of a function and allows you to set two callbacks - one when entering the function and another when returning from it. It works pretty much like the *apiHooks* property of the *EventHandler* class, only it doesn't need the function to be exported by a DLL library. It's useful for intercepting calls to internal functions of the debugee, if you know where they are.

The **watch_variable** method sets a hardware breakpoint at the given address. Every time a read or write access is made to that address, a callback function is called. It's useful for tracking accesses to a variable (for example, a member of a C++ object in the heap). It works only on specific threads, to monitor the variable on the entire process you must set a watch for each thread.

Finally, the **watch_buffer** method sets a page breakpoint at the given address range. Every time a read or write access is made to that part of the memory a callback function is called. It's similar to *watch_variable* but it works for the entire process, not just a single thread, and it allows any range to be specified (*watch_variable* only works for small address ranges, from 1 to 8 bytes).

*Debug* objects also allow *stalking*. Stalking basically means to set one-shot breakpoints - that is, breakpoints that are automatically disabled after they're hit for the first time. The term was originally coined by **Pedram Amini** for his `Process Stalker <https://www.openrce.org/downloads/details/171>`_ tool, and this technique is key to `differential debugging <https://www.zynamics.com/binnavi.html>`_.

The stalking methods and their equivalents are the following:

+--------------------+------------------+
| Stalking method    | Equivalent to    |
+====================+==================+
| *stalk_at*         | *break_at*       |
+--------------------+------------------+
| *stalk_function*   | *hook_function*  |
+--------------------+------------------+
| *stalk_variable*   | *watch_variable* |
+--------------------+------------------+
| *stalk_buffer*     | *watch_buffer*   |
+--------------------+------------------+

Example #11: setting a breakpoint
+++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/11_breakpoint.py>`

.. literalinclude:: ../../examples/debugging/11_breakpoint.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #12: hooking a function
+++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/12_hook_function.py>`

.. literalinclude:: ../../examples/debugging/12_hook_function.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #13: watching a variable
++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/13_watch_variable.py>`

.. literalinclude:: ../../examples/debugging/13_watch_variable.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #14: watching a buffer
++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/14_watch_buffer.py>`

.. literalinclude:: ../../examples/debugging/14_watch_buffer.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

.. _labels:

Labels
------

Labels are used to represent memory locations in a more user-friendly way than simply using their addresses. This is useful to provide a better user interface, both for input and output. Also, labels can be useful when DLL libraries in a debugee are relocated on each run - memory addresses change every time, but labels don't.

For example, the label *"kernel32!CreateFileA"* always points to the *CreateFileA* function of the *kernel32.dll* library. The actual memory address, on the other hand, may change across Windows versions.

In addition to exported functions, debugging symbols are used whenever possible.

A complete explanation on how labels work can be found at the Advanced Topics section of this document.

Example #15: getting the label for a given memory address
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/15_get_label.py>`

.. literalinclude:: ../../examples/debugging/15_get_label.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #16: resolving a label back into a memory address
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/16_resolve_label.py>`

.. literalinclude:: ../../examples/debugging/16_resolve_label.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Generating minidump files
--------------------------

In addition to WinAppDbg's native crash dumps, you can also generate standard Windows minidump files (.dmp) that can be analyzed with tools like WinDbg, Visual Studio, or other debuggers. Minidumps are the industry-standard format for crash reporting on Windows.

The minidump functionality is available through the :meth:`Process.generate_minidump` method for any process, and through :meth:`Event.generate_minidump` method on debug events for convenient crash dump generation. Exception events automatically include exception context and exception records.

Example #17: saving crash minidumps
++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/17_crash_minidump.py>`

.. literalinclude:: ../../examples/debugging/17_crash_minidump.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,
