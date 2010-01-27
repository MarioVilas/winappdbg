.. _debugging:

Debugging
*********

Debugging operations are performed by the :ref:`Debug <the-debug-class>` class. You can receive notification of debugging events by passing a custom event handler to the *Debug* object when creating it - each event is represented by an :ref:`Event <the-event-class>` object. Custom event handlers can also be subclasses of the :ref:`EventHandler <the-eventhandler-class>` class.

*Debug* objects can also set :ref:`breakpoints, watches and hooks <breakpoints-watches-and-hooks>` and support the use of :ref:`labels <labels>`.

.. _the-debug-class:

The Debug class
---------------

A *Debug* object provides methods to launch new processes, attach to and detach from existing processes, and manage breakpoints. It also contains a *System* snapshot to instrument debugged processes - this snapshot is updated automatically for processes being debugged.

Example #1: starting a new process and waiting for it to finish
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/01_start.py>`

.. literalinclude:: ../../examples/debugging/01_start.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #2: attaching to a process and waiting for it to finish
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/02_attach.py>`

.. literalinclude:: ../../examples/debugging/02_attach.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #3: attaching to a process by filename
+++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/03_find_and_attach.py>`

.. literalinclude:: ../../examples/debugging/03_find_and_attach.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #4: killing a process by attaching to it
+++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/04_kill.py>`

.. literalinclude:: ../../examples/debugging/04_kill.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

.. _the-event-class:

The Event class
---------------

So far we have seen how to attach to or start processes. But a debugger also needs to react to events that happen in the debugee, and this is done by passing a callback function as the **eventHandler** parameter when instancing the *Debug* object. This callback, when called, will receive as parameter an **Event** object which describes the event and contains a reference to the *Debug* object itself.

Example #5: handling debug events
++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/05_debug_events.py>`

.. literalinclude:: ../../examples/debugging/05_debug_events.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

.. _the-eventhandler-class:

The EventHandler class
-----------------------

Using a callback function is not very flexible when your code is too large. For that reason, the **EventHandler** class is provided.

Instead of a function, you can define a subclass of *EventHandler* where each method of your class should match an event - for example, to receive notification on new DLL libraries being loaded, define the *load_dll* method in your class. If you don't want to receive notifications on a specific event, simply don't define the method in your class.

These are the most important event notification methods:

+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| *Notification name* | *What does it mean?*                                  | *When is it received*                                                                                                                                      |
+=====================+=======================================================+============================================================================================================================================================+
| **create_process**  | The debugger has attached to a new process.           | When attaching to a process, when starting a new process for debugging, or when the debugee starts a new process and the *bFollow* flag was set to *True*. |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **exit_process**    | A debugee process has finished executing.             | When a process terminates by itself or when the *Process.kill* method is called.                                                                           |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **create_thread**   | A debugee process has started a new thread.           | When the process creates a new thread or when the _Process.start_thread_ method is called.                                                                 |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **exit_thread**     | A thread in a debugee process has finished executing. | When a thread terminates by itself or when the *Thread.kill* method is called.                                                                             |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **load_dll**        | A module in a debugee process was loaded.             | When a process loads a DLL module by itself or when the *Process.inject_dll* method is called.                                                             |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **unload_dll**      | A module in a debugee process was unloaded.           | When a process unloads a DLL module by itself.                                                                                                             |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **exception**       | An exception was raised by the debugee.               | When a hardware fault is triggered or when the process calls `RaiseException() <http://msdn.microsoft.com/en-us/library/ms680552(VS.85).aspx>`_.           |
+---------------------+-------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+

The event handler can also receive notifications for specific exceptions as a different event. When you define the method for that exception, it takes precedence over the more generic *exception* method.

These are the most important exception notification methods:

+---------------------+----------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| *Notification name* | *What does it mean?*                               | *When is it received*                                                                                                                                                                                                                                                                   |
+=====================+====================================================+=========================================================================================================================================================================================================================================================================================+
| **breakpoint**      | A breakpoint exception was raised by the debugee.  | When a hardware fault is triggered by the `int3 opcode <http://en.wikipedia.org/wiki/INT_(x86_instruction)#INT_3>`_, when the process calls `DebugBreak() <http://msdn.microsoft.com/en-us/library/ms679297(VS.85).aspx>`_, or when a code breakpoint set by your program is triggered. |
+---------------------+----------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **single_step**     | A single step exception was raised by the debugee. | When a hardware fault is triggered by the `trap flag <http://maven.smith.edu/~thiebaut/ArtOfAssembly/CH17/CH17-2.html#HEADING2-10>`_ or the `icebp opcode <http://www.rcollins.org/secrets/opcodes/ICEBP.html>`_, or when a hardware breakpoint set by your program is triggered.       |
+---------------------+----------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **guard_page**      | A guard page exception was raised by the debugee.  | When a `guard page <http://msdn.microsoft.com/en-us/library/aa366549(VS.85).aspx>`_ is hit or when a page breakpoint set by your program is triggered.                                                                                                                                  |
+---------------------+----------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

In addition to all this, the *EventHandler* class provides a simple method for API hooking: the **apiHooks** class property. This property is a dictionary of tuples, specifying which API calls to hook on what DLL libraries, and how many parameter does each call take. That's it! The *EventHandler* class will automatically hooks this APIs for you when the corresponding library is loaded, and a method of your subclass will be called when entering and leaving the API function.

Example #6: tracing execution
++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/06_tracing.py>`

.. literalinclude:: ../../examples/debugging/06_tracing.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #7: intercepting API calls
+++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/07_api_hook.py>`

.. literalinclude:: ../../examples/debugging/07_api_hook.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

.. _breakpoints-watches-and-hooks:

Breakpoints, watches and hooks
------------------------------

A *Debug* object provides a small set of methods to set breakpoints, watches and hooks. These methods in turn use an underlying, more sophisticated interface that is described at the wiki page HowBreakpointsWork.

The **break_at** method sets a code breakpoint at the given address. Every time the code is run by any thread, a callback function is called. This is useful to know when certain parts of the debugee's code are being run (for example, set it at the beginning of a function to see how many times it's called).

The **hook_function** method sets a code breakpoint at the beginning of a function and allows you to set two callbacks - one when entering the function and another when returning from it. It works pretty much like the *apiHooks* property of the *EventHandler* class, only it doesn't need the function to be exported by a DLL library. It's useful for intercepting calls to internal functions of the debugee, if you know where they are.

The **watch_variable** method sets a hardware breakpoint at the given address. Every time a read or write access is made to that address, a callback function is called. It's useful for tracking accesses to a variable (for example, a member of a C++ object in the heap). It works only on specific threads, to monitor the variable on the entire process you must set a watch for each thread.

Finally, the **watch_buffer** method sets a page breakpoint at the given address range. Every time a read or write access is made to that part of the memory a callback function is called. It's similar to *watch_variable* but it works for the entire process, not just a single thread, and it allows any range to be specified (*watch_variable* only works for small address ranges, from 1 to 8 bytes).

*Debug* objects also allow *stalking*. Stalking basically means to set one-shot breakpoints - that is, breakpoints that are automatically disabled after they're hit for the first time. The term was originally coined by **Pedram Amini** for his `Process Stalker <http://pedram.redhive.com/process_stalking_manual/>`_ tool.

The stalking methods and their equivalents are the following:

+--------------------+-----------------+
| *Stalking method*  | *Equivalent to* |
+====================+=================+
| **stalk_at**       | break_at        |
+--------------------+-----------------+
| **stalk_function** | hook_function   |
+--------------------+-----------------+
| **stalk_variable** | watch_variable  |
+--------------------+-----------------+
| **stalk_buffer**   | watch_buffer    |
+--------------------+-----------------+

Example #8: setting a breakpoint
+++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/08_breakpoint.py>`

.. literalinclude:: ../../examples/debugging/08_breakpoint.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #9: hooking a function
+++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/09_hook_function.py>`

.. literalinclude:: ../../examples/debugging/09_hook_function.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #10: watching a variable
+++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/10_watch_variable.py>`

.. literalinclude:: ../../examples/debugging/10_watch_variable.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

Example #11: watching a buffer
+++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/11_watch_buffer.py>`

.. literalinclude:: ../../examples/debugging/11_watch_buffer.py
   :start-after: from winappdbg
   :end-before: def simple_debugger

.. _labels:

Labels
------

Labels are used to represent memory locations in a more user-friendly way than simply using their addresses. This is useful to provide a better user interface, both for input and output. Also, labels can be useful when DLL libraries in a debugee are relocated on each run - memory addresses change every time, but labels don't.

For example, the label *"kernel32  CreateFileA"* always points to the *CreateFileA* function of the *kernel32.dll* library. The actual memory address, on the other hand, may change across Windows versions.

In addition to exported functions, debugging symbols are used whenever possible.

A complete explanation on how labels work can be found at the wiki page HowLabelsWork.

Example #12: getting the label for a given memory address
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/12_get_label.py>`

.. literalinclude:: ../../examples/debugging/12_get_label.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #13: resolving a label back into a memory address
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/debugging/13_resolve_label.py>`

.. literalinclude:: ../../examples/debugging/13_resolve_label.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

