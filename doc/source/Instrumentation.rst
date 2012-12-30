.. _instrumentation:

Instrumentation
***************

You can implement process instrumentation in your Python scripts by using the provided set of classes: :ref:`System <the-system-class>`, :ref:`Process <the-process-class>`, :ref:`Thread <the-thread-class>`, :ref:`Module <the-module-class>` and :ref:`Window <the-window-class>`. Each one acts as a snapshot of the processes, threads and DLL modules in the system.

A **System** object is a snapshot of all running processes. It contains **Process** objects, which in turn are snapshots of threads and modules, containing **Thread** and **Module** objects.

*System* objects also contain **Window** objects, representing the windows in the current desktop.

.. note::

    You don't need to be attached as a debugger for these classes to work.

.. _the-system-class:

The System class
----------------

The **System** class groups functionality that lets you instrument some global aspects of the machine where you installed *WinAppDbg*. It also behaves like a snapshot of the running processes. It can enumerate processes and perform operations on a batch of processes.

Example #1: knowing on which platform we're running
+++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/01_platform.py>`

.. literalinclude:: ../../examples/instrumentation/01_platform.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #2: enumerating running processes
+++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/02_show_processes.py>`

.. literalinclude:: ../../examples/instrumentation/02_show_processes.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #3: starting a new process
++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/03_start.py>`

.. literalinclude:: ../../examples/instrumentation/03_start.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

The *System* class has many more features, so we'll be coming back to it later on in the tutorial.

.. _the-process-class:

The Process class
-----------------

The **Process** class lets you manipulate any process in the system. You can get a *Process* instance by enumerating a *System* snapshot, or instancing one directly by providing the process ID.

A *Process* object allows you to manipulate the process memory (read, write, allocate and free operations), create new threads in the process, and more. It also acts as a snapshot of it's threads and DLL modules.

Example #4: enumerating threads and DLL modules in a process
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/04_show_threads_and_modules.py>`

.. literalinclude:: ../../examples/instrumentation/04_show_threads_and_modules.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #5: killing a process
+++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/05_kill.py>`

.. literalinclude:: ../../examples/instrumentation/05_kill.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #6: reading the process memory
++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/06_read_memory.py>`

.. literalinclude:: ../../examples/instrumentation/06_read_memory.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #7: getting the command line for a process
++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/07_command_line.py>`

.. literalinclude:: ../../examples/instrumentation/07_command_line.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #8: getting the environment variables for a process
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/08_environment.py>`

.. literalinclude:: ../../examples/instrumentation/08_environment.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #9: loading a DLL into the process
++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/09_inject_dll.py>`

.. literalinclude:: ../../examples/instrumentation/09_inject_dll.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #10: getting the process memory map
+++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/10_memory_map.py>`

.. literalinclude:: ../../examples/instrumentation/10_memory_map.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #11: searching the process memory
+++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/11_memory_search.py>`

.. literalinclude:: ../../examples/instrumentation/11_memory_search.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #12: dumping ASCII strings from the process memory
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/12_strings.py>`

.. literalinclude:: ../../examples/instrumentation/12_strings.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

.. _the-thread-class:

The Thread class
----------------

A **Thread** object lets you manipulate any thread in any process in the system. You can get a *Thread* instance by enumerating a *Process* snapshot, or instancing one manually by providing the thread ID.

You can manipulate the thread context (read and write to it's registers), perform typical debugger operations (getting stack traces, etc), suspend and resume execution, and more.

Example #13: freeze all threads in a process
++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/13_freeze.py>`

.. literalinclude:: ../../examples/instrumentation/13_freeze.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #14: print a thread's context
+++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/14_registers.py>`

.. literalinclude:: ../../examples/instrumentation/14_registers.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #15: print a thread's code disassembly
++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/15_disassemble.py>`

.. literalinclude:: ../../examples/instrumentation/15_disassemble.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

.. _the-module-class:

The Module class
----------------

A **Module** object lets you manipulate any thread in any process in the system. You can get a *Module* instance by enumerating a *Process* snapshot. *Module* objects can be used to resolve the addresses of exported functions in the process address space.

Example #16: resolve an API function in a process
+++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/16_resolve_api.py>`

.. literalinclude:: ../../examples/instrumentation/16_resolve_api.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

The Window class
----------------

A **Window** object lets you manipulate any window in the current desktop. You can get a *Window* instance by querying a *System* object.

Example #17: enumerate the top-level windows
++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/17_list_windows.py>`

.. literalinclude:: ../../examples/instrumentation/17_list_windows.py
   :start-after: $Id

Example #18: minimize all top-level windows
+++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/18_minimize_all.py>`

.. literalinclude:: ../../examples/instrumentation/18_minimize_all.py
   :start-after: $Id

Example #19: traverse the windows tree
++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/19_show_window_tree.py>`

.. literalinclude:: ../../examples/instrumentation/19_show_window_tree.py
   :start-after: $Id
   :end-before: if __name__ == '__main__':

Example #20: get windows by screen position
+++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/20_get_window_at.py>`

.. literalinclude:: ../../examples/instrumentation/20_get_window_at.py
   :start-after: $Id

Example #21: find windows by class and caption
++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/21_find_window.py>`

.. literalinclude:: ../../examples/instrumentation/21_find_window.py
   :start-after: $Id
   :end-before: if __name__ == '__main__':

Example #22: kill a program using its window
++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/22_kill.py>`

.. literalinclude:: ../../examples/instrumentation/22_kill.py
   :start-after: # ...begins just like the previous example...
   :end-before: if __name__ == '__main__':

Back to the System class
------------------------

As promised, we're back on the **System** class to see more of its features. We'll now see how to access the Windows Registry and work with system services.

Example #23: exporting a Registry key
+++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/23_registry_export.py>`

.. literalinclude:: ../../examples/instrumentation/23_registry_export.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #24: searching the Registry
+++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/24_registry_search.py>`

.. literalinclude:: ../../examples/instrumentation/24_registry_search.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Example #25: listing system services
++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/25_services.py>`

.. literalinclude:: ../../examples/instrumentation/25_services.py
   :start-after: $Id
   :end-before: if __name__ == "__main__":

Example #26: stopping and starting a system service
+++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/instrumentation/26_service_restart.py>`

.. literalinclude:: ../../examples/instrumentation/26_service_restart.py
   :start-after: $Id
   :end-before: # When invoked from the command line,
