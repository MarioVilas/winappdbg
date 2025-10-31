﻿.. _tools:

Command line tools
******************

*WinAppDbg* comes with a collection of tools useful for common tasks when debugging or fuzzing a program. The most important tool, the :ref:`Crash logger <crash-logger>`, attaches to any number of target processes and collects crash dump information in a SQL database. It can also apply :ref:`heuristics <signature>` to discard multiple occurrences of the same crash.

The source code of these tools can also be read for more examples on programming using *WinAppDbg*.

.. _crash-logger:

Crash logger
++++++++++++

.. only:: html

    .. figure:: _static/crash_logger.png
       :align:  right

* :download:`crash_logger.py <../../winappdbg/tools/crash_logger.py>` :

   Attaches as a debugger or starts a new process for debugging. Whenever an interesting debug event occurs (i.e. a bug is found) it can save the info to a database (SQLite, MySQL, SQL Server, etc.) and/or log it through standard output.

   A :ref:`heuristic signature <signature>` can be used to try to determine whether two crashes were caused by the same bug, in order to discard duplicates. It can also try to guess how exploitable would the found crashes be, using similar heuristics to those of `!exploitable <https://web.archive.org/web/20210413145507/https://archive.codeplex.com/?p=msecdbg>`_.

   Additional features allow attaching to system services, setting breakpoints at the target process(es), attaching to spawned child processes, restarting crashed processes, and running a custom command when a crash is found.

   Settings are defined in a Unix-style configuration file. Here's a :download:`template file <../../winappdbg/tools/example.cfg>` you can use, where all options are explained.

* :download:`crash_report.py <../../winappdbg/tools/crash_report.py>` :

   Shows the contents of the crashes database to standard output.

Process tools
+++++++++++++

These tools were inspired by the **ptools** suite by `Nicolás Economou <https://x.com/nicoeconomou>`_.

* :download:`pdebug.py <../../winappdbg/tools/pdebug.py>` :

   Extremely simple command line debugger. It's main feature is being written entirely in Python, so it's easy to modify or write plugins for it.

* :download:`ptrace.py <../../winappdbg/tools/ptrace.py>` :

   Traces execution of a process. It supports three methods: single stepping, single stepping on branches, and native syscall hooking.

* :download:`pinject.py <../../winappdbg/tools/pinject.py>` :

   Forces a process to load a DLL library of your choice.

* :download:`pfind.py <../../winappdbg/tools/pfind.py>` :

   Finds the given text, binary data, binary pattern or regular expression in a process memory space.

* :download:`pstrings.py <../../winappdbg/tools/pstrings.py>` :

   Extracts printable strings from a process memory space, similar to the Unix ``strings`` command. Supports both ASCII and Unicode (UTF-16LE) string extraction with configurable minimum length.

* :download:`plist.py <../../winappdbg/tools/plist.py>` :

   Shows a list of all currently running processes.

* :download:`pmap.py <../../winappdbg/tools/pmap.py>` :

   Shows a map of a process memory space.

* :download:`pread.py <../../winappdbg/tools/pread.py>` :

   Reads the memory contents of a process to standard output or any file of your choice.

* :download:`pwrite.py <../../winappdbg/tools/pwrite.py>`:

   Writes to the memory of a process from the command line or any file of your choice.

* :download:`pkill.py <../../winappdbg/tools/pkill.py>` :

   Terminates a process or a batch of processes.

Miscellaneous
+++++++++++++

* :download:`SelectMyParent.py <../../winappdbg/tools/SelectMyParent.py>` :

   Allows you to create a new process specifying any other process as it's parent, and inherit it's handles. See the `blog post by Didier Stevens <https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/>`_ for the original C version.

* :download:`hexdump.py <../../winappdbg/tools/hexdump.py>` :

   Shows an hexadecimal dump of the contents of a file.
