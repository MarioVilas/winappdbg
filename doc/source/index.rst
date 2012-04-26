.. _index:

Welcome to WinAppDbg's documentation!
*************************************

The *WinAppDbg* python module allows developers to quickly code instrumentation scripts in **Python** under a **Windows** environment.

It uses **ctypes** to wrap many `Win32 API <http://msdn.microsoft.com/en-us/library/ms679304(VS.85).aspx>`_ calls related to debugging, and provides a powerful abstraction layer to manipulate threads, libraries and processes, attach your script as a debugger, trace execution, hook API calls, handle events in your debugee and set breakpoints of different kinds (code, hardware and memory). Additionally it has no native code at all, making it easier to maintain or modify than other debuggers on Windows.

The intended audience are QA engineers and software security auditors wishing to test or fuzz Windows applications with quickly coded Python scripts. Several :ref:`ready to use utilities <tools>` are shipped and can be used for this purposes.

Current features also include disassembling x86 native code (using the `diStorm disassembler <http://ragestorm.net/distorm/>`_), debugging multiple processes simultaneously and produce a detailed log of application crashes, useful for fuzzing and automated testing.

Download
--------

* `winappdbg-1.5.win32.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win32.exe/download>`_ - All supported 32-bit Python versions
* `winappdbg-1.5.win-amd64.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win-amd64.exe/download>`_ - All supported 64-bit Python versions
* `winappdbg-1.5.zip <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.zip/download>`_ - Manual install (setup.py)

For more information go to the :ref:`downloads page <download>`.

Related projects
----------------

Here is a list of software projects that use *WinAppDbg* in alphabetical order:

* `PyPeElf <http://sourceforge.net/apps/trac/pypeelf>`_ is an open source GUI executable file analyzer for Windows and Linux released under the BSD license. You can download it `here <http://pypeelf.svn.sourceforge.net/svnroot/pypeelf/trunk>`_ and there's also a `blog <http://pypeelf.blogspot.com/>`_.
* `python-haystack <https://github.com/trolldbois/python-haystack/>`_ is an heap analysis framework, focused on classic C structure matching. The basic functionnality is to search in a process' memory maps for a specific C Structures. The extended reverse engineering functionnality aims at reversing structures from memory/heap analysis.
* `SRS <http://5d4a.wordpress.com/2009/12/07/messing-around-with-register/>`_ is a tool to spy on registry API calls made by the program of your choice.

Reference
---------

`Click here <http://winappdbg.sourceforge.net/doc/latest/reference/>`_ for a full reference page of all classes and methods in *WinAppDbg*.

Tutorial
--------

.. toctree::
   :maxdepth: 2

   GettingStarted
   Tools
   ProgrammingGuide
   Redistribution
