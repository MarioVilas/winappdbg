.. _index:

Welcome to WinAppDbg's documentation!
*************************************

The *WinAppDbg* python module allows developers to quickly code instrumentation scripts in **Python** under a **Windows** environment.

It uses **ctypes** to wrap many `Win32 API <http://msdn.microsoft.com/en-us/library/ms679304(VS.85).aspx>`_ calls related to debugging, and provides a powerful abstraction layer to manipulate threads, libraries and processes, attach your script as a debugger, trace execution, hook API calls, handle events in your debugee and set breakpoints of different kinds (code, hardware and memory). Additionally it has no native code at all, making it easier to maintain or modify than other debuggers on Windows.

The intended audience are QA engineers and software security auditors wishing to test or fuzz Windows applications with quickly coded Python scripts. Several :ref:`ready to use utilities <tools>` are shipped and can be used for this purposes.

Current features also include disassembling x86 native code (using the `diStorm disassembler <http://ragestorm.net/distorm/>`_), debugging multiple processes simultaneously and produce a detailed log of application crashes, useful for fuzzing and automated testing.

Table of Contents
-----------------

.. toctree::
   :maxdepth: 2

   GettingStarted
   Tools
   ProgrammingGuide
   Redistribution

