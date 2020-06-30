I modified the project WinAppDbg so it can be running with python 3.

Test:
	I have tested almost the python files in the examples and tools folders with python 3.7.7. 

==================
What is WinAppDbg?
==================

The WinAppDbg python module allows developers to quickly code instrumentation
scripts in Python under a Windows environment.

It uses ctypes to wrap many Win32 API calls related to debugging, and provides
an object-oriented abstraction layer to manipulate threads, libraries and
processes, attach your script as a debugger, trace execution, hook API calls,
handle events in your debugee and set breakpoints of different kinds (code,
hardware and memory). Additionally it has no native code at all, making it
easier to maintain or modify than other debuggers on Windows.

The intended audience are QA engineers and software security auditors wishing to
test / fuzz Windows applications with quickly coded Python scripts, as well as malware
analysts and researchers wishing to instrument and test Windows binaries. Several
ready to use utilities are shipped and can be used for this purposes.

Current features also include disassembling x86/x64 native code, debugging
multiple processes simultaneously and produce a detailed log of application
crashes, useful for fuzzing and automated testing.

Where can I find WinAppDbg?
===========================

 * [Homepage](https://github.com/MarioVilas/winappdbg/)
 * [Source code](https://github.com/MarioVilas/winappdbg/releases/tag/winappdbg_v1.6)
 * [Documentation](http://winappdbg.readthedocs.io/en/latest/)

