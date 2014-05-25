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
test / fuzz Windows applications with quickly coded Python scripts. Several
ready to use utilities are shipped and can be used for this purposes.

Current features also include disassembling x86/x64 native code, debugging
multiple processes simultaneously and produce a detailed log of application
crashes, useful for fuzzing and automated testing.

Where can I find WinAppDbg?
===========================

 * [Homepage](http://winappdbg.sourceforge.net/)

Download links
==============

 * [Windows installer (32 bits)](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win32.msi/download)
 * [Windows installer (64 bits)](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win-amd64.msi/download)
 * [Source code](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.zip/download)

Documentation
=============

Online
------

 * [Tutorial](http://winappdbg.sourceforge.net/doc/v1.5/tutorial)
 * [Reference](http://winappdbg.sourceforge.net/doc/v1.5/reference)

 Windows Help
 ------------
 
 * [Tutorial](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-tutorial.chm/download)
 * [Reference](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-reference.chm/download)

 HTML format (offline)
 ---------------------
 
 * [Tutorial](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-tutorial.chm/download)
 * [Reference](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-reference.chm/download)

 PDF format (suitable for printing)
 ----------------------------------
 
 * [Tutorial](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-tutorial.pdf/download)
 * [Reference](http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5-reference.pdf/download)
