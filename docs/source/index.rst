.. _index:

Welcome to WinAppDbg |version|!
*******************************

.. only:: html

    Download
    --------

    Some quick links for the impatient:

    * `Homepage <https://github.com/MarioVilas/winappdbg/>`_
    * `Source code <https://github.com/MarioVilas/winappdbg/releases/tag/winappdbg_v2.0>`_
    * `Documentation <http://winappdbg.readthedocs.io/en/latest/>`_

Introduction
------------

.. only:: html

    .. image:: _images/screenshot.png
       :width: 30%
       :align: right
       :target: Screenshots.html
       :alt: Click for more screenshots

The *WinAppDbg* python module allows developers to quickly code instrumentation scripts in **Python** under a **Windows** environment.

It uses **ctypes** to wrap many `Win32 API <https://learn.microsoft.com/en-us/windows/win32/debug/debugging-reference>`_ calls related to debugging, and provides a powerful abstraction layer to manipulate threads, libraries and processes, attach your script as a debugger, trace execution, hook API calls, handle events in your debugee and set breakpoints of different kinds (code, hardware and memory). Additionally it has no native code at all, making it easier to maintain or modify than other debuggers on Windows.

The intended audience are QA engineers and software security auditors wishing to test or fuzz Windows applications with quickly coded Python scripts. Several :ref:`ready to use tools <tools>` are shipped and can be used for this purposes.

Current features also include disassembling x86/x64 native code, debugging multiple processes simultaneously and produce a detailed log of application crashes, useful for fuzzing and automated testing.

Table of Contents
-----------------

.. toctree::
   :maxdepth: 2

   Downloads
   Tools
   ProgrammingGuide
   API
