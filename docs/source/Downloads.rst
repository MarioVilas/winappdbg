.. _download:

Downloading and installing
**************************

This is what you need to know to download, install and begin to use *WinAppDbg*:

Latest version
--------------

The latest version is **1.7**. You can get the bleeding-edge version from the `Github repository <https://github.com/MarioVilas/winappdbg>`_.

Dependencies
------------

Naturally you need the `Python interpreter <https://www.python.org/downloads/>`_. You'll have to install the 32 bit VM to debug 32 bit targets and the 64 bit VM for 64 bit targets. Both interpreters can be installed on the same machine.

There are optional dependencies listed in the package, which are needed to enable some extra features such as database support, disassemblers and other stuff. You can install them using pip as well.

Disassembler
++++++++++++

*WinAppDbg* itself doesn't come with a disassembler, but all of the following are compatible. *WinAppDbg* will pick the most suitable one automatically when needed, but you can also decide which one to use.

* The `Capstone <http://www.capstone-engine.org/>`_ disassembler by Nguyen Anh Quynh.
* The `diStorm <https://github.com/gdabah/distorm>`_ disassembler by Gil Dabah.
* The `BeaEngine <https://github.com/BeaEngine/beaengine>`_ disassembler by BeatriX.

Debugging Symbols
+++++++++++++++++

*WinAppDbg* has the capability to download debugging symbols from the Microsoft Debugging Symbols server. For best results, install the `Microsoft SDK <https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk>`_.

Database storage
++++++++++++++++

The `SQL Alchemy <https://www.sqlalchemy.org/>`_ ORM module gives *WinAppDbg* the ability to use a SQL database to store and find crash dumps. Most major database engines are supported.

To use MongoDB databases, you will need to install `PyMongo <https://pymongo.readthedocs.io/en/stable/>_`.

Install
-------

Use `PIP Installs Python <https://pip.pypa.io/en/stable/>`_ to install *WinAppDbg* from a local copy of the source code:

.. code-block:: bat

    pip install .

Support
-------

Minimim requirements:

* **Windows 7**

* **Python 3.9**

Recommended platform:

* **Windows 11**

* **Python 3.11**

It might work, but was not tested, under *Wine* and *ReactOS*, and some bugs and missing features are to be expected in these platforms (mainly due to missing APIs or Python itself not working well).

Interpreters other than CPython such as *Jython*, *IronPython* or *PyPy* are considered experimental - try at your own risk.

If you find a bug or have a feature suggestion, don't hesitate to  `open a new issue <https://github.com/MarioVilas/winappdbg/issues>`_. Both comments and complaints are welcome! :)

Known issues
------------

* Debugging 32 bit processes from a 64 bit Python VM does not work very well. Debugging 64 bit processes from a 32 bit Python VM does not work at all. This is in part because the Win32 API makes it difficult, but there's also a design problem in WinAppDbg: most of the C struct definitions change from 32 to 64 bits and there's currently no support for having both definitions at the same time. The effort is probably not worth it - if you need to debug both 32 and 64 bits simultaneously, it's best to have two scripts running in two different interpreters talking to each other via IPC.

* Some operations, most notably setting hardware breakpoints in the main thread, before the process has finished initializing, does not work. This is not supported by the Windows API itself, and is not a limitation of WinAppDbg. Future versions of WinAppDbg will try to detect this error and warn about it.

License
-------

This software is released under the `BSD license <https://en.wikipedia.org/wiki/BSD_license>`_, so as a user you are entitled to create derivative work and redistribute it if you wish. The sources to this documentation are provided and can be compiled with `Sphinx <https://www.sphinx-doc.org/en/master/>`_.
