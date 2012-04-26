.. _getting-started:

Getting started
***************

This is what you need to know to download, install and begin to use *WinAppDbg*:

.. _download:

Download
--------

The current version is **1.5**. There are different installers depending on your Python version (32 and 64 bits) and the source code can be installer via the setup.py script. All of them work in all supported Windows versions - by 32-bit or 64-bit it means the Python interpreter, not the OS itself.

The Sourceforge project's `download page <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/>`_ contains all versions. You can also get the bleeding-edge version as a source code tarball from the `subversion repository <http://winappdbg.svn.sourceforge.net/viewvc/winappdbg/trunk.tar.gz?view=tar>`_.

**Installer packages**

* `winappdbg-1.5.win32.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win32.msi/download>`_ - All supported 32-bit Python versions
* `winappdbg-1.5.win-amd64.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.win-amd64.msi/download>`_ - All supported 64-bit Python versions

**Source code**

* `winappdbg-1.5.zip <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-1.5.zip/download>`_ - Manual install (setup.py)

Manuals
-------

The programming manuals can be consulted `online <http://winappdbg.sourceforge.net/doc/v1.5/reference/>`_, but they're also available for download:

**Windows Help Files**

* `winappdbg-tutorial-1.5.chm  <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-tutorial-1.5.chm/download>`_ - Introduction and tutorials
* `winappdbg-reference-1.5.chm <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-reference-1.5.chm/download>`_ - Complete reference material

**PDF Files (for printing)**

* `winappdbg-tutorial-1.5.pdf  <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-tutorial-1.5.pdf/download>`_ - Introduction and tutorials
* `winappdbg-reference-1.5.pdf <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.5/winappdbg-reference-1.5.pdf/download>`_ - Complete reference material

Install
-------

Simply run the **Windows installer** package and follow the wizard.

If you prefer to install directly from the **sources** package, extract it to any temporary folder and run the following command: ::

    install

You can also install WinAppDbg from its `PyPI repository <http://pypi.python.org/pypi/winappdbg/>`_ using any of the compatible **package managers**:

* `PIP Installs Python <http://www.pip-installer.org/>`_ ::

    pip install winappdbg

* `PyPM <http://code.activestate.com/pypm/search:winappdbg/>`_ (only when using `ActivePython <http://www.activestate.com/activepython>`_)

* Easy Install (formerly from `Setuptools <http://pypi.python.org/pypi/setuptools>`_, now from `Distribute <http://packages.python.org/distribute/>`_) ::

    easy_install winappdbg

* `Python Package Manager <http://sourceforge.net/projects/pythonpkgmgr/>`_ (it's a GUI installer)

Dependencies
------------

Naturally you need the `Python interpreter <http://www.python.org/download/>`_. It's recommended to use Python 2.7.

If you're still using Python 2.5 64-bit, you'll need to install `ctypes <http://python.net/crew/theller/ctypes/>`_ as well. This is needed to interface with the Win32 API, and *WinAppDbg* won't work without it. Newer version os Python already have this module.

The following packages provide extra features and performance improvements, they are very recommended but not mandatory:

* *WinAppDbg* itself doesn't come with a disassembler, but any one of the following disassemblers is compatible:

  * The `diStorm <https://code.google.com/p/distorm/downloads/list>`_ disassembler by Gil Dabah (precompiled binaries, older version: `distorm-1.7.30.win32.exe <http://sourceforge.net/projects/winappdbg/files/additional%20packages/diStorm/diStorm%201.7.30%20for%20Python%202/distorm-1.7.30.win32.exe/download>`_ or `distorm-1.7.30.win-amd64.exe <http://sourceforge.net/projects/winappdbg/files/additional%20packages/diStorm/diStorm%201.7.30%20for%20Python%202/distorm-1.7.30.win-amd64.exe/download>`_).

  * The `BeaEngine <http://www.beaengine.org/>`_ disassembler by BeatriX (precompiled binaries: `BeaEnginePython-3.1.0.win32.exe <http://sourceforge.net/projects/winappdbg/files/additional%20packages/BeaEngine/BeaEnginePython-3.1.0.win32.exe/download>`_ or `BeaEnginePython-3.1.0.win-amd64.exe <http://sourceforge.net/projects/winappdbg/files/additional%20packages/BeaEngine/BeaEnginePython-3.1.0.win-amd64.exe/download>`_).

  * The `PyDasm <https://code.google.com/p/libdasm/>`_ Python bindings to libdasm by Ero Carrera (precompiled binaries: `PyDasm-1.5-precompiled.zip <http://sourceforge.net/projects/winappdbg/files/additional%20packages/PyDasm/PyDasm-1.5-precompiled.zip/download>`_).

* The `SQL Alchemy <http://www.sqlalchemy.org/>`_ ORM module gives the crash logger tool the ability to connect to almost any SQL database.

* The Python specializing compiler, `Psyco <http://psyco.sourceforge.net/>`_. *WinAppDbg* will experience a performance gain just by installing it, no additional steps are needed. You can download it from `here <http://psyco.sourceforge.net/download.html>`_.

* `PyReadline <http://ipython.scipy.org/moin/PyReadline/Intro>`_ is useful when using the console tools shipped with *WinAppDbg*, but they'll work without it. Basically what it does is provide autocomplete and history for console applications.

Support
-------

Minimim requirements:

* **Windows XP**

* **Python 2.5**

Recommended platform:

* **Windows 7**

* **Python 2.7**

It might work, but was not tested, under *Windows 2000*, *Wine* and *ReactOS*, and some bugs and missing features are to be expected in these platforms (mainly due to missing APIs).

Python 3.x support was experimental up to *WinAppDbg 1.4*, and was dropped with *WinAppDbg 1.5*. There are currently no plans to support Python 3.x in the near future - backwards compatibility would be broken and plenty of code would need to be refactored just to port it.

While there are still some issues that need ironing out, it may be worth trying out faster Python interpreters such as `PyPy <http://bitbucket.org/pypy/pypy/downloads/>`_ and `IronPython <http://ironpython.net/download/>`_.

If you find a bug or have a feature suggestion, don't hesitate to send an email to the [https://lists.sourceforge.net/lists/listinfo/winappdbg-users winappdbg-users] mailing list. Both comments and complaints are welcome! :)

The following tables show which Python interpreters, operating systems and processor architectures are currently supported. **Full** means all features are fully functional. **Partial** means some features may be broken and/or untested. **Experimental** means there is a subversion branch with at least partial support, but hasn't been merged to trunk yet. **Untested** means that though no testing was performed it should probably work.

* Python interpreters

    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | Python 2.4 and earlier   |  *not supported*  | Use an `older version <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/>`_ of WinAppDbg in this case. |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | Python 2.5 through 2.7   |     **full**      |                                                                                                                 |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | Python 3.0 and newer     |  *not supported*  |                                                                                                                 |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | PyPy 1.4 and earlier     |  *not supported*  | It doesn't seem to be available for download any more...                                                        |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | PyPy 1.5 and 1.6         |  *experimental*   | The sqlite3 dll is missing, after you fix that it should be the same as newer versions.                         |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | PyPy 1.7 and newer       |  *experimental*   | Some compatibility issues need fixing.                                                                          |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+
    | IronPython 2.0 and newer |  *experimental*   | Some compatibility issues need fixing.                                                                          |
    +--------------------------+-------------------+-----------------------------------------------------------------------------------------------------------------+

* Operating systems

    +------------------------+------------+-----------------------------------+
    | Windows 2000 and older | *partial*  | Some Win32 APIs didn't exist yet. |
    +------------------------+------------+-----------------------------------+
    | Windows XP             | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows Vista          | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows 7              | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows Server 2003    | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows Server 2003 R2 | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows Server 2008    | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | Windows Server 2008 R2 | **full**   |                                   |
    +------------------------+------------+-----------------------------------+
    | ReactOS                | *untested* | Probably similar to Windows 2000. |
    +------------------------+------------+-----------------------------------+
    | Linux (using Wine 1.2) | *untested* | Reported to work on Ubuntu.       |
    +------------------------+------------+-----------------------------------+
    | Linux (using Wine 1.3) | *untested* | Reported to work on Ubuntu.       |
    +------------------------+------------+-----------------------------------+

* Architectures

    +----------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Intel x86 (32 bits) and compatible     |    **full**    |                                                                                                                                                                                        |
    +----------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Intel x86_x64 (64 bits) and compatible |    **full**    |                                                                                                                                                                                        |
    +----------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | ARM and compatible                     | *experimental* | Planned for WinAppDbg 1.6. See the next item about currently missing features.                                                                                                         |
    +----------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Other architectures                    | *experimental* | Platform specific features are missing, for example: disassembling, reading or writing to registers, setting code and hardware breakpoints, function hooks, accessing the PEB and TEB. |
    +----------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Known issues
------------

* Python strings default encoding is 'ascii' since Python 2.5. While I did my best to prevent encoding errors when manipulting binary data, I recommend setting the default to 'latin-1' (ISO 8859-1) instead. You can do this by adding a `sitecustomize.py <http://docs.python.org/faq/programming.html?highlight=sitecustomize#what-does-unicodeerror-ascii-decoding-encoding-error-ordinal-not-in-range-128-mean>`_ script to your Python installation.

* Debugging 32 bit processes from a 64 bit Python VM does not work very well. Debugging 64 bit processes from a 32 bit Python VM does not work at all. This is in part because the Win32 API makes it difficult, but there's also a design problem in WinAppDbg: most of the C struct definitions change from 32 to 64 bits and there's currently no support for having both definitions at the same time.

* Step-on-branch mode stopped working since Windows Vista. This is due to a change in the Windows kernel. The next version of WinAppDbg will support this.

* Setting hardware breakpoints in the main thread before the process has finished initializing does not work. This is not supported by the Windows itself, and is not a limitation of WinAppDbg. Future versions of WinAppDbg will try to detect this error and warn about it.

License
-------

This package is released under the `BSD license <http://en.wikipedia.org/wiki/BSD_license>`_, so as a user you are entitled to create derivative work and :ref:`redistribute <redistribution>` it if you wish. A makefile is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using `Epydoc <http://epydoc.sourceforge.net/>`_. The sources to this documentation are also provided and can be compiled with `Sphinx <http://sphinx.pocoo.org/>`_.
