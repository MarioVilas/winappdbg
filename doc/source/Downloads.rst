.. _download:

Downloading and installing
**************************

This is what you need to know to download, install and begin to use *WinAppDbg*:

Latest version
--------------

The latest version is **1.6**. The project's `download page <https://github.com/MarioVilas/winappdbg/releases/tag/winappdbg_v1.6>`_ has this version. You can also get the bleeding-edge version from the `Github repository <https://github.com/MarioVilas/winappdbg>`_.

.. _older:

Older versions
--------------

Older versions are still available for download as well at the old `Sourceforge site <http://winappdbg.sourceforge.net/dist/>`_.

+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.5** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.5.win32.msi>`_     |
| *(20 Dec 2013)* | * `64-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.5.win-amd64.msi>`_ |
|                 | * `Tutorial <http://winappdbg.sourceforge.net/dist/winappdbg-1.5-tutorial.pdf>`_          |
|                 | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-1.5-reference.pdf>`_    |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.5.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.4** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.4.win32.exe>`_     |
| *(10 Dec 2010)* | * `64-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.4.win-amd64.exe>`_ |
|                 | * `Tutorial <http://winappdbg.sourceforge.net/dist/winappdbg-tutorial-1.4.pdf>`_          |
|                 | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-reference-1.4.pdf>`_    |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.4.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.3** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.3.win32.exe>`_     |
| *(12 Feb 2010)* | * `64-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.3.win-amd64.exe>`_ |
|                 | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-1.3.pdf>`_              |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.3.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.2** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.2.win32.exe>`_     |
| *(16 Jun 2009)* | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-1.2.pdf>`_              |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.2.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.1** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.1.win32.exe>`_     |
| *(18 May 2009)* | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-1.1.pdf>`_              |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.1.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+
| Version **1.0** | * `32-bit installer <http://winappdbg.sourceforge.net/dist/winappdbg-1.0.win32.exe>`_     |
| *(22 Apr 2009)* | * `Documentation <http://winappdbg.sourceforge.net/dist/winappdbg-1.0.pdf>`_              |
|                 | * `Source code <http://winappdbg.sourceforge.net/dist/winappdbg-1.0.zip>`_                |
+-----------------+-------------------------------------------------------------------------------------------+

Dependencies
------------

Naturally you need the `Python interpreter <http://www.python.org/download/>`_. It's recommended to use Python 2.7. You'll have to install the 32 bit VM to debug 32 bit targets and the 64 bit VM for 64 bit targets. Both VMs can be installed on the same machine.

If you're still using Python 2.5 64-bit, you'll need to install `ctypes <http://python.net/crew/theller/ctypes/>`_ as well. This is needed to interface with the Win32 API, and *WinAppDbg* won't work without it. Newer versions of Python already have this module.

The following packages provide extra features and performance improvements, they are very recommended but not mandatory.

Disassembler
++++++++++++

*WinAppDbg* itself doesn't come with a disassembler, but all of the following are compatible. *WinAppDbg* will pick the most suitable one automatically when needed, but you can also decide which one to use.

* The `Capstone <http://capstone-engine.org/>`_ disassembler by Nguyen Anh Quynh.
* The `diStorm <hhttps://github.com/gdabah/distorm>`_ disassembler by Gil Dabah.
* The `BeaEngine <https://github.com/BeaEngine/beaengine>`_ disassembler by BeatriX.
* The `PyDasm <https://github.com/alexeevdv/libdasm>`_ Python bindings to libdasm.
* The `Libdisassemble <http://www.immunitysec.com/resources-freesoftware.shtml>`_ module from Immunity.

Database storage
++++++++++++++++

The `SQL Alchemy <http://www.sqlalchemy.org/>`_ ORM module gives *WinAppDbg* the ability to use a SQL database to store and find crash dumps. Most major database engines are supported.

Other goodies
+++++++++++++

Running WinAppDbg under Python interpreters other than CPython is considered experimental, but you may experience performance gains by using them. Also, in older versions of CPython, with the Python specializing compiler, `Psyco <http://psyco.sourceforge.net/>`_, *WinAppDbg* will experience a performance gain just by installing it, no additional steps are needed. You can download the sources and some old precompiled binaries from the `official site <http://psyco.sourceforge.net/download.html>`_ and newer but unofficial builds from `Voidspace <http://www.voidspace.org.uk/python/modules.shtml#psyco>`_.

Also `PyReadline <http://pypi.python.org/pypi/pyreadline>`_ is useful when using the console tools shipped with *WinAppDbg*, but they'll work without it. Basically what it does is provide autocomplete and history for console applications.

Install
-------

You can install directly from the **sources** package, extract it to any temporary folder and run the following command: ::

    install.bat

You can also install WinAppDbg (stable versions only) from the `Cheese Shop <http://pypi.python.org/pypi/winappdbg/>`_ using any of the compatible **package managers**:

* `PIP Installs Python <http://www.pip-installer.org/>`_ ::

    pip install winappdbg

* `PyPM <http://code.activestate.com/pypm/search%3Awinappdbg/>`_ (only when using `ActivePython <http://www.activestate.com/activepython>`_)

* Easy Install (formerly from `Setuptools <http://pypi.python.org/pypi/setuptools>`_, now from `Distribute <http://packages.python.org/distribute/>`_) ::

    easy_install winappdbg

* `Python Package Manager <http://sourceforge.net/projects/pythonpkgmgr/>`_ (it's a GUI installer)

Support
-------

Minimim requirements:

* **Windows XP**

* **Python 2.5**

Recommended platform:

* **Windows 7**

* **Python 2.7**

It might work, but was not tested, under *Windows 2000*, *Wine* and *ReactOS*, and some bugs and missing features are to be expected in these platforms (mainly due to missing APIs).

Python 3 support was experimental up to *WinAppDbg 1.4*, and was dropped with *WinAppDbg 1.5*. There are currently no plans to support Python 3 in the near future - backwards compatibility would be broken and plenty of code would need to be refactored just to port it.

While there are still some issues that need ironing out, it may be worth trying out faster Python interpreters such as `PyPy <https://bitbucket.org/pypy/pypy/downloads/>`_ and `IronPython <http://ironpython.net/download/>`_.

If you find a bug or have a feature suggestion, don't hesitate to  `open a new issue <https://github.com/MarioVilas/winappdbg/issues>`_. Both comments and complaints are welcome! :)

The following tables show which Python interpreters, operating systems and processor architectures are currently supported. **Full** means all features are fully functional. **Partial** means some features may be broken and/or untested. **Untested** means that though no testing was performed it should probably work. **Experimental** means it's not expected to work and although it might, you can encounter many bugs.

Python interpreters
+++++++++++++++++++

+--------------------------+-----------------+----------------------------------------------------------------+
| Version                  | Status          | Notes                                                          |
+==========================+=================+================================================================+
| CPython 2.4 and earlier  | *not supported* | Use an :ref:`older version <older>` of WinAppDbg in this case. |
+--------------------------+-----------------+----------------------------------------------------------------+
| CPython 2.5 through 2.7  |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| CPython 3.0 and newer    | *not supported* | Planned for WinAppDbg 2.0.                                     |
+--------------------------+-----------------+----------------------------------------------------------------+
| PyPy 1.4 and earlier     | *not supported* | It doesn't seem to be available for download any more...       |
+--------------------------+-----------------+----------------------------------------------------------------+
| PyPy 1.5 and 1.6         | *experimental*  | The sqlite3 dll is missing, after you fix that                 |
|                          |                 | it should be the same as newer versions.                       |
+--------------------------+-----------------+----------------------------------------------------------------+
| PyPy 1.7 and newer       | *experimental*  | Some compatibility issues need fixing.                         |
+--------------------------+-----------------+----------------------------------------------------------------+
| IronPython 2.0 and newer | *experimental*  | Some compatibility issues need fixing.                         |
+--------------------------+-----------------+----------------------------------------------------------------+
| Jython 2.5 and earlier   | *not supported* | Support for ctypes is                                          |
|                          |                 | `incomplete <http://bugs.jython.org/issue1328>`_               |
|                          |                 | in this platform.                                              |
+--------------------------+-----------------+----------------------------------------------------------------+

Operating systems
+++++++++++++++++

+--------------------------+-----------------+----------------------------------------------------------------+
| Version                  | Status          | Notes                                                          |
+==========================+=================+================================================================+
| Windows 2000 and older   | *not supported* | Some required Win32 API functions didn't exist yet.            |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows XP               |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Server 2003      |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Server 2003 R2   |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Vista            |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows 7                |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Server 2008      |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Server 2008 R2   |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows 8                |   *untested*    | Probably similar to Windows 7.                                 |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Server 2012      |   *untested*    | Probably similar to Windows Server 2008 R2.                    |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows 10               |   *untested*    | Probably similar to Windows 7.                                 |
+--------------------------+-----------------+----------------------------------------------------------------+
| ReactOS                  |   *untested*    | Probably similar to Windows 2000.                              |
+--------------------------+-----------------+----------------------------------------------------------------+
| Linux (using Wine 1.2)   |   *untested*    | Reported to work on Ubuntu.                                    |
+--------------------------+-----------------+----------------------------------------------------------------+
| Linux (using Wine 1.3)   |   *untested*    | Reported to work on Ubuntu.                                    |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows + Cygwin         |   *partial*     | Some features may be missing.                                  |
+--------------------------+-----------------+----------------------------------------------------------------+
| Windows Phone            | *not supported* | Planned for WinAppDbg 2.0.                                     |
+--------------------------+-----------------+----------------------------------------------------------------+

Architectures
+++++++++++++

+--------------------------+-----------------+----------------------------------------------------------------+
| Version                  | Status          | Notes                                                          |
+==========================+=================+================================================================+
| Intel (32 bits)          |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| Intel (64 bits)          |    **full**     |                                                                |
+--------------------------+-----------------+----------------------------------------------------------------+
| ARM                      | *not supported* | Planned for WinAppDbg 2.0.                                     |
+--------------------------+-----------------+----------------------------------------------------------------+

Known issues
------------

* Python strings default encoding is 'ascii' since Python 2.5. While I did my best to prevent encoding errors when manipulating binary data, I recommend setting the default to 'latin-1' (ISO 8859-1) instead. You can do this by adding a `sitecustomize.py <http://docs.python.org/faq/programming.html?highlight=sitecustomize#what-does-unicodeerror-ascii-decoding-encoding-error-ordinal-not-in-range-128-mean>`_ script to your Python installation.

* Step-on-branch mode stopped working since Windows Vista. This is due to a change in the Windows kernel. The next major version of WinAppDbg (2.0) will support this.

* Debugging 32 bit processes from a 64 bit Python VM does not work very well. Debugging 64 bit processes from a 32 bit Python VM does not work at all. This is in part because the Win32 API makes it difficult, but there's also a design problem in WinAppDbg: most of the C struct definitions change from 32 to 64 bits and there's currently no support for having both definitions at the same time. This will change with WinAppDbg 2.0 too.

* Setting hardware breakpoints in the main thread before the process has finished initializing does not work. This is not supported by the Windows API itself, and is not a limitation of WinAppDbg. Future versions of WinAppDbg will try to detect this error and warn about it.

License
-------

This software is released under the `BSD license <http://en.wikipedia.org/wiki/BSD_license>`_, so as a user you are entitled to create derivative work and :ref:`redistribute <redistribution>` it if you wish. A makefile is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using `Epydoc <http://epydoc.sourceforge.net/>`_. The sources to this documentation are also provided and can be compiled with `Sphinx <http://sphinx-doc.org/>`_.
