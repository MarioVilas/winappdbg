.. _getting-started:

Getting started
***************

This is what you need to know to download, install and begin to use *WinAppDbg*:

Download
--------

The current version is **1.4**. You can choose **any** of the following files (if in doubt, pick the **first**):

Windows (32 bits)
+++++++++++++++++

* `winappdbg-1.4.win32.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32.exe/download>`_ - Standard installer
* `winappdbg-1.4.win32.msi <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32.msi/download>`_ - MSI installer

Windows (64 bits)
+++++++++++++++++

* `winappdbg-1.4.win-amd64.exe <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64.exe/download>`_ - Standard installer
* `winappdbg-1.4.win-amd64.msi <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64.msi/download>`_ - MSI installer

Source code
+++++++++++

* `winappdbg-1.4.zip     <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.zip/download>`_ - Manual install

Manuals
+++++++

The programming manuals can be consulted `online <http://winappdbg.sourceforge.net/doc/v1.4/reference/>`_, but they're also provided as CHM help files for download:

* `winappdbg-tutorial-1.4.chm  <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-tutorial-1.4.chm/download>`_ - Introduction and tutorials
* `winappdbg-reference-1.4.chm <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-reference-1.4.chm/download>`_ - Complete reference material

The Sourceforge project's `download page <http://sourceforge.net/projects/winappdbg/files/WinAppDbg/>`_ contains all versions. You can also get the bleeding-edge version as a source code tarball from the `subversion repository <http://winappdbg.svn.sourceforge.net/viewvc/winappdbg/trunk.tar.gz?view=tar>`_.

Install
-------

Simply run the Windows installer package and follow the wizard.

Alternatively, if you prefer using EasyInstall (`setuptools <http://pypi.python.org/pypi/setuptools>`_), type the following at the command prompt ::

    easy_install winappdbg

And *WinAppDbg* will be automatically downloaded and installed from the `PyPI repository <http://pypi.python.org/pypi/winappdbg/1.3>`_.

If you prefer to install directly from the sources package, extract it to any temporary folder and run the following command ::

    setup.py install

Dependencies
------------

Naturally you need the Python interpreter. There are two basic flavors, just pick your favorite:

* The **official** `Python <http://www.python.org/download/>`_ interpreter (free, open source). This is the preferred choice.

* ActiveState `ActivePython <http://www.activestate.com/store/activepython/download/>`_ (free, closed source). It should work but in 64 bit Windows the *ctypes* module is missing and you'll have to install it manually.

If you're still using Python 2.4 you'll need to install some additional modules:

* The `ctypes <http://python.net/crew/theller/ctypes/>`_ module is needed to interface with the Win32 API.

* The `SQLite python bindings <http://sourceforge.net/projects/pysqlite/>`_ can be used with the crash logger tool to store the crash information in an SQLite database file.

The `diStorm <http://code.google.com/p/distorm/>` disassembler is also required. You can download the `official <http://code.google.com/p/distorm/downloads/detail?name=distorm.zip&can=2&q=>`_ Python wrappers (32 bits only, manual install) or our own `installers <http://winappdbg.sourceforge.net/distorm3/>`_. Bear in mind that the official build is more likely to stay up to date.

.. note::

    If you don't install diStorm, all classes and methods of the debugger not related to dissassembling will still work correctly.

Optional packages
+++++++++++++++++

The following packages provide extra features and performance improvements, but they're not required to use *WinAppDbg*:

* The `PyODBC <http://code.google.com/p/pyodbc/>`_ module gives the crash logger tool the ability to connect to MSSQL databases.

* The Python specializing compiler, `Psyco <http://psyco.sourceforge.net/>`_. *WinAppDbg* will experience a performance gain just by installing it, no additional steps are needed. You can download it from `here <http://psyco.sourceforge.net/download.html>`_.

* `PyReadline <http://ipython.scipy.org/moin/PyReadline/Intro>`_ is useful when using the console tools shipped with *WinAppDbg*, but they'll work without it. Basically what it does is provide autocomplete and history for console applications.

* The `py2exe <http://www.py2exe.org/>`_ package. You can use it to generate standalone binaries for any tools made with *WinAppDbg*. See the instructions on how to use the :ref:`Makefile <redistribution>`.

Support
-------

This package has been tested under **Windows XP** and above (both 32 and 64 bits) using **Python 2.6**. It was loosely tested under *Windows 2000*, *Wine* and *ReactOS*, and some bugs are to be expected in these platforms (mainly due to missing APIs).

If you find a bug or have a feature suggestion, don't hesitate to send an email to the [https://lists.sourceforge.net/lists/listinfo/winappdbg-users winappdbg-users] mailing list. Both comments and complaints are welcome! :)

The following tables show which Python interpreters, operating systems and processor architectures are currently supported. **Full** means all features are fully functional. **Partial** means some features may be broken and/or untested. **Experimental** means there is a subversion branch with at least partial support, but hasn't been merged to trunk yet. **Untested** means that though no testing was performed it should probably work.

* Python interpreters

    +------------+----------------+----------------------------------------------------------------------------------------------+
    | Python 2.4 | **full**       |                                                                                              |
    +------------+----------------+----------------------------------------------------------------------------------------------+
    | Python 2.5 | **full**       |                                                                                              |
    +------------+----------------+----------------------------------------------------------------------------------------------+
    | Python 2.6 | **full**       |                                                                                              |
    +------------+----------------+----------------------------------------------------------------------------------------------+
    | Python 2.7 | **full**       |                                                                                              |
    +------------+----------------+----------------------------------------------------------------------------------------------+
    | Python 3.x | *experimental* | (see `this branch <http://winappdbg.svn.sourceforge.net/viewvc/winappdbg/branches/compat>`_) |
    +------------+----------------+----------------------------------------------------------------------------------------------+

* Operating systems

    +------------------------+------------+------------------------------------+
    | Windows XP             | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows Vista          | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows 7              | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows Server 2003    | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows Server 2003 R2 | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows Server 2008    | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows Server 2008 R2 | **full**   |                                    |
    +------------------------+------------+------------------------------------+
    | Windows 2000 and older | *partial*  | (some Win32 APIs didn't exist yet) |
    +------------------------+------------+------------------------------------+
    | ReactOS                | *untested* | (probably similar to Windows 2000) |
    +------------------------+------------+------------------------------------+
    | Linux (using Wine 1.2) | *untested* | (reported to work on Ubuntu)       |
    +------------------------+------------+------------------------------------+
    | Linux (using Wine 1.3) | *untested* | (reported to work on Ubuntu)       |
    +------------------------+------------+------------------------------------+

* Architectures

    +----------------------------------------+----------------+-----------------------------------------------------------+
    | Intel x86 (32 bits) and compatible     | **full**       |                                                           |
    +----------------------------------------+----------------+-----------------------------------------------------------+
    | Intel x86_x64 (64 bits) and compatible | *partial*      | (function hooks are not yet implemented)                      |
    +----------------------------------------+----------------+-----------------------------------------------------------+
    | Intel IA64 (Itanium)                   | *experimental* | (no actual Itanium system to test it on, help is needed!) |
    +----------------------------------------+----------------+-----------------------------------------------------------+

License
-------

This package is released under the `BSD license <http://en.wikipedia.org/wiki/BSD_license>`_, so as a user you are entitled to create derivative work and :ref:`redistribute <redistribution>` it if you wish. A makefile is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using `Epydoc <http://epydoc.sourceforge.net/>`_. The sources to this documentation are also provided and can be compiled with `Sphinx <http://sphinx.pocoo.org/>`_.

