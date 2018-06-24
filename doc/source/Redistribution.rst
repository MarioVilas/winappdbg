.. _redistribution:

:orphan:

Building your own distribution packages
***************************************

*WinAppDbg* is released under the :download:`BSD license <_static/bsd.txt>`, so as a user you are entitled to create derivative work and redistribute it if you wish. A batch script is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using Epydoc and Sphinx.

Prerequisites
-------------

The distribution building requires Python 2.7 as a minimum version. It works both with 32 and 64 bits. Older versions of Python will fail. The 32 bits interpreter is expected to be installed at %SystemDrive%\Python27 and the 64 bits version at %SystemDrive%\Python27-x64. If both are found the 64 bits version is used.

This documentation was generated using `Sphinx <http://sphinx-doc.org/>`_. The reStructuredText sources are provided with the source code downloads only.

The `Epydoc <http://epydoc.sourceforge.net/>`_ package is required to autogenerate the reference documentation. `GraphViz <http://www.graphviz.org/>`_ is used by Epydoc to generate UML graphs for the documentation.

A Latex compiler is used to generate the documentation in PDF format. We're currently using `MikTex 2.7 <https://miktex.org/>`_ on Windows.

The HTML help can be compiled to a .CHM file using `Microsoft HTML Help Workshop <http://www.microsoft.com/en-us/download/details.aspx?id=21138>`_.

The Make utility is used to run makefiles, and the Tar, GZip and BZip2 utilities are required to compress .tar.gz and .tar.bz2 files. We're using `Cygwin <http://www.cygwin.com/>`_ because the packages from GnuWin32 suffer from really nasty bugs (most notably the Tar command tries to call fork() on Windows...).

All of these tools must be present in the **PATH** environment variable.

The `decorator <https://pypi.org/project/decorator>`_ module is also recommended since it integrates better than the built-in decorators with the autodoc tools we're using. You can install it with easy_install or download it from the `Python Package Index <https://pypi.org/project/decorator>`_.

    +------------------------------------------------------------------------------------------------+
    | `Download Sphinx             <https://pypi.org/project/Sphinx>`_                               |
    +------------------------------------------------------------------------------------------------+
    | `Download Pygments           <https://pypi.org/project/Pygments>`_                             |
    +------------------------------------------------------------------------------------------------+
    | `Download Epydoc             <https://sourceforge.net/projects/epydoc/files/>`_                |
    +------------------------------------------------------------------------------------------------+
    | `Download GraphViz           <http://www.graphviz.org/Download.php>`_                          |
    +------------------------------------------------------------------------------------------------+
    | `Download MikTex 2.7         <https://miktex.org/2.7/setup>`_                                  |
    +------------------------------------------------------------------------------------------------+
    | `Download HTML Help Workshop <http://www.microsoft.com/en-us/download/details.aspx?id=21138>`_ |
    +------------------------------------------------------------------------------------------------+
    | `Download Cygwin             <http://cygwin.com/>`_                                            |
    +------------------------------------------------------------------------------------------------+
    | `Download Decorator          <https://pypi.org/project/decorator>`_                            |
    +------------------------------------------------------------------------------------------------+

Installation
------------

Both the source code and Windows installer packages are generated with Distutils, which is already shipped with your Python distribution. The :download:`setup.py <../../setup.py>` file is the installer script that contains the package metadata and the list of files to include.

You can find more information on Distutils installer scripts `here <https://docs.python.org/2/distutils/setupscript.html>`_.

An install batch file (:download:`install.bat <../../install.bat>`) is provided for convenience when installing WinAppDbg in multiple versions of Python coexisting in the same machine.

Building the packages
---------------------

A batch file (:download:`distro.bat<../../distro.bat>`) is provided to build the packages. These are the commands it supports:

Building the project
++++++++++++++++++++

* **distro all**

  Generates the all documentation and builds all the packages.

* **distro clean**

  Removes all files and directories created by the other make commands.

Building each component
+++++++++++++++++++++++

* **distro source**

  Builds only the source code packages in *zip* and *tar.bz2* format.

* **distro wininst**

  Builds only the Windows installer packages (that is, the *exe* and *msi* files) for all supported platforms and architectures.

* **distro autodoc**

  Generates only the reference documentation using Epydoc.

* **distro manuals**

  Generates only the manuals using Sphinx.

Directory structure
-------------------

This is the directory structure expected for the makefile and the install script to work.

Input directories
+++++++++++++++++

* **/doc**

  This folder contains the reStructured text for the manuals. It's included **only** in the source distribution package.

* **/examples**

  This folder contains the example scripts shipped with WinAppDbg. They're the same examples found in the project wiki pages. It's included **only** in the source distribution package.

* **/tools**

  This folder contains the utility scripts shipped with WinAppDbg. It's included in both the source distribution package and the Windows installer.

* **/winappdbg**

  This folder contains the WinAppDbg source code itself. It's included in both the source distribution package and the Windows installer.

Output directories
++++++++++++++++++

* **/build**

  Temporary folder created when building the source distribution and Windows installer. You can safely delete this.

* **/dist**

  This is where the source distribution and the Windows installer files are stored.

* **/doc/build**

  This folder contains the compiled manuals in HTML and PDF formats.

* **/html**

  This is where the reference documentation files are stored, in HTML format. If you compile this documentation into a .CHM file it'll also be stored here.

* **/pdf**

  This is where the reference documentation files are stored, in PDF and PostScript format.
