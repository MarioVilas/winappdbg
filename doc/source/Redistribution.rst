.. _redistribution:

Building your own distribution packages
***************************************

*WinAppDbg* is released under the :download:`BSD license <../../../misc/license/bsd.txt>`, so as a user you are entitled to create derivative work and redistribute it if you wish. A makefile is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using Epydoc.

Prerequisites
-------------

A Make utility is required to use the makefile. Without it you're going to have to run each command manually to generate the documentation and packages. We're using GNU Make for Windows from the `GNU Win32 project <http://gnuwin32.sourceforge.net/>`_.

Tar and BZip2 utilities are required to compress .tar.bz2 files. We're also using the packages from the `GNU Win32 project <http://gnuwin32.sourceforge.net/>`_.

The `Epydoc <http://epydoc.sourceforge.net/>`_ package is required to autogenerate the documentation. [http://www.graphviz.org/ GraphViz] is used by Epydoc to generate UML graphs for the documentation.

This documentation was generated using `Sphinx <http://sphinx.pocoo.org/>`_. The reStructuredText sources are provided with the source code downloads only.

A Latex compiler is used to generate the documentation in PDF format. We're currently using `MikTex 2.7 <http://miktex.org/>`_ on Windows.

The HTML help can be compiled to a .CHM file using `Microsoft HTML Help Workshop <http://go.microsoft.com/fwlink/?LinkId=154968>`_.

The `py2exe <http://www.py2exe.org/>`_ package is used to generate standalone binaries for the tools. This step is optional. You can (also optionally) compress the executables with `UPX <http://upx.sourceforge.net/>`_.

All of these tools should be present in the **PATH** environment variable.

    +-------------------------------------------------------------------------------------+
    | `Download Make for Windows   <http://gnuwin32.sourceforge.net/packages/make.htm>`_  |
    +-------------------------------------------------------------------------------------+
    | `Download Tar for Windows    <http://gnuwin32.sourceforge.net/packages/gtar.htm>`_  |
    +-------------------------------------------------------------------------------------+
    | `Download BZip2 for Windows  <http://gnuwin32.sourceforge.net/packages/bzip2.htm>`_ |
    +-------------------------------------------------------------------------------------+
    | `Download Epydoc             <http://sourceforge.net/projects/epydoc/files/>`_      |
    +-------------------------------------------------------------------------------------+
    | `Download Sphinx             <http://pypi.python.org/pypi/Sphinx>`_                 |
    +-------------------------------------------------------------------------------------+
    | `Download GraphViz           <http://www.graphviz.org/Download.php>`_               |
    +-------------------------------------------------------------------------------------+
    | `Download MikTex 2.7         <http://miktex.org/2.7/setup>`_                        |
    +-------------------------------------------------------------------------------------+
    | `Download HTML Help Workshop <http://go.microsoft.com/fwlink/?LinkId=154968>`_      |
    +-------------------------------------------------------------------------------------+
    | `Download py2exe             <http://sourceforge.net/projects/py2exe/files/>`_      |
    +-------------------------------------------------------------------------------------+
    | `Download UPX                <http://upx.sourceforge.net/#download>`_               |
    +-------------------------------------------------------------------------------------+

Installation
------------

Both the source code and Windows installer packages are generated with the Distutils standard package, which is already shipped with your Python distribution. The :download:`setup.py <../../setup.py>` file is the installer script that contains the package metadata and the list of files to include.

You can find more information on Distutils installer scripts `here <http://docs.python.org/distutils/setupscript.html>`_.

An :download:`install batch file <../../install.bat>` is provided for convenience when installing WinAppDbg in multiple versions of Python coexisting in the same machine.

Building the packages
---------------------

A :download:`batch file <../../make>` is provided to build the packages. These are the commands it supports:

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

.. * **distro portable**
..
..   Builds only the portable packages in *zip* and *tar.bz2* format.

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

* **/examples**

  This folder contains the example scripts shipped with python-winappdbg. They're the same examples found in the project wiki pages. It's included **only** in the source distribution package.

* **/tools**

  This folder contains the utility scripts shipped with python-winappdbg. It's included in both the source distribution package and the Windows installer.

* **/winappdbg**

  This folder contains the winappdbg module files. It's included in both the source distribution package and the Windows installer.

Output directories
++++++++++++++++++

* **/build**

  Temporary folder created when building the source distribution and Windows installer. You can safely delete this.

* **/dist**

  This is where the source distribution and the Windows installer files are stored.

* **/html**

  This is where the autogenerated documentation files are stored, in HTML format. If you compile this documentation into a .CHM file it'll also be stored here.

* **/pdf**

  This is where the autogenerated documentation files are stored, in PDF and PostScript format.

