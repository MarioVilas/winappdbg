.. _redistribution:

Building your own distribution packages
***************************************

*WinAppDbg* is released under the :download:`BSD license <../../../misc/license/bsd.txt>`, so as a user you are entitled to create derivative work and redistribute it if you wish. A batch script is provided to automatically generate the source distribution package and the Windows installer, and can also generate the documentation for all the modules using Epydoc and Sphinx.

Prerequisites
-------------

This documentation was generated using `Sphinx <http://sphinx.pocoo.org/>`_. The reStructuredText sources are provided with the source code downloads only. To get the syntax highlighting to work on Sphinx you'll have to install the `Pygments <http://pygments.org/>`_ library too.

The `Epydoc <http://epydoc.sourceforge.net/>`_ package is required to autogenerate the reference documentation. [http://www.graphviz.org/ GraphViz] is used by Epydoc to generate UML graphs for the documentation.

A Latex compiler is used to generate the documentation in PDF format. We're currently using `MikTex 2.7 <http://miktex.org/>`_ on Windows.

The HTML help can be compiled to a .CHM file using `Microsoft HTML Help Workshop <http://go.microsoft.com/fwlink/?LinkId=154968>`_.

Tar and BZip2 utilities are required to compress .tar.bz2 files. We're using the packages from the `GNU Win32 project <http://gnuwin32.sourceforge.net/>`_.

All of these tools must be present in the **PATH** environment variable.

    +-------------------------------------------------------------------------------------+
    | `Download Sphinx             <http://pypi.python.org/pypi/Sphinx>`_                 |
    +-------------------------------------------------------------------------------------+
    | `Download Pygments           <http://pypi.python.org/pypi/Pygments>`_               |
    +-------------------------------------------------------------------------------------+
    | `Download Epydoc             <http://sourceforge.net/projects/epydoc/files/>`_      |
    +-------------------------------------------------------------------------------------+
    | `Download GraphViz           <http://www.graphviz.org/Download.php>`_               |
    +-------------------------------------------------------------------------------------+
    | `Download MikTex 2.7         <http://miktex.org/2.7/setup>`_                        |
    +-------------------------------------------------------------------------------------+
    | `Download HTML Help Workshop <http://go.microsoft.com/fwlink/?LinkId=154968>`_      |
    +-------------------------------------------------------------------------------------+
    | `Download Tar for Windows    <http://gnuwin32.sourceforge.net/packages/gtar.htm>`_  |
    +-------------------------------------------------------------------------------------+
    | `Download BZip2 for Windows  <http://gnuwin32.sourceforge.net/packages/bzip2.htm>`_ |
    +-------------------------------------------------------------------------------------+

Installation
------------

Both the source code and Windows installer packages are generated with the Distutils standard package, which is already shipped with your Python distribution. The :download:`setup.py <../../setup.py>` file is the installer script that contains the package metadata and the list of files to include.

You can find more information on Distutils installer scripts `here <http://docs.python.org/distutils/setupscript.html>`_.

An :download:`install batch file <../../install.bat>` is provided for convenience when installing WinAppDbg in multiple versions of Python coexisting in the same machine.

Building the packages
---------------------

A :download:`batch file <../../distro.bat>` is provided to build the packages. These are the commands it supports:

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
