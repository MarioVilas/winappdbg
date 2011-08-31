# $Id$

###############################################################################
#                                                                             #
#                          For more information see:                          #
#      http://sourceforge.net/apps/trac/winappdbg/wiki/Redistribution         #
#                                                                             #
###############################################################################


# The following packages should be installed and present in the PATH environment variable:
#   Python 2.7 (older versions won't do because of distutils)
#   Make (try gnuwin32, cygwin's make doesn't seem to work well for me, but your mileage may vary)
#   Tar and BZip2 (to compress the source packages to tar.bz2 format, also downloadable at gnuwin32)
#   Epydoc and GraphViz (to generate the docs)
#   Microsoft HTML Help Compiler to generate CHM help files
#   MikTex (or an equivalent Latex package for Windows, to generate pdfs)


# Location of the Python interpreter
PYTHON_CMD=c:/python27/python.exe

# Epydoc command line options
EPYDOC_CMD=$(PYTHON_CMD) c:/python27/scripts/epydoc.py
EPYDOC_OPT=--verbose --fail-on-docstring-warning --simple-term --docformat epytext --name "WinAppDbg - Programming Reference" --url "http://sourceforge.net/projects/winappdbg/" winappdbg
EPYDOC_HTML_OPT=--html --include-log --show-frames --css default
EPYDOC_PDF_OPT=--pdf --separate-classes
EPYDOC_TEST_OPT=--check
EPYDOC_OUTPUT_OPT=--show-private --no-imports --inheritance=included
EPYDOC_GRAPH_OPT=--graph all

# note to self: use --no-sourcecode to generate smaller documentation pages

# Source package options
SDIST_OPT=--formats=zip,bztar

# Windows installer package options
# (the UAC setting is only supported by Python 2.6 and above,
# use it to generate installers compatible with Windows Vista)
#BDIST_UAC=
BDIST_UAC=--user-access-control auto


# Build everything
all: clean doc dist

# Generate the documentation
docs: doc
doc: html pdf sphinx
sphinx: sphinx_html sphinx_chm sphinx_pdf

# Build the packages
dist: sdist bdist


# Install the module
install:
	$(PYTHON_CMD) setup.py install


# Generate the HTML documentation only
html:
	$(EPYDOC_CMD) $(EPYDOC_HTML_OPT) $(EPYDOC_OUTPUT_OPT) $(EPYDOC_OPT)

# Compile the HTML documentation into a CHM file
chm: html
	hhc winappdbg.hhp

# Generate the PDF documentation only
pdf:
	$(EPYDOC_CMD) $(EPYDOC_PDF_OPT) $(EPYDOC_OUTPUT_OPT) $(EPYDOC_OPT)

# Generate the HTML manual only
sphinx_html:
	cd doc
	make html
	cd ..

# Generate the CHM manual only
sphinx_chm:
	cd doc
	make htmlhelp
	cd build
	cd htmlhelp
	hhc WinAppDbg.hhp
	cd ..
	cd ..
	cd ..

# Generate the PDF manual only
sphinx_pdf:
	cd doc
	make latex
	cd build
	cd latex
	make
	cd ..
	cd ..
	cd ..


# Build the source distribution package
sdist:
	$(PYTHON_CMD) setup.py sdist $(SDIST_OPT)

# Build the Windows installer package
bdist: wininst msi

# Build the Windows installer package
wininst:
	$(PYTHON_CMD) setup.py bdist_wininst $(BDIST_UAC)

# Build the Windows MSI installer package
msi:
	$(PYTHON_CMD) setup.py bdist_msi --target-version=2.4
	$(PYTHON_CMD) setup.py bdist_msi --target-version=2.5
	$(PYTHON_CMD) setup.py bdist_msi --target-version=2.6
	$(PYTHON_CMD) setup.py bdist_msi --target-version=2.7


# Clean up
clean:
	python setup.py clean
	if exist build del /s /q build
	if exist html del /s /q html
	if exist pdf del /s /q pdf
	if exist dist del /s /q dist
	if exist build rmdir /s /q build
	if exist html rmdir /s /q html
	if exist pdf rmdir /s /q pdf
	if exist dist rmdir /s /q dist
	if exist MANIFEST del MANIFEST
