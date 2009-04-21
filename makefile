# $Id$

# The following packages need to be installed and present in the PATH environment variable:
#   Python (d'oh!)
#   Make (try gnuwin32, cygwin's make doesn't seem to work well for me, but your mileage may vary)
#   Tar and BZip2 (to compress the source packages to tar.bz2 format, also downloadable at gnuwin32)
#   Epydoc and GraphViz (to generate the docs)
#   MikTex (or an equivalent Latex package for Windows, to generate pdfs)
#   py2exe to build the tools into Windows executable files


# Epydoc command line options
# don't use --fail-on-docstring-warning until all warnings are removed
EPYDOC_OPT=--verbose --simple-term --docformat epytext --name "Windows application debugging engine" --url "http://sourceforge.net/projects/winappdbg/" winappdbg
EPYDOC_HTML_OPT=--html --include-log --show-frames --css default
EPYDOC_PDF_OPT=--pdf --separate-classes
EPYDOC_TEST_OPT=--check
EPYDOC_OUTPUT_OPT=--show-private --no-sourcecode --no-imports --inheritance=included --graph all

# Source package options
SDIST_OPT=--formats=zip,bztar

# Windows installer package options
# (uncomment only for Python 2.6 to generate Vista-compatible installers)
BDIST_UAC=
#BDIST_UAC=--user-access-control auto


# Build everything
all: doc dist

# Generate the documentation
docs: doc
doc: html pdf

# Build the packages
dist: sdist bdist


# Install the module
install:
	python setup.py install


# Build the tools
py2exe:
	python setup.py py2exe



# Test the documentation
#doctest:
#	epydoc $(EPYDOC_TEST_OPT) $(EPYDOC_OUTPUT_OPT) $(EPYDOC_OPT)


# Generate the HTML documentation only
html:
	epydoc $(EPYDOC_HTML_OPT) $(EPYDOC_OUTPUT_OPT) $(EPYDOC_OPT)

# Generate the PDF documentation only
pdf:
	epydoc $(EPYDOC_PDF_OPT) $(EPYDOC_OUTPUT_OPT) $(EPYDOC_OPT)


# Build the source distribution package
sdist:
	python setup.py sdist $(SDIST_OPT)

# Build the Windows installer package
bdist:
	python setup.py bdist_wininst $(BDIST_UAC)


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
