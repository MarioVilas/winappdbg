.. _win32-api-wrappers:

The Win32 API wrappers
**********************

The :mod:`win32` submodule provides a collection of useful API wrappers for most operations needed by a debugger. This will allow you to perform any task that the abstraction layer for some reason can't deal with, or won't deal with in the way you need. In most cases you won't need to resort to this, but it's important to know it's there.

Except in some rare cases, the rationale to port the API calls to Python was:

 * Take Python basic types as input, return Python basic types as output.
 * Functions that in C take an output pointer and a size as input, in Python take neither and return the output data directly (the wrapper takes care of allocating the memory buffers).
 * Functions that in C have to be called twice (first to get the buffer size, then to get the data) in Python only have to be called once (returns the data directly).
 * Functions in C with more than one output pointer return tuples of data in Python.
 * Functions in C that return an error condition, raise a Python exception (*WindowsError*) on error and return the data on success.
 * Default parameter values were added when possible. The default for all optional pointers is *NULL*. The default flags are usually the ones that provide all possible access (for example, the default flags value for *GetThreadContext* is *CONTEXT_ALL*)
 * For APIs with ANSI and Widechar versions, both versions are wrapped. If at least one parameter is a Unicode string en Widechar version is called (and all string parameters are converted to Unicode), otherwise the ANSI version is called. Either ANSI or Widechar versions can be used explicitly (for example, *CreateFile* can be called as *CreateFileA* or *CreateFileW*).

All handles returned by API calls are wrapped around the *Handle* class. This allows you to use the **with** statement to ensure proper cleanup, and causes handles to be closed automatically when they go out of scope, thus preventing handle leaks.

Example #1: finding a DLL in the search path
++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/win32_api_wrappers/01_search_path.py>`

.. literalinclude:: ../../examples/win32_api_wrappers/01_search_path.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #2: killing a process by attaching to it
++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/win32_api_wrappers/02_kill.py>`

.. literalinclude:: ../../examples/win32_api_wrappers/02_kill.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #3: enumerating heap blocks using the Toolhelp library
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/win32_api_wrappers/03_heap_walking.py>`

.. literalinclude:: ../../examples/win32_api_wrappers/03_heap_walking.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #4: enumerating modules using the Toolhelp library
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/win32_api_wrappers/04_show_dlls.py>`

.. literalinclude:: ../../examples/win32_api_wrappers/04_show_dlls.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,

Example #5: enumerating device drivers
++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/win32_api_wrappers/05_show_drivers.py>`

.. literalinclude:: ../../examples/win32_api_wrappers/05_show_drivers.py
   :start-after: # POSSIBILITY OF SUCH DAMAGE.
   :end-before: # When invoked from the command line,
