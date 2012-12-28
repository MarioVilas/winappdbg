.. _more-examples:

More examples
*************

.. _time-to-debug:

Set a debugging timeout
+++++++++++++++++++++++

Sometimes you'll want to set a maximum time to debug your target, especially when fuzzing or analyzing malware. This is an example on how to code a custom debugging loop with a timeout. It launches the Windows Calculator and stops when the target process is closed or after a 5 seconds timeout.

:download:`Download <../../examples/miscellaneous/01_debug_timeout.py>`

.. literalinclude:: ../../examples/miscellaneous/01_debug_timeout.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _memory-dump:

Dump the memory of a process
++++++++++++++++++++++++++++

This is an example on how to dump the memory map and contents of a process into an SQLite database. A table is created where each row is a memory region, and the columns are the properties of that region (address, size, mapped filename, etc.) and it's data. The data is compressed using zlib to reduce the database size, but simply commenting out line 160 stores the data in uncompressed form.

:download:`Download <../../examples/miscellaneous/02_memory_dump.py>`

.. literalinclude:: ../../examples/miscellaneous/02_memory_dump.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _find-alnum:

Find alphanumeric addresses to jump to
++++++++++++++++++++++++++++++++++++++

This example will find all memory addresses in a target process that are executable and whose address consists of alphanumeric characters only. This is useful when exploiting a stack buffer overflow and the input string is limited to alphanumeric characters only.

Note that in 64 bit processors most memory addresses are not alphanumeric, so this example is meaningful for 32 bits only.

:download:`Download <../../examples/miscellaneous/03_find_alnum.py>`

.. literalinclude:: ../../examples/miscellaneous/03_find_alnum.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _enum-dep:

Show processes DEP settings
+++++++++++++++++++++++++++

Beginning with Windows XP SP3, it's possible to query a process and find out its Data Execution Prevention (DEP) settings. It may have DEP enabled or disabled, DEP-ATL thunking emulation enabled or disabled, and these settings may be changeable on runtime or permanent for the lifetime of the process.

This example shows all 32 bits processes the current user has permission to access and shows their DEP settings.

:download:`Download <../../examples/miscellaneous/04_dep.py>`

.. literalinclude:: ../../examples/miscellaneous/04_dep.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _disassembler:

Choose the disassembler you want to use
+++++++++++++++++++++++++++++++++++++++

WinAppDbg supports several disassembler engines. When more than one compatible engine is installed a default one is picked. However, you can manually select which one you want to use.

This example shows you how to list the supported disassembler engines for the desired architecture and pick one.

:download:`Download <../../examples/miscellaneous/05_disasm.py>`

.. literalinclude:: ../../examples/miscellaneous/05_disasm.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _atoms:

Enumerate all named global atoms
++++++++++++++++++++++++++++++++

Global atoms are WORD numeric values that can be associated to arbitrary strings. They are used primarily for IPC purposes on Windows XP (Vista and 7 don't seem to be using them anymore). This example shows how to retrieve the string from any atom value.

:download:`Download <../../examples/miscellaneous/06_atoms.py>`

.. literalinclude:: ../../examples/miscellaneous/06_atoms.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,
