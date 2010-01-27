.. _more-examples:

More examples
*************

.. _memory-dump-example:

Dump the memory of a process
++++++++++++++++++++++++++++

This is an example on how to dump the memory map and contents of a process into an SQLite database. A table is created where each row is a memory region, and the columns are the properties of that region (address, size, mapped filename, etc.) and it's data. The data is compressed using zlib to reduce the database size, but simply commenting out line 160 stores the data in uncompressed form.

:download:`Download <../../examples/miscellaneous/memory_dump_example.py>`

.. literalinclude:: ../../examples/miscellaneous/memory_dump_example.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

.. _time-to-debug:

Set a debugging timeout
+++++++++++++++++++++++

Sometimes you'll want to set a maximum time to debug your target, especially when fuzzing. This is an example on how to code a custom debugging loop with a timeout. It launches the Windows Calculator and stops when the target process is closed or after a 5 seconds timeout.

:download:`Download <../../examples/miscellaneous/time-to-debug.py>`

.. literalinclude:: ../../examples/miscellaneous/time-to-debug.py
   :start-after: # $Id
   :end-before: # When invoked from the command line,

