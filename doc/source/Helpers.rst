.. _helper-classes-and-functions:

Helper classes and functions
****************************

**WinAppDbg** provides some helper classes and functions, mostly related to input and output, that can come in handy when reading input from users or writing debugging data.

Console output with colors
--------------------------

The functions from the **Color** static class allow your scripts to write colored text to the console.

Tipically you'll make a call to the **can_use_colors** function to determine if it's possible to write text with colors. This is necessary because color output only works with a real console - if the user has redirected the output to a file or a pipe, trying to use colors will cause an exception to be raised.

The following functions set the console text color:

 * **black**
 * **white**
 * **red**
 * **green**
 * **blue**
 * **cyan**
 * **magenta**
 * **yellow**

You can also combine the colors with the brightness settings using the **light** and **dark** functions, to get more variations on colors:

.. code-block:: python

   Color.red()
   Color.light()
   print "This is printed in light red."
   Color.dark()
   print "This is printed in dark red."
   Color.blue()
   print "This is printed in dark blue."
   Color.light()
   print "This is printed in light blue."

The following functions set the console background color:

 * **bk_black**
 * **bk_white**
 * **bk_red**
 * **bk_green**
 * **bk_blue**
 * **bk_cyan**
 * **bk_magenta**
 * **bk_yellow**

The matching **bk_light** and **bk_dark** functions control the brightness of the background, and they work just like *light* and *dark*.

If you want to go back to the default text color, just call the **default** function. There's also a **bk_default** function for the background color, and a *reset* method that reverts to the default for both at the same time.

Example #1: printing text with colors
+++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/helpers/01_colors.py>`

.. literalinclude:: ../../examples/helpers/01_colors.py
   :start-after: $Id

Text output in tables
---------------------

The **Table** class lets you build text tables. Each row is added using the **addRow** method, and the number of columns is automatically inferred. Text justification for each column is defined using the **justify** method.

The **show** method prints the output. If you prefer to get the text table in a string, you can call the **getOutput** method instead. Also, the **getWidth** method tells you the width in characters of the whole table, so you know if it fits in the screen before printing it.

Example #2: printing a text table
+++++++++++++++++++++++++++++++++

:download:`Download <../../examples/helpers/02_table.py>`

.. literalinclude:: ../../examples/helpers/02_table.py
   :start-after: $Id

Logging
-------

The **Logger** class implements a simple text logger that can send its output to standard output and/or to a file. There are many libraries in Python that can do this, but this one has the advantage of being integrated with *WinAppDbg* objects.

If you want to integrate other logging facilities to your scripts you can also use the functions from the static class **DebugLog**, which contains all the WinAppDbg-related implementation of *Logger*.

Example #3: logging debug events
++++++++++++++++++++++++++++++++

:download:`Download <../../examples/helpers/03_debug_log.py>`

.. literalinclude:: ../../examples/helpers/03_debug_log.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Hexadecimal input
-----------------

The static class **HexInput** contains a collection of functions to parse input data in various formats.

.. only:: html

    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Function              | Description                                                                                                                                                                           |
    +=======================+=======================================================================================================================================================================================+
    | *integer*             | Convert a string to an integer. Supports decimal, hexadecimal (0x prefix), octal (0o prefix) and binary (0b prefix).                                                                  |
    |                       | If no prefix is given, this method still does its best to tell if it's hexadecimal or not. If all fails, the number is assumed to be decimal.                                         |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *address*             | Read an hexadecimal value from a string. Unlike *integer* no attempt is made to detect other formats.                                                                                 |
    |                       | This function was conceived for parsing memory addresses, hence the name.                                                                                                             |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *hexadecimal*         | Convert a strip of hexadecimal numbers (like OllyDbg's memory view) into binary data.                                                                                                 |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *pattern*             | Similar to *hexadecimal*, but it also accepts question marks as wildcards for unknown values in fixed positions.                                                                      |
    |                       | The return value is a regular expression that can perform a search for the given byte pattern.                                                                                        |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *is_pattern*          | Determine if the given argument is a valid hexadecimal pattern to be used with *pattern*.                                                                                             |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *integer_list_file*   | Read a list of integers from a file, assuming a specific file format.                                                                                                                 |
    |                       | Check the documentation for `HexInput.integer_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#integer_list_file>`_ for details. |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *string_list_file*    | Read a list of strings from a file, assuming a specific file format.                                                                                                                  |
    |                       | Check the documentation for `HexInput.string_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#string_list_file>`_ for details.   |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | *mixed_list_file*     | Read a list of integers and strings from a file, assuming a specific file format.                                                                                                     |
    |                       | Check the documentation for `HexInput.mixed_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#mixed_list_file>`_ for details.     |
    +-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **integer**:
        Convert a string to an integer. Supports decimal, hexadecimal (0x prefix), octal (0o prefix) and binary (0b prefix).

        If no prefix is given, this method still does its best to tell if it's hexadecimal or not. If all fails, the number is assumed to be decimal.

     * **address**:
        Read an hexadecimal value from a string. Unlike *integer* no attempt is made to detect other formats. This function was conceived for parsing memory addresses, hence the name.

     * **hexadecimal**:
        Convert a strip of hexadecimal numbers (like OllyDbg's memory view) into binary data.

     * **pattern**:
        Similar to *hexadecimal*, but it also accepts question marks as wildcards for unknown values in fixed positions. The return value is a regular expression that can perform a search for the given byte pattern.

     * **is_pattern**:
        Determine if the given argument is a valid hexadecimal pattern to be used with *pattern*.

     * **integer_list_file**:
        Read a list of integers from a file, assuming a specific file format.

        Check the documentation for `HexInput.integer_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#integer_list_file>`_ for details.

     * **string_list_file**:
        Read a list of strings from a file, assuming a specific file format.

        Check the documentation for `HexInput.string_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#string_list_file>`_ for details.

     * **mixed_list_file**:
        Read a list of integers and strings from a file, assuming a specific file format.

        Check the documentation for `HexInput.mixed_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexInput-class.html#mixed_list_file>`_ for details.

Hexadecimal output
------------------

Two static classes contain all the functions related to hexadecimal output: **HexOutput** and **HexDump**. The first matches the input functions from *HexInput*, while the second is meant for showing data to the user rather than being parsed by a script.

The following functions are common to both:

.. only:: html

    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | Function              | Description                                                                                               |
    +=======================+===========================================================================================================+
    | **integer**           | Numeric value output, in decimal format.                                                                  |
    |                       | The default size depends on the current architecture, but you can override it using the *bits* parameter. |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **address**           | Memory address output, in hexadecimal format.                                                             |
    |                       | The default size depends on the current architecture, but you can override it using the *bits* parameter. |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexadecimal**       | Output binary data as a strip of hexadecimal numbers (like OllyDbg's memory view).                        |
    |                       | Currently both implementations are identical.                                                             |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **integer**:
        Numeric value output, in decimal format.

        The default size depends on the current architecture, but you can override it using the *bits* parameter.

     * **address**:
        Memory address output, in hexadecimal format.

        The default size depends on the current architecture, but you can override it using the *bits* parameter.

     * **hexadecimal**:
        Output binary data as a strip of hexadecimal numbers (like OllyDbg's memory view).

        Currently both implementations are identical.

The *HexOutput* class also has file output functions to match those in *HexInput*:

.. only:: html

    +-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Function              | Description                                                                                                                                                                               |
    +=======================+===========================================================================================================================================================================================+
    | **integer_list_file** | Write a list of integers into a file, assuming a specific file format.                                                                                                                    |
    |                       | Check the documentation for `HexOutput.integer_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#integer_list_file>`_ for details.   |
    +-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **string_list_file**  | Write a list of strings into a file, assuming a specific file format.                                                                                                                     |
    |                       | Check the documentation for `HexOutput.string_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#string_list_file>`_ for details.     |
    +-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **mixed_list_file**   | Write a list of integers and strings into a file, assuming a specific file format.                                                                                                        |
    |                       | Check the documentation for `HexOutput.mixed_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#mixed_list_file>`_ for details.       |
    +-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **integer_list_file**:
        Write a list of integers into a file, assuming a specific file format.

        Check the documentation for `HexOutput.integer_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#integer_list_file>`_ for details.

     * **string_list_file**:
        Write a list of strings into a file, assuming a specific file format.

        Check the documentation for `HexOutput.string_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#string_list_file>`_ for details.

     * **mixed_list_file**:
        Write a list of integers and strings into a file, assuming a specific file format.

        Check the documentation for `HexOutput.mixed_list_file <http://winappdbg.sourceforge.net/doc/latest/reference/winappdbg.textio.HexOutput-class.html#mixed_list_file>`_ for details.

The *HexDump* class has additional methods for showing hex dumps and binary data to the user in a printable manner:

.. only:: html

    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | Function              | Description                                                                                               |
    +=======================+===========================================================================================================+
    | **hexblock**          | Dump a block of hexadecimal numbers from binary data. Also show a printable text version of the data.     |
    |                       | The output mimics that of the WinDBG debugger.                                                            |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexline**           | Dump a line of hexadecimal numbers from binary data.                                                      |
    |                       | This is useful for printing bytes in a console one line at a time.                                        |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexa_word**         | Convert binary data to a string of hexadecimal WORDs.                                                     |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexa_dword**        | Convert binary data to a string of hexadecimal DWORDs.                                                    |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexa_qword**        | Convert binary data to a string of hexadecimal QWORDs.                                                    |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexblock_byte**     | Dump a block of hexadecimal BYTEs from binary data.                                                       |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexblock_word**     | Dump a block of hexadecimal WORDs from binary data.                                                       |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexblock_dword**    | Dump a block of hexadecimal DWORDs from binary data.                                                      |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexblock_qword**    | Dump a block of hexadecimal QWORDs from binary data.                                                      |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+
    | **hexblock_cb**       | Dump a block of binary data using a callback function to convert each line of text.                       |
    |                       | This allows you to customize the output.                                                                  |
    +-----------------------+-----------------------------------------------------------------------------------------------------------+

.. only:: latex

     * **hexblock**:
        Dump a block of hexadecimal numbers from binary data. Also show a printable text version of the data. The output mimics that of the WinDBG debugger.

     * **hexline**:
        Dump a line of hexadecimal numbers from binary data. This is useful for printing bytes in a console one line at a time.

     * **hexa_word**:
        Convert binary data to a string of hexadecimal WORDs.

     * **hexa_dword**:
        Convert binary data to a string of hexadecimal DWORDs.

     * **hexa_qword**:
        Convert binary data to a string of hexadecimal QWORDs.

     * **hexblock_byte**:
        Dump a block of hexadecimal BYTEs from binary data.

     * **hexblock_word**:
        Dump a block of hexadecimal WORDs from binary data.

     * **hexblock_dword**:
        Dump a block of hexadecimal DWORDs from binary data.

     * **hexblock_qword**:
        Dump a block of hexadecimal QWORDs from binary data.

     * **hexblock_cb**:
        Dump a block of binary data using a callback function to convert each line of text. This allows you to customize the output.

Dumping code, stack and registers
---------------------------------

The **CrashDump** static class has functions tipically used from the event handlers to show debug data like the disassembler output, the register contents or the stack trace. Crash dump objects use this class for text output, and pretty many examples in the :ref:`Debugging <Debugging>` section of the tutorial use functions from here too.

All functions return a string with the text to print. Here are the most commonly used ones:

.. only:: html

    +-----------------------------------+----------------------------------------------------------------------------+
    | Function                          | Description                                                                |
    +===================================+============================================================================+
    | **dump_code**                     | Dump a disassembly. Optionally mark where the program counter is.          |
    +-----------------------------------+----------------------------------------------------------------------------+
    | **dump_registers**                | Dump the x86 processor register values.                                    |
    |                                   | The output mimics that of the WinDBG debugger.                             |
    +-----------------------------------+----------------------------------------------------------------------------+
    | **dump_stack_trace**              | Dump a stack trace using only memory addresses.                            |
    +-----------------------------------+----------------------------------------------------------------------------+
    | **dump_stack_trace_with_labels**  | Dump a stack trace using labels instead of memory addresses when possible. |
    +-----------------------------------+----------------------------------------------------------------------------+

.. only:: latex

    **dump_code**
        Dump a disassembly. Optionally mark where the program counter is.

    **dump_registers**
        Dump the x86 processor register values. The output mimics that of the WinDBG debugger.

    **dump_stack_trace**
        Dump a stack trace using only memory addresses.

    **dump_stack_trace_with_labels**
        Dump a stack trace using labels instead of memory addresses when possible.

Example #4: dumping code, stack and registers
+++++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/helpers/04_dump.py>`

.. literalinclude:: ../../examples/helpers/04_dump.py
   :start-after: $Id
   :end-before: # When invoked from the command line,

Pathname and filename handling
------------------------------

The **PathOperations** static class provides functions to manipulate pathnames and filenames. It's somewhat similar to the standard *os.path* module - except that it works by using only the Win32 API instead of manually parsing the filenames, which provides better compatibility with Windows (UNC path support, for example).

.. only:: html

    +-------------------------------+------------------------------------------------------+
    | Function                      | Description                                          |
    +===============================+======================================================+
    | **path_is_relative**          | Returns *True* if the path is relative.              |
    +-------------------------------+------------------------------------------------------+
    | **path_is_absolute**          | Returns *True* if the path is absolute.              |
    +-------------------------------+------------------------------------------------------+
    | **make_relative**             | Converts an absolute to a relative path.             |
    +-------------------------------+------------------------------------------------------+
    | **make_absolute**             | Converts a relative to an absolute path.             |
    +-------------------------------+------------------------------------------------------+
    | **split_filename**            | Split the file from the directory where it resides.  |
    +-------------------------------+------------------------------------------------------+
    | **split_extension**           | Split the file name from the file extension.         |
    +-------------------------------+------------------------------------------------------+
    | **split_path**                | Split each component of a path.                      |
    +-------------------------------+------------------------------------------------------+
    | **join_path**                 | Join back the components of a path.                  |
    +-------------------------------+------------------------------------------------------+
    | **native_to_win32_pathname**  | Converts an NT Native path to a standard Win32 path. |
    +-------------------------------+------------------------------------------------------+

.. only:: latex

     * **path_is_relative**:
        Returns True if the path is relative.

     * **path_is_absolute**:
        Returns True if the path is absolute.

     * **make_relative**:
        Converts an absolute to a relative path.

     * **make_absolute**:
        Converts a relative to an absolute path.

     * **split_filename**:
        Split the file from the directory where it resides.

     * **split_extension**:
        Split the file name from the file extension.

     * **split_path**:
        Split each component of a path.

     * **join_path**:
        Join back the components of a path.

     * **native_to_win32_pathname**:
        Converts an NT Native path to a standard Win32 path.

Example #5: pathname and filename handling
++++++++++++++++++++++++++++++++++++++++++

:download:`Download <../../examples/helpers/05_path.py>`

.. literalinclude:: ../../examples/helpers/05_path.py
   :start-after: $Id
   :end-before: # When invoked from the command line,
