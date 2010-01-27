.. _how-labels-work:

A closer look at how labels work
********************************

Labels are an approximated way of referencing memory locations across different executions of the same process, or different processes
with common modules. They are not meant to be perfectly unique, and some errors may occur when multiple modules with the same name are loaded, or when module filenames can't be retrieved.

The following examples assume there is a running process called *"calc.exe"* and the current user has enough privileges to debug it. The resolved addresses may vary in your system.

Labels syntax
-------------

This is the syntax of labels:

.. figure:: _static/labels-syntax.png
   :align:  left

Where all components are optional and blank spaces are ignored.

 * The **module** is a module name as returned by *Module.get_name()*.
 * The **function** is a string with an exported function name.
 * The **ordinal** is an integer with an exported function ordinal.
 * The **offset** is an integer number. It may be an offset from the module base address, or the function address. If not specified, the default is *0*.

If debugging symbols are available, they are used automatically in addition to exported functions.

Integer numbers in labels may be expressed in any format supported by HexInput.integer(), but by default they are in hexadecimal format (for example *0x1234*).

If only the **module** or the **function** are specified, but not both, the exclamation mark (**!**) may be omitted in fuzzy mode (explained later in this document). However, resolving the label may be a little slower, as all module names have to be checked to resolve the ambiguity.

Generating labels
-----------------

To create a new label, use the **parse_label** static method of the **Process** class:

>>> import winappdbg
>>> winappdbg.Process.parse_label()                                 # no arguments
'0x0'
>>> winappdbg.Process.parse_label(None, None, None)                 # empty label
'0x0'
>>> winappdbg.Process.parse_label(None, None, 512)                  # offset or address
'0x200'
>>> winappdbg.Process.parse_label("kernel32")                       # module base
'kernel32!'
>>> winappdbg.Process.parse_label("kernel32", "CreateFileA")        # exported function...
'kernel32!CreateFileA'
>>> winappdbg.Process.parse_label("kernel32", 16)                   # ...by ordinal
'kernel32!#0x10'
>>> winappdbg.Process.parse_label("kernel32", None, 512)            # module base + offset
'kernel32!0x200'
>>> winappdbg.Process.parse_label(None, "CreateFileA")              # function in any module...
'!CreateFileA'
>>> winappdbg.Process.parse_label(None, 16)                         # ...by ordinal
'!#0x10'
>>> winappdbg.Process.parse_label(None, "CreateFileA", 512)         # ...plus an offset...
'!CreateFileA+0x200'
>>> winappdbg.Process.parse_label(None, 16, 512)                    # ...by ordinal
'!#0x10+0x200'
>>> winappdbg.Process.parse_label("kernel32", "CreateFileA", 512)   # full label...
'kernel32!CreateFileA+0x200'
>>> winappdbg.Process.parse_label("kernel32", 16, 512)              # ...by ordinal
'kernel32!#0x10+0x200'

The **get_label_at_address** method automatically guesses a good label for any given address in the process.

>>> import winappdbg
>>> aSystem = winappdbg.System()
>>> aSystem.request_debug_privileges()
True
>>> aSystem.scan()
>>> aProcess = aSystem.find_processes_by_filename("calc.exe")[0][0]
>>> aProcess.get_label_at_address(0x7c801a28)                           # address within kernel32.dll
'kernel32+0x1a28!'

Splitting labels
----------------

To split labels back to their original *module*, *function* and *offset* components there are two modes. The **strict** mode allows only labels that have been generated with *parse_label*. The **fuzzy** mode has a more flexible syntax, and supports some notation abuses that can only be resolved by a live *Process* instance.

The **split_label** method will automatically use the *strict* mode when called as a static method, and the *fuzzy* mode when called as an instance method:

::

    winappdbg.Process.split_method( "kernel32!CreateFileA" )            # static method, using the strict mode
    aProcessInstance.split_method( "CreateFileA" )                      # instance method, using the fuzzy mode

The **sanitize_label** method takes a fuzzy syntax label and converts it to strict syntax. This is useful when reading labels from user input and storing them for later use, when the process is no longer being debugged.

Strict syntax mode
++++++++++++++++++

To explicitly use the *strict* syntax mode, call the **split_label_strict** method:

>>> import winappdbg
>>> winappdbg.Process.split_label_strict(None)                             # empty label
(None, None, None)
>>> winappdbg.Process.split_label_strict('')                               # empty label
(None, None, None)
>>> winappdbg.Process.split_label_strict('0x0')                            # NULL pointer
(None, None, None)
>>> winappdbg.Process.split_label_strict('0x200')                          # any memory address
(None, None, 512)
>>> winappdbg.Process.split_label_strict('0x200 ! ')                       # meaningless ! is ignored
(None, None, 512)
>>> winappdbg.Process.split_label_strict(' ! 0x200')                       # meaningless ! is ignored
(None, None, 512)
>>> winappdbg.Process.split_label_strict('kernel32 ! ')                    # module base
('kernel32', None, None)
>>> winappdbg.Process.split_label_strict('kernel32 ! CreateFileA')         # exported function...
('kernel32', 'CreateFileA', None)
>>> winappdbg.Process.split_label_strict('kernel32 ! # 0x10')              # ...by ordinal
('kernel32', 16, None)
>>> winappdbg.Process.split_label_strict('kernel32 ! 0x200')               # base address + offset...
('kernel32', None, 512)
>>> winappdbg.Process.split_label_strict('kernel32 + 0x200 ! ')            # ...alternative syntax
('kernel32', None, 512)
>>> winappdbg.Process.split_label_strict(' ! CreateFileA')                 # function in any module...
(None, 'CreateFileA', None)
>>> winappdbg.Process.split_label_strict(' ! # 0x10')                      # ...by ordinal
(None, 16, None)
>>> winappdbg.Process.split_label_strict(' ! CreateFileA + 0x200')         # ...plus an offset...
(None, 'CreateFileA', 512)
>>> winappdbg.Process.split_label_strict(' ! # 0x10 + 0x200')              # ...by ordinal
(None, 16, 512)
>>> winappdbg.Process.split_label_strict('kernel32 ! CreateFileA + 0x200') # full label...
('kernel32', 'CreateFileA', 512)
>>> winappdbg.Process.split_label_strict('kernel32 ! # 0x10 + 0x200')      # ...by ordinal
('kernel32', 16, 512)

Fuzzy syntax mode
+++++++++++++++++

To explicitly use the *fuzzy* syntax mode, call the **split_label_fuzzy** method:

>>> import winappdbg
>>> aSystem = winappdbg.System()
>>> aSystem.request_debug_privileges()
True
>>> aSystem.scan()
>>> aProcess = aSystem.find_processes_by_filename("calc.exe")[0][0]
>>> aProcess.split_label_fuzzy( "kernel32" )                            # allows no ! sign
('kernel32', None, None)
>>> aProcess.split_label_fuzzy( "kernel32.dll" )                        # strips the default extension
('kernel32', None, None)
>>> aProcess.split_label_fuzzy( "CreateFileA" )                         # can tell a module from a function name
(None, 'CreateFileA', None)
>>> aProcess.split_label_strict( "0x7c800000" )                         # strict mode can't tell base address from offset
(None, None, 2088763392)
>>> aProcess.split_label_fuzzy( "0x7c800000" )                          # fuzzy mode can tell base address from offset
('kernel32', None, None)
>>> aProcess.split_label_fuzzy( "0x7c800000 + 6696" )                   # base address + offset
('kernel32', None, 6696)
>>> aProcess.split_label_fuzzy("0x7c801a28")                            # any memory address
('kernel32', None, 6696)
>>> aProcess.split_label_fuzzy( "0x200" )                               # address outside of any loaded module
(None, None, 512)

Resolving labels
----------------

The **resolve_label** method allows you to get the actual memory address the label points at the given process. If the module is not loaded or the function is not exported, the method fails with an exception.

>>> import winappdbg
>>> aSystem = winappdbg.System()
>>> aSystem.request_debug_privileges()
True
>>> aSystem.scan()
>>> aProcess = aSystem.find_processes_by_filename("calc.exe")[0][0]
>>> aProcess.resolve_label( "kernel32" )                                # module base
2088763392
>>> aProcess.resolve_label( "KERNEL32" )                                # module names are case insensitive
2088763392
>>> aProcess.resolve_label( "kernel32.dll" )
2088763392
>>> aProcess.resolve_label( "kernel32 + 0x200" )                        # module + offset
2088763904
>>> aProcess.resolve_label( "kernel32 ! CreateFileA" )
2088770088
>>> aProcess.resolve_label( "CreateFileA" )                             # all loaded modules are searched
2088770088
>>> aProcess.resolve_label( " # 16" )                                   # function ordinal
2090010350
>>> aProcess.resolve_label( " # 0x10" )                                 # function ordinal in hexa
2090010350
>>> aProcess.resolve_label( "kernel32 ! CreateFileA + 0x200" )
2088770600
>>> aProcess.resolve_label( "CreateFileA + 0x200" )
2088770600
>>> aProcess.resolve_label( "0x7c800000" )                              # module base address
2088763392
>>> aProcess.resolve_label( "0x7c800000 ! CreateFileA" )
2088770088

