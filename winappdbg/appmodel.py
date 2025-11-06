#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Support for launching and managing packaged applications (UWP/MSIX).

This module provides functionality to launch and enumerate Windows packaged
applications (Universal Windows Platform apps, Windows Store apps, MSIX packages).

.. note::
    This module requires the ``comtypes`` library for COM interop.
    Install it with: ``pip install winappdbg[packaged_apps]``

Requires Windows 8 or later.
"""

__all__ = [
    "HAS_COMTYPES",
    "launch_packaged_app",
    "parse_package_full_name",
    "parse_aumid",
    "build_aumid",
]

import warnings

# Try to import comtypes for COM support (launching apps)
try:
    import comtypes
    import comtypes.client
    from comtypes import GUID, POINTER, COMMETHOD

    HAS_COMTYPES = True
except ImportError:
    HAS_COMTYPES = False
    comtypes = None

# ==============================================================================

# Activation options for IApplicationActivationManager
AO_NONE = 0x00000000
AO_DESIGNMODE = 0x00000001
AO_NOERRORUI = 0x00000002
AO_NOSPLASHSCREEN = 0x00000004
AO_PRELAUNCH = 0x02000000


def _require_comtypes():
    """
    Helper function to check if comtypes is available.

    :raises ImportError: If comtypes is not installed.
    """
    if not HAS_COMTYPES:
        raise ImportError(
            "Launching packaged apps requires the 'comtypes' library.\n"
            "Install it with: pip install winappdbg[packaged_apps]"
        )


# ==============================================================================
# COM Interface Definitions
# ==============================================================================

if HAS_COMTYPES:
    # IApplicationActivationManager interface
    # GUID: {2e941141-7f97-4756-ba1d-9decde894a3d}
    class IApplicationActivationManager(comtypes.IUnknown):
        _iid_ = GUID("{2e941141-7f97-4756-ba1d-9decde894a3d}")
        _methods_ = [
            COMMETHOD(
                [],
                comtypes.HRESULT,
                "ActivateApplication",
                (["in"], comtypes.c_wchar_p, "appUserModelId"),
                (["in"], comtypes.c_wchar_p, "arguments"),
                (["in"], comtypes.c_uint, "options"),
                (["out"], POINTER(comtypes.c_ulong), "processId"),
            ),
            COMMETHOD(
                [],
                comtypes.HRESULT,
                "ActivateForFile",
                (["in"], comtypes.c_wchar_p, "appUserModelId"),
                (["in"], comtypes.c_void_p, "itemArray"),  # IShellItemArray
                (["in"], comtypes.c_wchar_p, "verb"),
                (["out"], POINTER(comtypes.c_ulong), "processId"),
            ),
            COMMETHOD(
                [],
                comtypes.HRESULT,
                "ActivateForProtocol",
                (["in"], comtypes.c_wchar_p, "appUserModelId"),
                (["in"], comtypes.c_void_p, "itemArray"),  # IShellItemArray
                (["out"], POINTER(comtypes.c_ulong), "processId"),
            ),
        ]

    # CLSID for ApplicationActivationManager
    CLSID_ApplicationActivationManager = GUID("{45BA127D-10A8-46EA-8AB7-56EA9078943C}")


# ==============================================================================
# Public API Functions
# ==============================================================================


def launch_packaged_app(aumid, arguments=None, options=AO_NONE):
    """
    Launch a packaged application by its Application User Model ID (AUMID).

    :param str aumid: Application User Model ID (AUMID) of the app to launch.
        Example: "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"

    :param str arguments: Optional command-line arguments to pass to the app.

    :param int options: Activation options. Can be a combination of:
        - ``AO_NONE`` (0x00000000): No special options
        - ``AO_DESIGNMODE`` (0x00000001): Launch in design mode
        - ``AO_NOERRORUI`` (0x00000002): Don't show error UI
        - ``AO_NOSPLASHSCREEN`` (0x00000004): Don't show splash screen
        - ``AO_PRELAUNCH`` (0x02000000): Prelaunch the app

    :rtype: int
    :return: Process ID of the launched application.

    :raises ImportError: If comtypes is not installed.
    :raises WindowsError: If the app fails to launch.

    Example::

        from winappdbg.appmodel import launch_packaged_app

        # Launch Windows Calculator
        pid = launch_packaged_app("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App")
        print(f"Calculator launched with PID: {pid}")
    """
    _require_comtypes()

    # Initialize COM
    comtypes.CoInitializeEx(comtypes.COINIT_APARTMENTTHREADED)

    try:
        # Create the ApplicationActivationManager instance
        aam = comtypes.client.CreateObject(
            CLSID_ApplicationActivationManager, interface=IApplicationActivationManager
        )

        # Call ActivateApplication
        # Note: out parameters in comtypes are returned, not passed
        process_id = aam.ActivateApplication(aumid, arguments or "", options)

        # Return the process ID
        return process_id

    finally:
        # Uninitialize COM
        comtypes.CoUninitialize()


# ==============================================================================
# Helper Functions
# ==============================================================================


def parse_package_full_name(package_full_name):
    """
    Parse a package full name into its components.

    Package full name format: ``Name_Version_Architecture_ResourceId_PublisherHash``

    Example: ``Microsoft.WindowsCalculator_11.2508.1.0_arm64__8wekyb3d8bbwe``

    :param str package_full_name: Package full name to parse.

    :rtype: dict or None
    :return: Dictionary with parsed components, or None if invalid format.
        Returned dict contains:
        - ``name`` (str): Package name
        - ``version`` (str): Version string
        - ``architecture`` (str): Architecture (x86, x64, arm, arm64, neutral)
        - ``resource_id`` (str): Resource ID (often empty)
        - ``publisher_hash`` (str): Publisher hash
        - ``package_family_name`` (str): Package family name (Name_PublisherHash)

    Example::

        info = parse_package_full_name(
            "Microsoft.WindowsCalculator_11.2508.1.0_arm64__8wekyb3d8bbwe"
        )
        # info['name']: "Microsoft.WindowsCalculator"
        # info['version']: "11.2508.1.0"
        # info['architecture']: "arm64"
        # info['package_family_name']: "Microsoft.WindowsCalculator_8wekyb3d8bbwe"
    """
    if not package_full_name:
        return None

    # Split by underscores
    # Format: Name_Version_Arch_ResourceId_PublisherHash
    parts = package_full_name.split("_")

    if len(parts) < 3:
        return None

    # The tricky part is that the name itself can contain underscores
    # The last part is always the publisher hash
    # The second-to-last is resource ID (can be empty)
    # The third-to-last is architecture
    # The fourth-to-last is version
    # Everything before that is the name

    publisher_hash = parts[-1]
    resource_id = parts[-2] if len(parts) > 1 else ""
    architecture = parts[-3] if len(parts) > 2 else ""
    version = parts[-4] if len(parts) > 3 else ""

    # Everything before version is the name (join with underscores)
    if len(parts) > 4:
        name = "_".join(parts[:-4])
    else:
        name = ""

    # Package family name is Name_PublisherHash
    package_family_name = f"{name}_{publisher_hash}"

    return {
        "name": name,
        "version": version,
        "architecture": architecture,
        "resource_id": resource_id,
        "publisher_hash": publisher_hash,
        "package_family_name": package_family_name,
    }


def parse_aumid(aumid):
    """
    Parse an Application User Model ID (AUMID) into its components.

    An AUMID has the format: ``PackageFamilyName!ApplicationId``

    :param str aumid: Application User Model ID to parse.

    :rtype: tuple[str, str] or None
    :return: Tuple of (package_family_name, app_id), or None if invalid format.

    Example::

        package_family_name, app_id = parse_aumid(
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
        )
        # package_family_name: "Microsoft.WindowsCalculator_8wekyb3d8bbwe"
        # app_id: "App"
    """
    if "!" not in aumid:
        return None

    parts = aumid.split("!", 1)
    return (parts[0], parts[1])


def build_aumid(package_family_name, app_id):
    """
    Build an Application User Model ID (AUMID) from components.

    :param str package_family_name: Package family name.
    :param str app_id: Application ID within the package.

    :rtype: str
    :return: Complete AUMID.

    Example::

        aumid = build_aumid("Microsoft.WindowsCalculator_8wekyb3d8bbwe", "App")
        # Result: "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
    """
    return f"{package_family_name}!{app_id}"


# ==============================================================================
# Module initialization warning
# ==============================================================================

# Warn if comtypes is missing
if not HAS_COMTYPES:
    warnings.warn(
        "The 'comtypes' library is not installed. "
        "Packaged app launching will not be available. "
        "Install with: pip install winappdbg[packaged_apps]",
        ImportWarning,
        stacklevel=2,
    )
