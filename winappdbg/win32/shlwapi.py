# Copyright (c) 2009, Mario Vilas
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
Debugging API wrappers in ctypes.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/Win32APIWrappers}
"""

__revision__ = "$Id$"

from defines import *

#--- shlwapi.dll --------------------------------------------------------------

# LPTSTR PathAddBackslash(
#     LPTSTR lpszPath
# );
def PathAddBackslashA(lpszPath):
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathAddBackslashA(lpszPath)
    return lpszPath.value
def PathAddBackslashW(lpszPath):
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathAddBackslashW(lpszPath)
    return lpszPath.value
PathAddBackslash = GuessStringType(PathAddBackslashA, PathAddBackslashW)

# BOOL PathAddExtension(
#     LPTSTR pszPath,
#     LPCTSTR pszExtension
# );
def PathAddExtensionA(lpszPath, pszExtension = None):
    if pszExtension is None:
        pszExtension = NULL
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAddExtensionA(lpszPath, pszExtension)
    if success == FALSE:
        return None
    return lpszPath.value
def PathAddExtensionW(lpszPath, pszExtension = None):
    if pszExtension is None:
        pszExtension = NULL
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAddExtensionW(lpszPath, pszExtension)
    if success == FALSE:
        return None
    return lpszPath.value
PathAddExtension = GuessStringType(PathAddExtensionA, PathAddExtensionW)

# BOOL PathAppend(
#     LPTSTR pszPath,
#     LPCTSTR pszMore
# );
def PathAppendA(lpszPath, pszMore = None):
    if pszMore is None:
        pszMore = NULL
    lpszPath = ctypes.create_string_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAppendA(lpszPath, pszMore)
    if success == FALSE:
        return None
    return lpszPath.value
def PathAppendW(lpszPath, pszMore = None):
    if pszMore is None:
        pszMore = NULL
    lpszPath = ctypes.create_unicode_buffer(lpszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathAppendW(lpszPath, pszMore)
    if success == FALSE:
        return None
    return lpszPath.value
PathAppend = GuessStringType(PathAppendA, PathAppendW)

# LPTSTR PathCombine(
#     LPTSTR lpszDest,
#     LPCTSTR lpszDir,
#     LPCTSTR lpszFile
# );
def PathCombineA(lpszDir, lpszFile):
    lpszDest = ctypes.create_string_buffer("", max(MAX_PATH, len(lpszDir) + len(lpszFile) + 1))
    retval = ctypes.windll.shlwapi.PathCombineA(lpszDest, lpszDir, lpszFile)
    if retval == NULL:
        return None
    return lpszDest.value
def PathCombineW(lpszDir, lpszFile):
    lpszDest = ctypes.create_unicode_buffer(u"", max(MAX_PATH, len(lpszDir) + len(lpszFile) + 1))
    retval = ctypes.windll.shlwapi.PathCombineW(lpszDest, lpszDir, lpszFile)
    if retval == NULL:
        return None
    return lpszDest.value
PathCombine = GuessStringType(PathCombineA, PathCombineW)

# BOOL PathCanonicalize(
#     LPTSTR lpszDst,
#     LPCTSTR lpszSrc
# );
def PathCanonicalizeA(lpszSrc):
    lpszDst = ctypes.create_string_buffer("", MAX_PATH)
    success = ctypes.windll.shlwapi.PathCanonicalizeA(ctypes.byref(lpszDst), lpszSrc)
    if success == FALSE:
        raise ctypes.WinError()
    return lpszDst.value
def PathCanonicalizeW(lpszSrc):
    lpszDst = ctypes.create_unicode_buffer(u"", MAX_PATH)
    success = ctypes.windll.shlwapi.PathCanonicalizeW(ctypes.byref(lpszDst), lpszSrc)
    if success == FALSE:
        raise ctypes.WinError()
    return lpszDst.value
PathCanonicalize = GuessStringType(PathCanonicalizeA, PathCanonicalizeW)

# BOOL PathFileExists(
#     LPCTSTR pszPath
# );
def PathFileExistsA(pszPath):
    return bool( ctypes.windll.shlwapi.PathFileExistsA(pszPath) )
def PathFileExistsW(pszPath):
    return bool( ctypes.windll.shlwapi.PathFileExistsW(pszPath) )
PathFileExists = GuessStringType(PathFileExistsA, PathFileExistsW)

# LPTSTR PathFindExtension(
#     LPCTSTR pszPath
# );
def PathFindExtensionA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathExtension = ctypes.windll.shlwapi.PathFindExtensionA(pszPath)
    pszPathExtension = ctypes.c_void_p(pszPathExtension)
    pszPathExtension = ctypes.cast(pszPathExtension, ctypes.c_char_p)
    return pszPathExtension.value
def PathFindExtensionW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathExtension = ctypes.windll.shlwapi.PathFindExtensionW(pszPath)
    pszPathExtension = ctypes.c_void_p(pszPathExtension)
    pszPathExtension = ctypes.cast(pszPathExtension, ctypes.c_wchar_p)
    return pszPathExtension.value
PathFindExtension = GuessStringType(PathFindExtensionA, PathFindExtensionW)

# LPTSTR PathFindFileName(
#     LPCTSTR pszPath
# );
def PathFindFileNameA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathFilename = ctypes.windll.shlwapi.PathFindFileNameA(pszPath)
    pszPathFilename = ctypes.c_void_p(pszPathFilename)
    pszPathFilename = ctypes.cast(pszPathFilename, ctypes.c_char_p)
    return pszPathFilename.value
def PathFindFileNameW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathFilename = ctypes.windll.shlwapi.PathFindFileNameW(pszPath)
    pszPathFilename = ctypes.c_void_p(pszPathFilename)
    pszPathFilename = ctypes.cast(pszPathFilename, ctypes.c_wchar_p)
    return pszPathFilename.value
PathFindFileName = GuessStringType(PathFindFileNameA, PathFindFileNameW)

# LPTSTR PathFindNextComponent(
#     LPCTSTR pszPath
# );
def PathFindNextComponentA(pszPath):
    pszPath = ctypes.c_char_p(pszPath)
    pszPathNext = ctypes.windll.shlwapi.PathFindNextComponentA(pszPath)
    pszPathNext = ctypes.c_void_p(pszPathNext)
    pszPathNext = ctypes.cast(pszPathNext, ctypes.c_char_p)
    return pszPathNext.value    # may return None
def PathFindNextComponentW(pszPath):
    pszPath = ctypes.c_wchar_p(pszPath)
    pszPathNext = ctypes.windll.shlwapi.PathFindNextComponentW(pszPath)
    pszPathNext = ctypes.c_void_p(pszPathNext)
    pszPathNext = ctypes.cast(pszPathNext, ctypes.c_wchar_p)
    return pszPathNext.value    # may return None
PathFindNextComponent = GuessStringType(PathFindNextComponentA, PathFindNextComponentW)

# BOOL PathFindOnPath(
#     LPTSTR pszFile,
#     LPCTSTR *ppszOtherDirs
# );
def PathFindOnPathA(pszFile, ppszOtherDirs = None):
    pszFile = ctypes.create_string_buffer(pszFile, MAX_PATH)
    if not ppszOtherDirs:
        ppszOtherDirs = NULL
    else:
        ppszArray = ""
        for pszOtherDirs in ppszOtherDirs:
            if pszOtherDirs:
                ppszArray = "%s%s\0" % (ppszArray, pszOtherDirs)
        ppszArray = ppszArray + "\0"
        ppszOtherDirs = ctypes.byref( ctypes.create_string_buffer(ppszArray) )
    success = ctypes.windll.shlwapi.PathFindOnPathA(pszFile, ppszOtherDirs)
    if success == FALSE:
        return None
    return pszFile.value
def PathFindOnPathW(pszFile, ppszOtherDirs = None):
    pszFile = ctypes.create_unicode_buffer(pszFile, MAX_PATH)
    if not ppszOtherDirs:
        ppszOtherDirs = NULL
    else:
        ppszArray = u""
        for pszOtherDirs in ppszOtherDirs:
            if pszOtherDirs:
                ppszArray = u"%s%s\0" % (ppszArray, pszOtherDirs)
        ppszArray = ppszArray + u"\0"
        ppszOtherDirs = ctypes.byref( ctypes.create_unicode_buffer(ppszArray) )
    success = ctypes.windll.shlwapi.PathFindOnPathW(pszFile, ppszOtherDirs)
    if success == FALSE:
        return None
    return pszFile.value
PathFindOnPath = GuessStringType(PathFindOnPathA, PathFindOnPathW)

# LPTSTR PathGetArgs(
#     LPCTSTR pszPath
# );
def PathGetArgsA(pszPath):
    pszPath = ctypes.windll.shlwapi.PathGetArgsA(pszPath)
    pszPath = ctypes.c_void_p(pszPath)
    pszPath = ctypes.cast(pszPath, ctypes.c_char_p)
    return pszPath.value
def PathGetArgsW(pszPath):
    pszPath = ctypes.windll.shlwapi.PathGetArgsW(pszPath)
    pszPath = ctypes.c_void_p(pszPath)
    pszPath = ctypes.cast(pszPath, ctypes.c_wchar_p)
    return pszPath.value
PathGetArgs = GuessStringType(PathGetArgsA, PathGetArgsW)

# BOOL PathIsContentType(
#     LPCTSTR pszPath,
#     LPCTSTR pszContentType
# );
def PathIsContentTypeA(pszPath, pszContentType):
    return bool( ctypes.windll.shlwapi.PathIsContentTypeA(pszPath, pszContentType) )
def PathIsContentTypeW(pszPath, pszContentType):
    return bool( ctypes.windll.shlwapi.PathIsContentTypeW(pszPath, pszContentType) )
PathIsContentType = GuessStringType(PathIsContentTypeA, PathIsContentTypeW)

# BOOL PathIsDirectory(
#     LPCTSTR pszPath
# );
def PathIsDirectoryA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryA(pszPath) )
def PathIsDirectoryW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryW(pszPath) )
PathIsDirectory = GuessStringType(PathIsDirectoryA, PathIsDirectoryW)

# BOOL PathIsDirectoryEmpty(
#     LPCTSTR pszPath
# );
def PathIsDirectoryEmptyA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryEmptyA(pszPath) )
def PathIsDirectoryEmptyW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsDirectoryEmptyW(pszPath) )
PathIsDirectoryEmpty = GuessStringType(PathIsDirectoryEmptyA, PathIsDirectoryEmptyW)

# BOOL PathIsNetworkPath(
#     LPCTSTR pszPath
# );
def PathIsNetworkPathA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsNetworkPathA(pszPath) )
def PathIsNetworkPathW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsNetworkPathW(pszPath) )
PathIsNetworkPath = GuessStringType(PathIsNetworkPathA, PathIsNetworkPathW)

# BOOL PathIsRelative(
#     LPCTSTR lpszPath
# );
def PathIsRelativeA(lpszPath):
    return bool( ctypes.windll.shlwapi.PathIsRelativeA(lpszPath) )
def PathIsRelativeW(lpszPath):
    return bool( ctypes.windll.shlwapi.PathIsRelativeW(lpszPath) )
PathIsRelative = GuessStringType(PathIsRelativeA, PathIsRelativeW)

# BOOL PathIsRoot(
#     LPCTSTR pPath
# );
def PathIsRootA(pPath):
    return bool( ctypes.windll.shlwapi.PathIsRootA(pPath) )
def PathIsRootW(pPath):
    return bool( ctypes.windll.shlwapi.PathIsRootW(pPath) )
PathIsRoot = GuessStringType(PathIsRootA, PathIsRootW)

# BOOL PathIsSameRoot(
#     LPCTSTR pszPath1,
#     LPCTSTR pszPath2
# );
def PathIsSameRootA(pszPath1, pszPath2):
    return bool( ctypes.windll.shlwapi.PathIsSameRootA(pszPath1, pszPath2) )
def PathIsSameRootW(pszPath1, pszPath2):
    return bool( ctypes.windll.shlwapi.PathIsSameRootW(pszPath1, pszPath2) )
PathIsSameRoot = GuessStringType(PathIsSameRootA, PathIsSameRootW)

# BOOL PathIsUNC(
#     LPCTSTR pszPath
# );
def PathIsUNCA(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsUNCA(pszPath) )
def PathIsUNCW(pszPath):
    return bool( ctypes.windll.shlwapi.PathIsUNCW(pszPath) )
PathIsUNC = GuessStringType(PathIsUNCA, PathIsUNCW)

# XXX PathMakePretty turns filenames into all lowercase.
# I'm not sure how well that might work on Wine.

# BOOL PathMakePretty(
#     LPCTSTR pszPath
# );
def PathMakePrettyA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath)
    ctypes.windll.shlwapi.PathMakePrettyA(ctypes.byref(pszPath))
    return pszPath.value
def PathMakePrettyW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath)
    ctypes.windll.shlwapi.PathMakePrettyW(ctypes.byref(pszPath))
    return pszPath.value
PathMakePretty = GuessStringType(PathMakePrettyA, PathMakePrettyW)

# void PathRemoveArgs(
#     LPTSTR pszPath
# );
def PathRemoveArgsA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveArgsA(pszPath)
    return pszPath.value
def PathRemoveArgsW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveArgsW(pszPath)
    return pszPath.value
PathRemoveArgs = GuessStringType(PathRemoveArgsA, PathRemoveArgsW)

# void PathRemoveBackslash(
#     LPTSTR pszPath
# );
def PathRemoveBackslashA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveBackslashA(pszPath)
    return pszPath.value
def PathRemoveBackslashW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveBackslashW(pszPath)
    return pszPath.value
PathRemoveBackslash = GuessStringType(PathRemoveBackslashA, PathRemoveBackslashW)

# void PathRemoveExtension(
#     LPTSTR pszPath
# );
def PathRemoveExtensionA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveExtensionA(pszPath)
    return pszPath.value
def PathRemoveExtensionW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveExtensionW(pszPath)
    return pszPath.value
PathRemoveExtension = GuessStringType(PathRemoveExtensionA, PathRemoveExtensionW)

# void PathRemoveFileSpec(
#     LPTSTR pszPath
# );
def PathRemoveFileSpecA(pszPath):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveFileSpecA(pszPath)
    return pszPath.value
def PathRemoveFileSpecW(pszPath):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    ctypes.windll.shlwapi.PathRemoveFileSpecW(pszPath)
    return pszPath.value
PathRemoveFileSpec = GuessStringType(PathRemoveFileSpecA, PathRemoveFileSpecW)

# BOOL PathRenameExtension(
#     LPTSTR pszPath,
#     LPCTSTR pszExt
# );
def PathRenameExtensionA(pszPath, pszExt):
    pszPath = ctypes.create_string_buffer(pszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathRenameExtensionA(pszPath, pszExt)
    if success == FALSE:
        return None
    return pszPath.value
def PathRenameExtensionW(pszPath, pszExt):
    pszPath = ctypes.create_unicode_buffer(pszPath, MAX_PATH)
    success = ctypes.windll.shlwapi.PathRenameExtensionW(pszPath, pszExt)
    if success == FALSE:
        return None
    return pszPath.value
PathRenameExtension = GuessStringType(PathRenameExtensionA, PathRenameExtensionW)

# BOOL PathUnExpandEnvStrings(
#     LPCTSTR pszPath,
#     LPTSTR pszBuf,
#     UINT cchBuf
# );
def PathUnExpandEnvStringsA(pszPath):
    pszBuf = ctypes.create_string_buffer("", MAX_PATH)
    cchBuf = MAX_PATH
    ctypes.windll.shlwapi.PathUnExpandEnvStringsA(ctypes.byref(pszPath), ctypes.byref(pszBuf), cchBuf)
    return pszBuf.value
def PathUnExpandEnvStringsW(pszPath):
    pszBuf = ctypes.create_unicode_buffer(u"", MAX_PATH)
    cchBuf = MAX_PATH
    ctypes.windll.shlwapi.PathUnExpandEnvStringsW(ctypes.byref(pszPath), ctypes.byref(pszBuf), cchBuf)
    return pszBuf.value
PathUnExpandEnvStrings = GuessStringType(PathUnExpandEnvStringsA, PathUnExpandEnvStringsW)
