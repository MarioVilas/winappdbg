#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    HANDLE hFile;
    char* buffer;
    HANDLE hHeap;
    DWORD bytesWritten;
    DWORD bytesRead;
    HKEY hKey;
    LONG lRes;
    WCHAR wideBuffer[128];
    char narrowBuffer[128];
    HMODULE hUser32;
    FARPROC pMessageBoxA;

    printf("Dummy program starting.\n");

    // Use LoadLibrary and GetProcAddress
    printf("Loading user32.dll and getting MessageBoxA address...\n");
    hUser32 = LoadLibraryA("user32.dll");
    if (hUser32 != NULL) {
        pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
        if (pMessageBoxA != NULL) {
            printf("Calling MessageBoxA...\n");
            ((int (WINAPI *)(HWND, LPCSTR, LPCSTR, UINT))pMessageBoxA)(NULL, "Hello from dummy program!", "WinAppDbg Test", MB_OK);
        } else {
            printf("Failed to get address of MessageBoxA.\n");
        }
        FreeLibrary(hUser32);
    } else {
        printf("Failed to load user32.dll.\n");
    }

    // File operations
    printf("Creating file 'dummy_file.txt'...\n");
    hHeap = GetProcessHeap();
    buffer = (char*)HeapAlloc(hHeap, 0, 128);
    if (buffer == NULL) {
        printf("Failed to allocate buffer on the heap.\n");
        return 1;
    }

    hFile = CreateFileA("dummy_file.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("Writing to file...\n");
        WriteFile(hFile, "Hello, world!", 13, &bytesWritten, NULL);

        printf("Moving file pointer to the beginning...\n");
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

        printf("Reading from file...\n");
        ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("Read from file: %s\n", buffer);
        }

        CloseHandle(hFile);
        printf("Closed file handle.\n");
    } else {
        printf("Failed to create file.\n");
    }
    HeapFree(hHeap, 0, buffer);

    // Registry operations
    printf("Creating registry key HKCU\\Software\\WinAppDbg\\Dummy...\n");
    lRes = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\WinAppDbg\\Dummy", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (lRes == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("Registry key created and closed.\n");
    } else {
        printf("Failed to create registry key.\n");
    }

    // wsprintfW
    printf("Using wsprintfW to format a string...\n");
    wsprintfW(wideBuffer, L"This is a formatted string with number %d", 12345);

    // Convert wide char string to narrow char string to print to console
    if (WideCharToMultiByte(CP_ACP, 0, wideBuffer, -1, narrowBuffer, sizeof(narrowBuffer), NULL, NULL) > 0) {
        printf("Formatted string: %s\n", narrowBuffer);
    }

    printf("Dummy program finishing. Sleeping for 5 seconds...\n");
    Sleep(5000); // Sleep for 5 seconds

    return 0;
}
