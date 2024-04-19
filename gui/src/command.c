/**
 * @file command.c
 *
 * Form and execute command line operations
 */

#include <windows.h>
#include <ntstatus.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <ntdef.h>

#include "command.h"
#include "gui.h"

#define TEMP_HASHES_FILE L"temp.hashes.txt"

#define MAX_ALGO_NAME_LENGTH 32
#define MAX_ERROR_MSG_LENGTH (MAX_PATH + 128)


static VOID GetErrorMessage(NTSTATUS status, LPWSTR szErrorMessage) {
    /**
     * @brief Get error message for exit code into buffer
     */

    // Default error message
    StringCchPrintfW(szErrorMessage, sizeof(szErrorMessage), L"Error: 0x%08X", status);

    // Try to format message instead
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll != INVALID_HANDLE_VALUE) {
        FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                hNtDll,
                status,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                szErrorMessage,
                MAX_ERROR_MSG_LENGTH - MAX_PATH, NULL);
        CloseHandle(hNtDll);
    }
}


static VOID PopupFileError(LPCWSTR szFile, NTSTATUS status) {
    /**
     * @brief Popup error message for file, based on status
     */

    WCHAR szErrorMessage[MAX_ERROR_MSG_LENGTH];

    LPCWSTR szFileName = PathFindFileNameW(szFile);
    if (!szFileName) szFileName = szFile;

    StringCchPrintfW(szErrorMessage, MAX_ERROR_MSG_LENGTH, L"%s: ", szFileName);
    GetErrorMessage((NTSTATUS) status, szErrorMessage + wcslen(szErrorMessage));

    MessageBox(NULL, szErrorMessage, L"Error", MB_ICONERROR | MB_SYSTEMMODAL);
}


static VOID GetCUPath(LPWSTR szPath) {
    /**
     * @brief Get path to CU executable (./lab3.exe)
     *
     * @param szPath: Buffer to store path. Needs to be at least MAX_PATH size
     */

    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    PathRemoveFileSpecW(szPath);
    PathAppendW(szPath, L"lab3.exe");
}


static VOID GetTempFilePath(LPWSTR szPath) {
    /**
     * @brief Get path to temporary file
     *
     * @param szPath: Buffer to store path. Needs to be at least MAX_PATH size
     */

    GetTempPathW(MAX_PATH, szPath);
    PathAppendW(szPath, TEMP_HASHES_FILE);
}


static VOID BuildCmdLine(LPWSTR szCmdLine, LPCWSTR szCUPath, LPCWSTR szOperation, LPCWSTR szFile, LPCWSTR szKeyPath, LPCWSTR szAlgo, LPCWSTR szMode) {
    /**
     * @brief Build command line for operation
     */

    LPCWSTR szVerb;
    if (StrCmpIW(szOperation, APPLET_ENCRYPT) == 0) szVerb = L"encrypt";
    else if (StrCmpIW(szOperation, APPLET_DECRYPT) == 0) szVerb = L"decrypt";
    else if (StrCmpIW(szOperation, APPLET_HASH) == 0) szVerb = L"hash";
    else if (StrCmpIW(szOperation, APPLET_SIGN) == 0) szVerb = L"sign";
    else if (StrCmpIW(szOperation, APPLET_VERIFY) == 0) szVerb = L"verify";
    else if (StrCmpIW(szOperation, APPLET_GEN_KEY) == 0) szVerb = L"gen-key";
    else if (StrCmpIW(szOperation, APPLET_GEN_PAIR) == 0) szVerb = L"gen-pair";
    else return;

    // Encrypt / Decrypt: <verb> <input file> <key file> -a <algorithm> -m <mode>
    if (StrCmpIW(szOperation, APPLET_ENCRYPT) == 0 || StrCmpIW(szOperation, APPLET_DECRYPT) == 0) {
        StringCchPrintfW(szCmdLine, MAX_PATH * 4, L"\"%s\" %s \"%s\" \"%s\" -a %s -m %s",
                         szCUPath, szVerb, szFile, szKeyPath, szAlgo, szMode);
    }

    // Hash: <verb> <input file> -a <algorithm>
    else if (StrCmpIW(szOperation, APPLET_HASH) == 0) {
        StringCchPrintfW(szCmdLine, MAX_PATH * 4, L"\"%s\" %s \"%s\" -a %s",
                         szCUPath, szVerb, szFile, szAlgo);
    }

    // Sign / Verify: <verb> <input file> <key file> -s <sig_algorithm> -a <hash_algorithm>
    else if (StrCmpIW(szOperation, APPLET_SIGN) == 0 || StrCmpIW(szOperation, APPLET_VERIFY) == 0) {
        StringCchPrintfW(szCmdLine, MAX_PATH * 4, L"\"%s\" %s \"%s\" \"%s\" -s %s -a %s",
                         szCUPath, szVerb, szFile, szKeyPath, szAlgo, szMode);
    }

    // GenKey, GenPair: <verb> -a <algorithm>
    else if (StrCmpIW(szOperation, APPLET_GEN_KEY) == 0 || StrCmpIW(szOperation, APPLET_GEN_PAIR) == 0) {
        StringCchPrintfW(szCmdLine, MAX_PATH * 4, L"\"%s\" %s -a %s",
                         szCUPath, szVerb, szAlgo);
    }
}


LRESULT ExecuteOperation(UIOperationContext *data) {
    /**
     * @brief Execute operation based on fields in data
     */

    // Get CU path
    WCHAR szCUPath[MAX_PATH] = {0};
    GetCUPath(szCUPath);

    // Get parameters from handles
    WCHAR szAlgo[MAX_ALGO_NAME_LENGTH];
    if (data->hAlgorithm != NULL)
        GetWindowTextW(data->hAlgorithm, szAlgo, MAX_ALGO_NAME_LENGTH - 1);

    WCHAR szMode[MAX_ALGO_NAME_LENGTH];
    if (data->hMode != NULL)
        GetWindowTextW(data->hMode, szMode, MAX_ALGO_NAME_LENGTH - 1);

    WCHAR szKeyPath[MAX_PATH];
    if (data->hKeyPath != NULL)
        GetWindowTextW(data->hKeyPath, szKeyPath, MAX_PATH - 1);

    // Hash: open temp file for hashes
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    WCHAR szTempPath[MAX_PATH] = {0};
    if (StrCmpIW(data->szOperation, APPLET_HASH) == 0) {
        GetTempFilePath(szTempPath);
        hTempFile = CreateFileW(szTempPath, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTempFile == INVALID_HANDLE_VALUE) {
            *data->result = STATUS_ACCESS_DENIED;
            return 0;
        }
    }

    // For each file in list, execute command
    for (DWORD i = 0; i < data->dwFilesCount; i++) {
        // Prepare command line
        WCHAR szCmdLine[MAX_PATH * 4] = {0};
        BuildCmdLine(szCmdLine, szCUPath, data->szOperation, data->pszFilesList[i], szKeyPath, szAlgo, szMode);

        // Execute command
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};

        // For hashes, redirect output to temp file
        if (hTempFile != INVALID_HANDLE_VALUE) {
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            si.hStdOutput = hTempFile;
            si.hStdError = hTempFile;
        }

        if (!CreateProcessW(szCUPath, szCmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            *data->result = STATUS_NOT_FOUND;
            continue;
        }

        // Wait for process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Get exit code
        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess, &dwExitCode);

        // Close process handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Set result on error
        if (!NT_SUCCESS(dwExitCode)) {
            *data->result = (NTSTATUS) dwExitCode;
            PopupFileError(data->pszFilesList[i], *data->result);
        }
    }

    // Close temp file
    if (hTempFile != INVALID_HANDLE_VALUE) CloseHandle(hTempFile);

    // Set success if not set
    if (*data->result == STATUS_PENDING)
        *data->result = STATUS_SUCCESS;

    // For non-hash, display success message
    if (NT_SUCCESS(*data->result) && 0 != StrCmpIW(data->szOperation, APPLET_HASH)) {
        WCHAR szMessage[MAX_PATH];
        StringCchPrintfW(szMessage, MAX_PATH, L"%s: success", data->szOperation);
        MessageBox(NULL, szMessage, L"Info", MB_OK);
    }

    // For hash, open temp file with notepad
    if (NT_SUCCESS(*data->result) && 0 == StrCmpIW(data->szOperation, APPLET_HASH))
        ShellExecuteW(NULL, L"open", L"notepad.exe", szTempPath, NULL, SW_SHOWNORMAL);

    return 0;
}
