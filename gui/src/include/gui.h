#pragma once

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>

#define APPLET_ENCRYPT L"Encrypt"
#define APPLET_DECRYPT L"Decrypt"
#define APPLET_SIGN L"Sign"
#define APPLET_VERIFY L"Verify"
#define APPLET_HASH L"Hash"
#define APPLET_GEN_KEY L"Generate Encryption Key"
#define APPLET_GEN_PAIR L"Generate Key Pair"


NTSTATUS CreateKeyedOperationWindow(HINSTANCE hInstance, LPCWSTR applet, LPWSTR *pszFilesList, DWORD dwFilesCount);

NTSTATUS CreateAlgorithmSelectWindow(HINSTANCE hInstance, LPCWSTR applet, LPWSTR *pszFilesList, DWORD dwFilesCount);
