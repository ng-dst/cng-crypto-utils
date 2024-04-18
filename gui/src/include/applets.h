#pragma once

#include <windows.h>


NTSTATUS ZCU_EncryptWindow(LPWSTR *pszFilesList, DWORD dwFilesCount);

NTSTATUS ZCU_DecryptWindow(LPWSTR *pszFilesList, DWORD dwFilesCount);

NTSTATUS ZCU_SignWindow(LPWSTR *pszFilesList, DWORD dwFilesCount);

NTSTATUS ZCU_VerifyWindow(LPWSTR *pszFilesList, DWORD dwFilesCount);

NTSTATUS ZCU_HashWindow(LPWSTR *pszFilesList, DWORD dwFilesCount);


NTSTATUS ZCU_GenKeyWindow();

NTSTATUS ZCU_GenPairWindow();
