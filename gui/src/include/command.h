#pragma once

#include <windows.h>


// Command context
typedef struct {
    NTSTATUS *result;
    LPCWSTR szOperation;
    LPWSTR *pszFilesList;
    DWORD dwFilesCount;
    HWND hKeyPath;
    HWND hAlgorithm;
    HWND hMode;
    HWND hBrowse;
    HWND hOK;
    HWND hCancel;
    LPCWSTR szFilter;
    WCHAR szKeyPath[MAX_PATH];
} UIOperationContext;


/**
 * @brief Command execution based on UI data context
 */
LRESULT ExecuteOperation(UIOperationContext *data);
