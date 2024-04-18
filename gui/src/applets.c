/**
 * @file applets.c
 *
 * GUI applets
 */

#include <windows.h>

#include "gui.h"


NTSTATUS ZCU_EncryptWindow(LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * Redirect to Full GUI window with Encrypt applet
     */
    return CreateKeyedOperationWindow(GetModuleHandle(NULL), APPLET_ENCRYPT, pszFilesList, dwFilesCount);
}


NTSTATUS ZCU_DecryptWindow(LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * Redirect to Full GUI window with Decrypt applet
     */
    return CreateKeyedOperationWindow(GetModuleHandle(NULL), APPLET_DECRYPT, pszFilesList, dwFilesCount);
}


NTSTATUS ZCU_SignWindow(LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * Redirect to Full GUI window with Sign applet
     */
    return CreateKeyedOperationWindow(GetModuleHandle(NULL), APPLET_SIGN, pszFilesList, dwFilesCount);
}


NTSTATUS ZCU_VerifyWindow(LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * Redirect to Full GUI window with Verify applet
     */
    return CreateKeyedOperationWindow(GetModuleHandle(NULL), APPLET_VERIFY, pszFilesList, dwFilesCount);
}


NTSTATUS ZCU_HashWindow(LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * Redirect to Algorithm GUI window with Hash applet
     */
    return CreateAlgorithmSelectWindow(GetModuleHandle(NULL), APPLET_HASH, pszFilesList, dwFilesCount);
}


NTSTATUS ZCU_GenKeyWindow() {
    /**
     * Redirect to Algorithm GUI window with GenKey applet
     */
    LPWSTR szFilesList[] = {L"", NULL};
    return CreateAlgorithmSelectWindow(GetModuleHandle(NULL), APPLET_GEN_KEY, szFilesList, 1);
}


NTSTATUS ZCU_GenPairWindow() {
    /**
     * Redirect to Algorithm GUI window with GenPair applet
     */
    LPWSTR szFilesList[] = {L"", NULL};
    return CreateAlgorithmSelectWindow(GetModuleHandle(NULL), APPLET_GEN_PAIR, szFilesList, 1);
}
