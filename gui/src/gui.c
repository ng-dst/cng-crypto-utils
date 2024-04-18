/**
 * @file gui.c
 *
 * GUI windows implementation
 */

#include <windows.h>
#include <shlwapi.h>
#include <ntstatus.h>
#include <stdio.h>
#include <strsafe.h>

#include "command.h"
#include "gui.h"


// Window dimensions
#define WIDTH 380
#define HEIGHT 150

#define WIDTH_SMALL 300
#define HEIGHT_SMALL 130

// Stored button callback
LONG_PTR pBtnProc = 0;


static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    /**
     * @brief (for internal use)
     *
     * Window procedure callback
     */

    switch (message) {
        case WM_CREATE:
        case WM_COMMAND:
        case WM_DESTROY:
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}


static LPWSTR GetFilterString(LPCWSTR applet) {
    /**
     * @brief Get filter string for key file dialog
     */

    if (StrCmpIW(applet, APPLET_ENCRYPT) == 0 || StrCmpIW(applet, APPLET_DECRYPT) == 0)
        return L"Key files (*.bin)\0*.bin\0All files (*.*)\0*.*\0";

    else if (StrCmpIW(applet, APPLET_SIGN) == 0)
        return L"Private key files (*.priv)\0*.priv\0All files (*.*)\0*.*\0";

    else if (StrCmpIW(applet, APPLET_VERIFY) == 0)
        return L"Public key files (*.pub)\0*.pub\0All files (*.*)\0*.*\0";

    else // Hash, gen-key, gen-pair
        return L"All files (*.*)\0*.*\0";
}


static LPCWSTR *GetAlgorithmList(LPCWSTR applet) {
    /**
     * @brief Get list of algorithms for dropdown
     */

    static LPCWSTR pszAlgosEnc[] = {L"AES", L"DES", L"3DES", L"DESX", L"RC4", L"RC2", NULL};
    static LPCWSTR pszAlgosSig[] = {L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P512", L"RSA", L"DSA", NULL};
    static LPCWSTR pszAlgosHash[] = {L"SHA256", L"SHA384", L"SHA512", L"SHA1", L"MD4", L"MD5", NULL};

    if (StrCmpIW(applet, APPLET_ENCRYPT) == 0 || StrCmpIW(applet, APPLET_DECRYPT) == 0 || StrCmpIW(applet, APPLET_GEN_KEY) == 0)
        return pszAlgosEnc;
    else if (StrCmpIW(applet, APPLET_SIGN) == 0 || StrCmpIW(applet, APPLET_VERIFY) == 0 || StrCmpIW(applet, APPLET_GEN_PAIR) == 0)
        return pszAlgosSig;
    else if (StrCmpIW(applet, APPLET_HASH) == 0)
        return pszAlgosHash;

    return (LPCWSTR[]) { NULL };
}


static LPCWSTR *GetModeList(LPCWSTR applet) {
    /**
     * @brief Get list of modes for dropdown
     */

    static LPCWSTR pszModesList[] = {L"", L"CBC", L"CFB", L"ECB", NULL};

    // Encrypt, Decrypt: mode
    if (StrCmpIW(applet, APPLET_ENCRYPT) == 0 || StrCmpIW(applet, APPLET_DECRYPT) == 0)
        return pszModesList;

    // Sign, Verify: hash algorithm
    else if (StrCmpIW(applet, APPLET_SIGN) == 0 || StrCmpIW(applet, APPLET_VERIFY) == 0)
        return GetAlgorithmList(APPLET_HASH);
}


static LRESULT CALLBACK BrowseCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    /**
     * @brief Open file dialog and set selected file path to szFilePath
     */

    if (message != WM_LBUTTONUP)
        return CallWindowProc((WNDPROC)pBtnProc, hWnd, message, wParam, lParam);

    UIOperationContext *ui = (UIOperationContext *)GetWindowLongPtr(hWnd, GWLP_USERDATA);

    OPENFILENAME ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = ui->szKeyPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = ui->szFilter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    GetOpenFileName(&ofn);
    SetWindowText(ui->hKeyPath, ui->szKeyPath);

    return 0;
}


static LRESULT CALLBACK ExecuteCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message != WM_LBUTTONUP)
        return CallWindowProc((WNDPROC)pBtnProc, hWnd, message, wParam, lParam);

    UIOperationContext *data = (UIOperationContext *) GetWindowLongPtr(hWnd, GWLP_USERDATA);
    return ExecuteOperation(data);
}


static LRESULT CALLBACK CancelCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message != WM_LBUTTONUP)
        return CallWindowProc((WNDPROC)pBtnProc, hWnd, message, wParam, lParam);

    NTSTATUS *pStatus = (NTSTATUS *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    *pStatus = STATUS_SUCCESS;
    return 0;
}


NTSTATUS CreateKeyedOperationWindow(HINSTANCE hInstance, LPCWSTR applet, LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * @brief Create window for file operation applets (with key select dialog)
     */

    NTSTATUS result = STATUS_PENDING;
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"ZCU";
    RegisterClass(&wc);

    POINT pt;
    GetCursorPos(&pt);

    HWND hWnd = CreateWindow(wc.lpszClassName, applet, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, pt.x, pt.y, WIDTH, HEIGHT, NULL, NULL, hInstance, NULL);
    if (hWnd == NULL)
        return STATUS_UNSUCCESSFUL;

    // Filter for key file dialog
    LPCWSTR szFilter = GetFilterString(applet);
    // Algorithm list for dropdown
    LPCWSTR *pszAlgorithmList = GetAlgorithmList(applet);
    // Mode (enc), Hash (sig) list for dropdown
    LPCWSTR *pszModeList = GetModeList(applet);

/* -----------------------------------  GUI Elements  ------------------------------------- */

    UIOperationContext ui = {&result, applet, pszFilesList, dwFilesCount, NULL, NULL, NULL, NULL, NULL, NULL, szFilter, L"Select file..."};

    // Add key file path label
    CreateWindow(L"STATIC", L"Key File:", WS_CHILD | WS_VISIBLE, 10, 10, 80, 20, hWnd, NULL, hInstance, NULL);

    // Add key file path input (with Browse...)
    ui.hKeyPath = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 10 + 80 + 10, 10,
                               WIDTH / 2, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hKeyPath == NULL) return STATUS_UNSUCCESSFUL;

    // Set input to update on typing
    SendMessage(ui.hKeyPath, EM_SETSEL, 0, -1);
    SendMessage(ui.hKeyPath, EM_SETLIMITTEXT, MAX_PATH, 0);

    // Add Browse button
    ui.hBrowse = CreateWindow(L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                              10 + 80 + 10 + WIDTH / 2 + 2, 10, 70, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hBrowse == NULL) return STATUS_UNSUCCESSFUL;

    // Browse callback
    SetWindowLongPtr(ui.hBrowse, GWLP_USERDATA, (LONG_PTR) &ui);
    SetWindowLongPtr(ui.hBrowse, GWLP_WNDPROC, (LONG_PTR) BrowseCallback);

    // Add algorithm label
    CreateWindow(L"STATIC", L"Algorithm:", WS_CHILD | WS_VISIBLE, 10, 40, 80, 20, hWnd, NULL, hInstance, NULL);

    // Add algorithm dropdown selection
    ui.hAlgorithm = CreateWindow(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 10 + 80 + 10, 40, WIDTH * 2 / 7 + 10, HEIGHT * 2, hWnd, NULL, hInstance, NULL);
    if (ui.hAlgorithm == NULL) return STATUS_UNSUCCESSFUL;

    // Add algorithms to dropdown
    for (DWORD i = 0; pszAlgorithmList[i] != NULL; i++)
        SendMessage(ui.hAlgorithm, CB_ADDSTRING, 0, (LPARAM)pszAlgorithmList[i]);

    // Set default algorithm
    SendMessage(ui.hAlgorithm, CB_SETCURSEL, 0, 0);

    // Mode or hash algorithm
    if (StrCmpIW(applet, APPLET_ENCRYPT) == 0 || StrCmpIW(applet, APPLET_DECRYPT) == 0)
        CreateWindow(L"STATIC", L"Mode:", WS_CHILD | WS_VISIBLE, 10, 70, 80, 20, hWnd, NULL, hInstance, NULL);
    else
        CreateWindow(L"STATIC", L"Hash:", WS_CHILD | WS_VISIBLE, 10, 70, 80, 20, hWnd, NULL, hInstance, NULL);

    // Add mode dropdown selection
    ui.hMode = CreateWindow(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 10 + 80 + 10, 70, WIDTH * 2 / 7 + 10, HEIGHT * 2, hWnd, NULL, hInstance, NULL);
    if (ui.hMode == NULL) return STATUS_UNSUCCESSFUL;

    // Add modes to dropdown
    for (DWORD i = 0; pszModeList[i] != NULL; i++)
        SendMessage(ui.hMode, CB_ADDSTRING, 0, (LPARAM)pszModeList[i]);

    // Set default mode
    SendMessage(ui.hMode, CB_SETCURSEL, 0, 0);

    // OK: Form a command line and execute the operation
    ui.hOK = CreateWindow(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, WIDTH - 70 - 10 - 70 - 10, 100, 70, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hOK == NULL) return STATUS_UNSUCCESSFUL;

    // Get pointer to original window procedure for buttons
    pBtnProc = GetWindowLongPtr(ui.hOK, GWLP_WNDPROC);

    // OK callback
    SetWindowLongPtr(ui.hOK, GWLP_USERDATA, (LONG_PTR)&ui);
    SetWindowLongPtr(ui.hOK, GWLP_WNDPROC, (LONG_PTR)ExecuteCallback);

    // Cancel: Close the window
    ui.hCancel = CreateWindow(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, WIDTH - 70 - 10, 100, 70, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hCancel == NULL) return STATUS_UNSUCCESSFUL;

    // Cancel callback
    SetWindowLongPtr(ui.hCancel, GWLP_USERDATA, (LONG_PTR)&result);
    SetWindowLongPtr(ui.hCancel, GWLP_WNDPROC, (LONG_PTR)CancelCallback);

/* ---------------------------------------------------------------------------------------- */

    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (result != STATUS_PENDING) {
            DestroyWindow(hWnd);
            break;
        }
    }

    if (result == STATUS_PENDING)
        result = STATUS_SUCCESS;

    return result;
}


NTSTATUS CreateAlgorithmSelectWindow(HINSTANCE hInstance, LPCWSTR applet, LPWSTR *pszFilesList, DWORD dwFilesCount) {
    /**
     * @brief Simpler window just to select algorithm
     */

    NTSTATUS result = STATUS_PENDING;
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"ZCU";
    RegisterClass(&wc);

    POINT pt;
    GetCursorPos(&pt);

    HWND hWnd = CreateWindow(wc.lpszClassName, applet, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, pt.x, pt.y, WIDTH_SMALL, HEIGHT_SMALL, NULL, NULL, hInstance, NULL);
    if (hWnd == NULL)
        return STATUS_UNSUCCESSFUL;

    // Algorithm list for dropdown
    LPCWSTR *pszAlgorithmList = GetAlgorithmList(applet);

/* -----------------------------------  GUI Elements  ------------------------------------- */

    UIOperationContext ui = {&result, applet, pszFilesList, dwFilesCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL, L""};

    // Add algorithm label
    CreateWindow(L"STATIC", L"Algorithm:", WS_CHILD | WS_VISIBLE, 10, 30, 80, 20, hWnd, NULL, hInstance, NULL);

    // Add algorithm dropdown selection
    ui.hAlgorithm = CreateWindow(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 10 + 80 + 10, 30, WIDTH_SMALL / 3 + 20, HEIGHT_SMALL * 2, hWnd, NULL, hInstance, NULL);
    if (ui.hAlgorithm == NULL) return STATUS_UNSUCCESSFUL;

    // Add algorithms to dropdown
    for (DWORD i = 0; pszAlgorithmList[i] != NULL; i++)
        SendMessage(ui.hAlgorithm, CB_ADDSTRING, 0, (LPARAM)pszAlgorithmList[i]);

    // Set default algorithm
    SendMessage(ui.hAlgorithm, CB_SETCURSEL, 0, 0);

    // OK: Form a command line and execute the operation
    ui.hOK = CreateWindow(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, WIDTH_SMALL - 70 - 10 - 70 - 10, HEIGHT_SMALL - 52, 70, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hOK == NULL) return STATUS_UNSUCCESSFUL;

    // Get pointer to original window procedure for buttons
    pBtnProc = GetWindowLongPtr(ui.hOK, GWLP_WNDPROC);

    // OK callback
    SetWindowLongPtr(ui.hOK, GWLP_USERDATA, (LONG_PTR)&ui);
    SetWindowLongPtr(ui.hOK, GWLP_WNDPROC, (LONG_PTR)ExecuteCallback);

    // Cancel: Close the window
    ui.hCancel = CreateWindow(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, WIDTH_SMALL - 70 - 10, HEIGHT_SMALL - 52, 70, 20, hWnd, NULL, hInstance, NULL);
    if (ui.hCancel == NULL) return STATUS_UNSUCCESSFUL;

    // Cancel callback
    SetWindowLongPtr(ui.hCancel, GWLP_USERDATA, (LONG_PTR)&result);
    SetWindowLongPtr(ui.hCancel, GWLP_WNDPROC, (LONG_PTR)CancelCallback);

/* ---------------------------------------------------------------------------------------- */

    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (result != STATUS_PENDING) {
            DestroyWindow(hWnd);
            break;
        }
    }

    if (result == STATUS_PENDING)
        result = STATUS_SUCCESS;

    return result;
}