/**
 * @file main.c
 *
 * GUI entry point for context menu
 */

#include <windows.h>
#include <shlwapi.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <locale.h>
#include <strsafe.h>

#include "applets.h"


#define MAX_ERROR_MSG_LENGTH 256


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    /**
     * @brief Main entry point for GUI
     */

    setlocale(LC_ALL, "");

    // Get args (command, all file names)
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL)
        return EXIT_FAILURE;

    // Check if we have any arguments
    if (argc < 2) {
        MessageBox(NULL, L"Usage: zcu.exe <command> [files...]\n\nCommands:\n  encrypt, decrypt, sign, verify, hash, gen-key, gen-pair", L"zCU", MB_ICONERROR | MB_SYSTEMMODAL);
        LocalFree(argv);
        return EXIT_FAILURE;
    }

    // Execute GUI applet

    NTSTATUS status = STATUS_NOINTERFACE;

    if (StrCmpIW(argv[1], L"encrypt") == 0 && argc >= 3)
        status = ZCU_EncryptWindow(argv + 2, argc - 2);

    else if (StrCmpIW(argv[1], L"decrypt") == 0 && argc >= 3)
        status = ZCU_DecryptWindow(argv + 2, argc - 2);

    else if (StrCmpIW(argv[1], L"sign") == 0 && argc >= 3)
        status = ZCU_SignWindow(argv + 2, argc - 2);

    else if (StrCmpIW(argv[1], L"verify") == 0 && argc >= 3)
        status = ZCU_VerifyWindow(argv + 2, argc - 2);

    else if (StrCmpIW(argv[1], L"hash") == 0 && argc >= 3)
        status = ZCU_HashWindow(argv + 2, argc - 2);

    else if (StrCmpIW(argv[1], L"gen-key") == 0)
        status = ZCU_GenKeyWindow();

    else if (StrCmpIW(argv[1], L"gen-pair") == 0)
        status = ZCU_GenPairWindow();
    else
        MessageBox(NULL, L"Invalid command", L"Error", MB_ICONERROR | MB_SYSTEMMODAL);

    PostQuitMessage(status);
    LocalFree(argv);
    return status;
}