/**
 * @file argparse.c
 * 
 * Command line argument parser and driver
 */

#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <tchar.h>

#include "cu.h"

#include "error.h"
#include "argparse.h"

#define ALGO_NAME_MAX_LENGTH 64
#define MODE_PREFIX L"ChainingMode"


VOID CleanupArgs(ARGUMENTS *args_struct) {
    /**
     * @brief Free memory allocated for arguments
     */

    if (args_struct->szAlgorithm) free((LPVOID) args_struct->szAlgorithm);
    if (args_struct->szMode) free((LPVOID) args_struct->szMode);
    if (args_struct->szHashAlgorithm) free((LPVOID) args_struct->szHashAlgorithm);
    if (args_struct->szSigAlgorithm) free((LPVOID) args_struct->szSigAlgorithm);
    if (args_struct->szInFile) free((LPVOID) args_struct->szInFile);
    if (args_struct->szKeyFile) free((LPVOID) args_struct->szKeyFile);
    if (args_struct->szOutFile) free((LPVOID) args_struct->szOutFile);
    if (args_struct->szPrivKeyFile) free((LPVOID) args_struct->szPrivKeyFile);
    if (args_struct->szPubKeyFile) free((LPVOID) args_struct->szPubKeyFile);
    if (args_struct->szSigFile) free((LPVOID) args_struct->szSigFile);
}


NTSTATUS ParseArgs(DWORD argc, LPTSTR *argv, ARGUMENTS *args_struct) {
    /**
     * @brief Form a structure with parsed arguments
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // No arguments
    if (argc < 2) {
        _tprintf(_T("No arguments provided. Use 'help' command for usage\n"));
        return STATUS_SUCCESS;
    }

    // Cut two leading hyphens if present
    if (_tcsncmp(argv[1], _T("--"), 2) == 0)
        argv[1] += 2;

    // Parse command
    if (_tcscmp(argv[1], _T("encrypt")) == 0) {
        args_struct->command = CMD_ENCRYPT;
    } else if (_tcscmp(argv[1], _T("decrypt")) == 0) {
        args_struct->command = CMD_DECRYPT;
    } else if (_tcscmp(argv[1], _T("sign")) == 0) {
        args_struct->command = CMD_SIGN;
    } else if (_tcscmp(argv[1], _T("verify")) == 0) {
        args_struct->command = CMD_VERIFY;
    } else if (_tcscmp(argv[1], _T("hash")) == 0) {
        args_struct->command = CMD_HASH;
    } else if (_tcscmp(argv[1], _T("gen-key")) == 0) {
        args_struct->command = CMD_GEN_KEY;
    } else if (_tcscmp(argv[1], _T("gen-pair")) == 0) {
        args_struct->command = CMD_GEN_PAIR;
    } else if (_tcscmp(argv[1], _T("algo")) == 0) {
        PrintAlgos();
        return STATUS_SUCCESS;
    } else if (_tcscmp(argv[1], _T("help")) == 0 || _tcscmp(argv[1], _T("-h")) == 0) {
        PrintUsage();
        return STATUS_SUCCESS;
    } else {
        _tprintf(_T("Unknown command: %S\n"), argv[1]);
        return STATUS_INVALID_PARAMETER;
    }

    // Positional parameters
    LPTSTR param1 = NULL;
    LPTSTR param2 = NULL;
    LPTSTR param3 = NULL;

    // Parse arguments with flags: -o, -a, -m, -s, -c
    for (DWORD i = 2; i < argc; i++) {
        if (_tcscmp(argv[i], _T("-o")) == 0) {
            if (i + 1 < argc) {
                args_struct->szOutFile = _tcsdup(argv[i + 1]);
                if (args_struct->szOutFile == NULL) goto Cleanup;
                i++;
            }

            // Algorithm
        } else if (_tcscmp(argv[i], _T("-a")) == 0) {
            if (i + 1 < argc) {
#ifdef _UNICODE
                args_struct->szAlgorithm = wcsdup(argv[i + 1]);
                if (args_struct->szAlgorithm == NULL) goto Cleanup;
#else
                LPWSTR convertedAlgo = malloc(ALGO_NAME_MAX_LENGTH * sizeof(WCHAR));
                if (convertedAlgo == NULL || !MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, convertedAlgo, ALGO_NAME_MAX_LENGTH))
                    goto Cleanup;
                args_struct->szAlgorithm = convertedAlgo;
#endif
                args_struct->szHashAlgorithm = wcsdup(args_struct->szAlgorithm);
                i++;
            }

            // Mode
        } else if (_tcscmp(argv[i], _T("-m")) == 0) {
            if (i + 1 < argc) {
#ifdef _UNICODE
                // Prepend "ChainingMode" to mode
                args_struct->szMode = malloc((wcslen(argv[i + 1]) + wcslen(MODE_PREFIX)) * sizeof(WCHAR));
                if (args_struct->szMode == NULL) goto Cleanup;
                wcscpy(args_struct->szMode, MODE_PREFIX);
                wcscat(args_struct->szMode, argv[i + 1]);
#else
                LPWSTR convertedMode = malloc(ALGO_NAME_MAX_LENGTH * sizeof(WCHAR));
                if (convertedMode == NULL) goto Cleanup;
                wcscpy(convertedMode, MODE_PREFIX);
                if (!MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, convertedMode + wcslen(MODE_PREFIX), ALGO_NAME_MAX_LENGTH))
                    goto Cleanup;
                args_struct->szMode = convertedMode;
#endif
                i++;
            }

            // Signature algorithm
        } else if (_tcscmp(argv[i], _T("-s")) == 0) {
            if (i + 1 < argc) {
#ifdef _UNICODE
                args_struct->szSigAlgorithm = wcsdup(argv[i + 1]);
                if (args_struct->szSigAlgorithm == NULL) goto Cleanup;
#else
                LPWSTR convertedSigAlgo = malloc(ALGO_NAME_MAX_LENGTH * sizeof(WCHAR));
                if (convertedSigAlgo == NULL || !MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, convertedSigAlgo, ALGO_NAME_MAX_LENGTH))
                    goto Cleanup;
                args_struct->szSigAlgorithm = convertedSigAlgo;
#endif
                i++;
            }

            // Key size
        } else if (_tcscmp(argv[i], _T("-c")) == 0) {
            if (i + 1 < argc) {
                args_struct->cbKeySize = _tcstoul(argv[i + 1], NULL, 0);
                i++;
            }

            // Positional parameters
        } else {
            if      (param1 == NULL) param1 = argv[i];
            else if (param2 == NULL) param2 = argv[i];
            else if (param3 == NULL) param3 = argv[i];
            else {
                _tprintf(_T("Too many positional parameters. Use 'help' command for usage\n"));
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    // Fill structure with positional parameters
    switch (args_struct->command) {
        case CMD_ENCRYPT:
        case CMD_DECRYPT:
            if (param1) args_struct->szInFile = _tcsdup(param1);
            if (param2) args_struct->szKeyFile = _tcsdup(param2);
            break;

        case CMD_SIGN:
            if (param1) args_struct->szInFile = _tcsdup(param1);
            if (param2) args_struct->szPrivKeyFile = _tcsdup(param2);
            break;

        case CMD_VERIFY:
            if (param1) args_struct->szInFile = _tcsdup(param1);
            if (param2) args_struct->szPubKeyFile = _tcsdup(param2);
            if (param3) args_struct->szSigFile = _tcsdup(param3);
            break;

        case CMD_HASH:
            if (param1) args_struct->szInFile = _tcsdup(param1);
            break;

        case CMD_GEN_KEY:
            if (param1) args_struct->szKeyFile = _tcsdup(param1);
            break;

        case CMD_GEN_PAIR:
            if (param1) args_struct->szPrivKeyFile = _tcsdup(param1);
            if (param2) args_struct->szPubKeyFile = _tcsdup(param2);
            // Allow -a option as well as -s
            if (args_struct->szSigAlgorithm == NULL && args_struct->szAlgorithm != NULL)
                args_struct->szSigAlgorithm = wcsdup(args_struct->szAlgorithm);
    }

    // Tell main to continue execution
    return STATUS_PENDING;

    Cleanup:

    CleanupArgs(args_struct);
    return status;
}
