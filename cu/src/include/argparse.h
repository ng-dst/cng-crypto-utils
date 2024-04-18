#pragma once

#include <windows.h>


// Command enumeration for argument parser
typedef enum {
    CMD_ENCRYPT,
    CMD_DECRYPT,
    CMD_SIGN,
    CMD_VERIFY,
    CMD_HASH,
    CMD_GEN_KEY,
    CMD_GEN_PAIR
} COMMAND;


// All possible parameters (filled by parser)
typedef struct {
    COMMAND command;
    LPTSTR szInFile;
    LPTSTR szKeyFile;
    LPTSTR szOutFile;
    LPTSTR szPrivKeyFile;
    LPTSTR szSigFile;
    LPTSTR szPubKeyFile;
    LPWSTR szAlgorithm;
    LPWSTR szMode;
    LPWSTR szHashAlgorithm;
    LPWSTR szSigAlgorithm;
    DWORD cbKeySize;
} ARGUMENTS;


/**
 * @brief Free memory allocated for arguments
 */
void CleanupArgs(ARGUMENTS *args_struct);


/**
 * @brief Fill ARGUMENTS structure with parsed arguments from command line
 *
 * @param argc: Argument count
 * @param argv: Argument values
 * @param args_struct: Pointer to ARGUMENTS structure
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS ParseArgs(DWORD argc, LPTSTR *argv, ARGUMENTS *args_struct);
