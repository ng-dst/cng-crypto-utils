#pragma once

#include <windows.h>


#define STATUS_WRONG_ENCRYPTION_KEY ((NTSTATUS)0xC00002ABL)

/**
 * @brief Print error message for NTSTATUS
 */
void PrintNTStatusError(NTSTATUS status);


/**
 * @brief Print usage information
 */
VOID PrintUsage();


/**
 * @brief Print supported algorithms
 */
VOID PrintAlgos();
