#pragma once

#include <windows.h>


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
