#pragma once

#include <ntdef.h>

#include "argparse.h"


/**
 * @brief Execute command based on ARGUMENTS struct
 *
 * @param args: Parsed arguments
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS ExecCommand(ARGUMENTS *args);
