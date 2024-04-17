#include <tchar.h>
#include <windows.h>
#include <locale.h>

#include "argparse.h"
#include "work.h"


int wmain(int argc, LPTSTR *argv) {
    /**
     * @brief Main: parse args and execute appropriate command
     */

    setlocale(LC_ALL, "");
    ARGUMENTS args_struct = {0};

    // Parse arguments
    NTSTATUS status = ParseArgs(argc, argv, &args_struct);
    if (status != STATUS_PENDING)
        return status;

    // Execute command
    status = ExecCommand(&args_struct);

    CleanupArgs(&args_struct);

    return status;
}
