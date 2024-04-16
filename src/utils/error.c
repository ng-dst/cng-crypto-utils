/**
 * @file error.c
 *
 * Print messages (errors, usage, etc.)
 */

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "error.h"


void PrintNTStatusError(NTSTATUS status) {
    /**
     * @brief Print error message for NTSTATUS
     */

    // Custom NTSTATUS error
    if (status == STATUS_WRONG_ENCRYPTION_KEY) {
        _ftprintf(stderr, _T("Error: Wrong encryption key, algorithm, or chaining mode\n(Code: 0x%08lx)\n"), status);
        return;
    }

    // Use NtDll to display errors
    LPTSTR pMsgBuf = NULL;
    HMODULE hNtDll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtDll == INVALID_HANDLE_VALUE) {
        // Fallback to error code
        _ftprintf(stderr, _T("Error: 0x%08lx\n"), status);
        return;
    }

    FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            hNtDll,
            status,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPVOID) &pMsgBuf,
            0, NULL);

    _ftprintf(stderr, _T("Error: %S(Code: 0x%08lx)\n"), pMsgBuf ? pMsgBuf : _T("unknown"), status);

    LocalFree(pMsgBuf);
    CloseHandle(hNtDll);
}


VOID PrintUsage() {
    /**
     * @brief Print usage information
     */

    _tprintf(_T("Lab 3: Cryptography utilities\n"));
    _tprintf(_T("\n"));
    _tprintf(_T("Encryption:\n"));
    _tprintf(_T("    lab3.exe encrypt <in_file> <key_file> [-o <out_file>] [-a <algorithm>] [-m <mode>]\n"));
    _tprintf(_T("    lab3.exe decrypt <in_file> <key_file> [-o <out_file>] [-a <algorithm>] [-m <mode>]\n"));
    _tprintf(_T("\n"));
    _tprintf(_T("Signature:\n"));
    _tprintf(_T("    lab3.exe sign <in_file> <priv_key_file> [-o <out_file>] [-a <hash_algorithm>] [-s <sig_algorithm>]\n"));
    _tprintf(_T("    lab3.exe verify <in_file> <pub_key_file> [sig_file] [-a <hash_algorithm>] [-s <sig_algorithm>]\n"));
    _tprintf(_T("\n"));
    _tprintf(_T("Hash:\n"));
    _tprintf(_T("    lab3.exe hash <in_file> [-a <algorithm>]\n"));
    _tprintf(_T("\n"));
    _tprintf(_T("Key generation:\n"));
    _tprintf(_T("    lab3.exe gen-key -c <key_size_bits> [-iv <iv_size>] [out_file]\n"));
    _tprintf(_T("    lab3.exe gen-pair -c <key_size_bits> -s <sig_algorithm> [priv_out_file] [pub_out_file]\n"));
    _tprintf(_T("\n"));
    _tprintf(_T("Algorithms list:\n"));
    _tprintf(_T("    lab3.exe algo\n"));
    _tprintf(_T("Help:\n"));
    _tprintf(_T("    lab3.exe [help / -h]\n"));
}


VOID PrintAlgos() {
    /**
     * @brief Print supported algorithms
    */

    _tprintf(_T("Encryption:\n"));
    _tprintf(_T("    AES (default)\n"));
    _tprintf(_T("    DES\n"));
    _tprintf(_T("    DESX\n"));
    _tprintf(_T("    3DES\n"));
    _tprintf(_T("    RC2\n"));
    _tprintf(_T("    RC4\n"));
    _tprintf(_T("\n"));

    _tprintf(_T("Modes:\n"));
    _tprintf(_T("    CBC (default)\n"));
    _tprintf(_T("    CFB\n"));
    _tprintf(_T("    ECB\n"));
    _tprintf(_T("\n"));

    _tprintf(_T("Hashing:\n"));
    _tprintf(_T("    SHA256 (default)\n"));
    _tprintf(_T("    SHA384\n"));
    _tprintf(_T("    SHA512\n"));
    _tprintf(_T("    SHA1\n"));
    _tprintf(_T("    SHA3\n"));
    _tprintf(_T("    MD5\n"));
    _tprintf(_T("\n"));

    _tprintf(_T("Signature:\n"));
    _tprintf(_T("    ECDSA_P256 (default)\n"));
    _tprintf(_T("    ECDSA_P384\n"));
    _tprintf(_T("    ECDSA_P521\n"));
    _tprintf(_T("    ECDH_P256\n"));
    _tprintf(_T("    ECDH_P384\n"));
    _tprintf(_T("    ECDH_P521\n"));
    _tprintf(_T("    RSA\n"));
    _tprintf(_T("    DSA\n"));
    _tprintf(_T("\n"));
}