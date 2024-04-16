/**
 * @file encrypt.c
 *
 * Encryption and decryption of files
 */

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"


// internal function
static NTSTATUS EncDecFile(LPCTSTR szFileIn, LPCTSTR szFileOut,
                           LPCWSTR szAlgo, LPCWSTR szMode,
                           LPBYTE pbKeyBlob, DWORD cbKeyBlobSize,
                           LPBYTE pbIv, DWORD cbIvSize, BOOL bDecrypt) {
    /**
     * @brief (for internal use)
     *
     * Encrypt / Decrypt file using symmetric algorithm
     *
     * @param szFileIn: Input file path
     * @param szFileOut: Output file path
     * @param szAlgo: Algorithm name (e.g. BCRYPT_AES_ALGORITHM)
     * @param szMode: Chaining mode (e.g. BCRYPT_CHAIN_MODE_CBC)
     * @param pbKeyBlob: Key blob buffer
     * @param cbKeyBlobSize: Key blob size
     * @param pbIv: IV buffer
     * @param cbIvSize: IV size
     * @param bDecrypt: Decrypt? (0 = Encrypt, 1 = Decrypt)
     */
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbBlockLen = 0;
    DWORD cbData = 0;
    DWORD cbOutTextSize = 0;
    DWORD cbInTextSize = 0;
    DWORD dwFlags = 0;
    PBYTE pbOutText = NULL;
    PBYTE pbInText = NULL;

    // Open file handles
    HANDLE hFileIn = CreateFile(szFileIn, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileIn == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not open input file (%lu): '%S'\n"), GetLastError(), szFileIn);
        return STATUS_UNSUCCESSFUL;
    }
    HANDLE hFileOut = CreateFile(szFileOut, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileOut == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not create output file (%lu): '%S'\n"), GetLastError(), szFileOut);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, szAlgo, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Check if key blob is valid (not null, correct magic)
    if (pbKeyBlob == NULL || ((BCRYPT_KEY_DATA_BLOB_HEADER*) pbKeyBlob)->dwMagic != BCRYPT_KEY_DATA_BLOB_MAGIC) {
        _ftprintf(stderr, _T("Bad parameter: Invalid key blob\n"));
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // Set chaining mode
    if (szMode != NULL) {
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)szMode, (DWORD)(wcslen(szMode) + 1) * sizeof(WCHAR), 0);
        if (!NT_SUCCESS(status)) goto Cleanup;
    }

    // Import key from blob
    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, pbKeyBlob, cbKeyBlobSize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Get block length
    status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Set chunk size to read / write
    // (any multiple of block size)
    DWORD cbChunkSize = cbBlockLen * CHUNK_SIZE_BLOCKS;

    // Allocate buffers
    pbInText = (PBYTE)malloc(cbChunkSize);
    if (pbInText == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
    pbOutText = (PBYTE)malloc(cbChunkSize + cbBlockLen);  // Extra block for padding
    if (pbOutText == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }

    // Perform encryption in chunks
    DWORD dwBytesLeft = GetFileSize(hFileIn, NULL);
    while (TRUE) {
        // Read a block of data
        if (!ReadFile(hFileIn, pbInText, cbChunkSize, &cbInTextSize, NULL)) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        // Check if we are processing the last block, if so, set the flag in dwFlags
        // Ignore padding if block len == 1  (stream ciphers)
        dwBytesLeft -= cbInTextSize;

        if (cbInTextSize == 0) break;
        if (dwBytesLeft == 0 && cbBlockLen > 1) dwFlags = BCRYPT_BLOCK_PADDING;

        // Encrypt / decrypt the chunk
        if (bDecrypt)
            status = BCryptDecrypt(hKey, pbInText, cbInTextSize, NULL, pbIv, cbIvSize, pbOutText, cbChunkSize, &cbOutTextSize, dwFlags);
        else
            status = BCryptEncrypt(hKey, pbInText, cbInTextSize, NULL, pbIv, cbIvSize, pbOutText, cbChunkSize + cbBlockLen, &cbOutTextSize, dwFlags);

        if (!NT_SUCCESS(status)) goto Cleanup;

        // Write the encrypted chunk
        if (!WriteFile(hFileOut, pbOutText, cbOutTextSize, &cbData, NULL)) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
    }

    Cleanup:

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbInText) { SecureZeroMemory(pbInText, cbInTextSize); free(pbInText); }
    if (pbOutText) { SecureZeroMemory(pbOutText, cbOutTextSize); free(pbOutText); }
    if (hFileOut != INVALID_HANDLE_VALUE) CloseHandle(hFileOut);
    CloseHandle(hFileIn);

    return status;
}


NTSTATUS CU_EncryptFile(LPCTSTR szFileIn, LPCTSTR szFileOut,
                        LPCWSTR szAlgo, LPCWSTR szMode,
                        LPBYTE pbKey, DWORD cbKey,
                        LPBYTE pbIv, DWORD cbIv) {
    /**
     * Redirect to EncDecFile with bDecrypt = FALSE
     */
    return EncDecFile(szFileIn, szFileOut, szAlgo, szMode, pbKey, cbKey, pbIv, cbIv, FALSE);
}


NTSTATUS CU_DecryptFile(LPCTSTR szFileIn, LPCTSTR szFileOut,
                        LPCWSTR szAlgo, LPCWSTR szMode,
                        LPBYTE pbKey, DWORD cbKey,
                        LPBYTE pbIv, DWORD cbIv) {
    /**
     * Redirect to EncDecFile with bDecrypt = TRUE
     */
    return EncDecFile(szFileIn, szFileOut, szAlgo, szMode, pbKey, cbKey, pbIv, cbIv, TRUE);
}
