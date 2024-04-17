/**
 * @file hash.c
 *
 * Hashing files
 */

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"


NTSTATUS CU_HashFile(LPCTSTR szFile, LPCWSTR szAlg, LPBYTE *pbHash, DWORD *pcbHashSize) {
    /**
     * @brief Get file hash using the specified algorithm
     *
     * @param szFile: File path
     * @param szAlg: Algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
     * @param pbHash: Pointer to get hash buffer to
     * @param pcbHashSize: Pointer to get hash size to
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashSize = 0;
    DWORD cbResult = 0;
    DWORD cbDataSize = 0;
    DWORD cbBlockSize;
    DWORD cbChunkSize;
    PBYTE pbData = NULL;
    PBYTE pbHashObject = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Open file handle
    hFile = CreateFile(szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not open input file (%lu): '%S'\n"), GetLastError(), szFile);
        return STATUS_UNSUCCESSFUL;
    }

    // Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, szAlg, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Calculate hash object size
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Get hash block size
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_BLOCK_LENGTH, (PBYTE)&cbBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Set chunk size
    // (any constant or multiple of block size)
    cbChunkSize = cbBlockSize * CHUNK_SIZE_BLOCKS;

    // Allocate memory for hash object
    pbHashObject = (PBYTE)malloc(cbHashSize);
    if (pbHashObject == NULL) goto Cleanup;

    // Create hash object
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashSize, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate hash buffer
    pbData = (PBYTE)malloc(cbChunkSize);
    if (pbData == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }

    // Perform hashing
    do {
        if (!ReadFile(hFile, pbData, cbChunkSize, &cbDataSize, NULL)) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
        // Hash file data
        status = BCryptHashData(hHash, pbData, cbDataSize, 0);
        if (!NT_SUCCESS(status)) goto Cleanup;
    } while (cbDataSize > 0);

    // Get hash length
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHashSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for hash
    *pbHash = (LPBYTE)malloc(cbHashSize);
    if (*pbHash == NULL) goto Cleanup;

    // Finalize hash
    status = BCryptFinishHash(hHash, *pbHash, cbHashSize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *pcbHashSize = cbHashSize;

    Cleanup:

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbData) { SecureZeroMemory(pbData, cbDataSize); free(pbData); }
    if (pbHashObject) { SecureZeroMemory(pbHashObject, cbHashSize); free(pbHashObject); }
    CloseHandle(hFile);

    return status;
}


LPTSTR CU_BytesToHex(LPBYTE pbBuf, DWORD cbBufSize) {
    /**
     * @brief Convert hash buffer to hex string
     *
     * @param pbHash: Hash buffer
     * @param cbHashSize: Hash buffer size
     *
     * @return LPTSTR: Hex string
     */

    LPTSTR szHex = NULL;
    DWORD i;

    // Allocate memory for hex string
    szHex = (LPTSTR) malloc(2 * cbBufSize * sizeof(TCHAR) + 1);
    if (szHex == NULL) return NULL;

    // Convert hash to hex string
    for (i = 0; i < cbBufSize; i++)
        _stprintf_s(&szHex[i * 2], 2 + 1, _T("%02x"), (TCHAR) pbBuf[i]);

    return szHex;
}
