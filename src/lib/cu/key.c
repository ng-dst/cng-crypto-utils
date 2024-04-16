/**
 * @file key.c
 *
 * Symmetric keys (generate, import, export)
 */

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"


NTSTATUS CU_GetRandomBytes(LPBYTE pbBuffer, DWORD cbBuffer) {
    /**
     * @brief Get random bytes
     *
     * @param pbBuffer: Buffer to store random bytes
     * @param cbBuffer: Buffer size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;

    // Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Generate random bytes
    status = BCryptGenRandom(hAlg, pbBuffer, cbBuffer, 0);

    Cleanup:

    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return status;
}


NTSTATUS CU_CreateKeyBlob(LPCWSTR szAlgo, LPBYTE pbKey, DWORD cbKeySize, LPBYTE *pbKeyBlob, DWORD *pcbKeyBlobSize) {
    /**
     * @brief Make symmetric key blob from key buffer
     *
     * @param szAlgo: Algorithm name (e.g. BCRYPT_AES_ALGORITHM)
     * @param pbKey: Key buffer
     * @param cbKey: Key buffer size
     * @param pbKeyBlob: Pointer to key blob buffer
     * @param cbKeyBlobSize: Key blob buffer size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyBlob = 0;
    DWORD cbResult = 0;

    // Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, szAlgo, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Calculate key blob size
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyBlob, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for key blob
    *pbKeyBlob = (LPBYTE)malloc(cbKeyBlob);
    if (*pbKeyBlob == NULL) goto Cleanup;

    // Generate key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, *pbKeyBlob, cbKeyBlob, pbKey, cbKeySize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Export key
    status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, *pbKeyBlob, cbKeyBlob, &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *pcbKeyBlobSize = cbResult;

    Cleanup:

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return status;
}


NTSTATUS CU_ExportKeyBlob(LPTSTR szPath, LPBYTE pbBlob, DWORD cbBlobSize, LPBYTE pbIv, DWORD cbIvSize) {
    /**
     * @brief Export symmetric key blob to file
     *
     * @param szPath: File path
     * @param pbBlob: Key blob buffer
     * @param cbBlobSize: Key blob buffer size
     * @param pbIv [optional]: IV buffer
     * @param cbIvSize [optional]: IV buffer size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD cbWritten = 0;

    // Open file
    hFile = CreateFile(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not create key file (%lu): '%S'\n"), GetLastError(), szPath);
        return STATUS_UNSUCCESSFUL;
    }

    // Write key blob to file
    if (!WriteFile(hFile, pbBlob, cbBlobSize, &cbWritten, NULL)) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    // Write IV to file
    if (pbIv != NULL && cbIvSize > 0)
        WriteFile(hFile, pbIv, cbIvSize, &cbWritten, NULL);

    status = STATUS_SUCCESS;
    CloseHandle(hFile);
    return status;
}


NTSTATUS CU_ImportSymmetricKeyBlob(LPTSTR szPath, LPBYTE *pbBlob, DWORD *pcbBlobSize, LPBYTE *pbIv, DWORD *pcbIvSize) {
    /**
     * @brief Import symmetric Key + IV blob from file
     *
     * @param szPath: File path
     * @param pbBlob: Pointer to get key blob to
     * @param pcbBlobSize: Pointer to get key blob size to
     * @param pbIv [optional]: Pointer to get IV buffer to
     * @param pcbIvSize [optional]: Pointer to get IV size to
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD cbRead = 0;
    DWORD cbFileSize;

    // Open file
    hFile = CreateFile(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not open key file (%lu): '%S'\n"), GetLastError(), szPath);
        return STATUS_UNSUCCESSFUL;
    }

    // Get file size
    cbFileSize = GetFileSize(hFile, NULL);
    if (cbFileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    // Allocate memory for key blob
    *pbBlob = (LPBYTE)malloc(cbFileSize);
    if (*pbBlob == NULL) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    // Read key blob from file
    if (!ReadFile(hFile, *pbBlob, cbFileSize, &cbRead, NULL)) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    *pcbBlobSize = cbRead;

    // Check if IV is present in blob
    BCRYPT_KEY_DATA_BLOB_HEADER* pBlobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)*pbBlob;
    DWORD cbIvSize = cbFileSize - pBlobHeader->cbKeyData - sizeof(BCRYPT_KEY_DATA_BLOB_HEADER);
    if (cbIvSize > 0 && cbIvSize < cbFileSize) {
        *pbIv = malloc(cbIvSize);
        if (*pbIv == NULL) {
            CloseHandle(hFile);
            return STATUS_UNSUCCESSFUL;
        }
        memcpy(*pbIv, *pbBlob + cbFileSize - cbIvSize, cbIvSize);
        *pcbIvSize = cbIvSize;
    }
    else {
        *pbIv = NULL;
        *pcbIvSize = 0;
    }

    status = STATUS_SUCCESS;
    CloseHandle(hFile);
    return status;
}
