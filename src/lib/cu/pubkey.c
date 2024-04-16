/**
 * @file pubkey.c
 *
 * Asymmetric key pairs (generate, import, export)
 */

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"


NTSTATUS CU_GenerateKeyPairBlob(LPCWSTR szAlgo, DWORD dwKeySize, LPBYTE *pbPubBlob, DWORD *pcbPubBlobSize, LPBYTE *pbPrivBlob, DWORD *pcbPrivBlobSize) {
    /**
     * @brief Generate asymmetric key pair blobs
     *
     * @param szAlgo: Algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
     * @param dwKeySize: Key size in bits
     * @param pbPubBlob: Pointer to public key blob buffer
     * @param pcbPubBlobSize: Public key blob buffer size
     * @param pbPrivBlob: Pointer to private key blob buffer
     * @param pcbPrivBlobSize: Private key blob buffer size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbPubBlob = 0;
    DWORD cbPrivBlob = 0;
    DWORD cbResult = 0;

    // Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, szAlgo, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Generate key pair
    status = BCryptGenerateKeyPair(hAlg, &hKey, dwKeySize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Finalize key pair
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Prepare to export public key
    status = BCryptExportKey(hKey, NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, 0, &cbPubBlob, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for public key blob
    *pbPubBlob = (LPBYTE)malloc(cbPubBlob);
    if (*pbPubBlob == NULL) goto Cleanup;

    // Export public key
    status = BCryptExportKey(hKey, NULL, BCRYPT_PUBLIC_KEY_BLOB, *pbPubBlob, cbPubBlob, &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *pcbPubBlobSize = cbResult;

    // Prepare to export private key
    status = BCryptExportKey(hKey, NULL, BCRYPT_PRIVATE_KEY_BLOB, NULL, 0, &cbPrivBlob, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for private key blob
    *pbPrivBlob = (LPBYTE)malloc(cbPrivBlob);
    if (*pbPrivBlob == NULL) goto Cleanup;

    // Export private key
    status = BCryptExportKey(hKey, NULL, BCRYPT_PRIVATE_KEY_BLOB, *pbPrivBlob, cbPrivBlob, &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *pcbPrivBlobSize = cbResult;

    Cleanup:

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return status;
}


NTSTATUS CU_ExportKeyPairBlob(LPTSTR szPubPath, LPTSTR szPrivPath, LPBYTE pbPubBlob, DWORD cbPubBlobSize, LPBYTE pbPrivBlob, DWORD cbPrivBlobSize) {
    /**
     * @brief Export key pair blobs to files
     *
     * @param szPubPath: Public key file path
     * @param szPrivPath: Private key file path
     * @param pbPubBlob: Public key blob buffer
     * @param cbPubBlobSize: Public key blob buffer size
     * @param pbPrivBlob: Private key blob buffer
     * @param cbPrivBlobSize: Private key blob buffer size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hPubFile = INVALID_HANDLE_VALUE;
    HANDLE hPrivFile = INVALID_HANDLE_VALUE;
    DWORD cbWritten = 0;

    // Open public key file
    hPubFile = CreateFile(szPubPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPubFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not create key file (%lu): '%S'\n"), GetLastError(), szPubPath);
        goto Cleanup;
    }

    // Write public key blob to file
    if (!WriteFile(hPubFile, pbPubBlob, cbPubBlobSize, &cbWritten, NULL))
        goto Cleanup;

    // Open private key file
    hPrivFile = CreateFile(szPrivPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPrivFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not create key file (%lu): '%S'\n"), GetLastError(), szPrivPath);
        goto Cleanup;
    }

    // Write private key blob to file
    if (!WriteFile(hPrivFile, pbPrivBlob, cbPrivBlobSize, &cbWritten, NULL))
        goto Cleanup;

    status = STATUS_SUCCESS;

    Cleanup:

    if (hPubFile != INVALID_HANDLE_VALUE) CloseHandle(hPubFile);
    if (hPrivFile != INVALID_HANDLE_VALUE) CloseHandle(hPrivFile);

    return status;
}


NTSTATUS CU_ImportAsymmetricKeyBlob(LPTSTR szPath, LPBYTE *pbBlob, DWORD *pcbBlobSize) {
    /**
     * @brief (For internal use)
     * Just allocate and read raw blob from file.
     *
     * @param szPath: Public key file path
     * @param pbPubBlob: Pointer to get public key blob to
     * @param pcbPubBlobSize: Pointer to get public key blob size to
     *
     * @return NTSTATUS (0 on success)
     */

    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD cbRead = 0;
    DWORD cbFileSize;

    // Open file for reading
    hFile = CreateFile(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _ftprintf(stderr, _T("File error: Could not open key file (%lu): '%S'\n"), GetLastError(), szPath);
        return STATUS_UNSUCCESSFUL;
    }

    // Allocate memory for key blob
    cbFileSize = GetFileSize(hFile, NULL);
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
    CloseHandle(hFile);

    return STATUS_SUCCESS;
}
