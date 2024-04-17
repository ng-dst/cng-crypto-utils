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
