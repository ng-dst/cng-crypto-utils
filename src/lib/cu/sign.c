/**
 * @file sign.c
 *
 * Signing and verifying data
 */

#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"


NTSTATUS CU_SignFile(LPCTSTR szFileIn, LPCTSTR szFileOut, LPCWSTR szHashAlg, LPCWSTR szSignAlg, LPBYTE pbPrivKeyBlob, DWORD cbPrivKeyBlobSize) {
    /**
     * @brief Sign file using asymmetric algorithm
     *
     * @param szFileIn: Input file path
     * @param szFileOut: Signature file path
     * @param szHashAlg: Hash algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
     * @param szSignAlg: Signature algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
     * @param pbPrivKeyBlob: Pointer to private key blob
     * @param cbPrivKeyBlobSize: Private key blob size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hSignAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = {szHashAlg};
    BCRYPT_PKCS1_PADDING_INFO *pPaddingInfo = NULL;
    DWORD cbResult = 0;
    DWORD cbHashSize = 0;
    DWORD cbSignatureSize = 0;
    DWORD dwFlags = 0;
    PBYTE pbHash = NULL;
    PBYTE pbSignature = NULL;
    HANDLE hFileOut = INVALID_HANDLE_VALUE;

    // Get file hash using function
    status = CU_HashFile(szFileIn, szHashAlg, &pbHash, &cbHashSize);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Open signature algorithm handle
    status = BCryptOpenAlgorithmProvider(&hSignAlg, szSignAlg, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Load private key from blob
    status = BCryptImportKeyPair(hSignAlg, NULL, BCRYPT_PRIVATE_KEY_BLOB, &hKey, pbPrivKeyBlob, cbPrivKeyBlobSize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // For RSA: Use padding (PKCS#1)
    if (!wcscmp(szSignAlg, BCRYPT_RSA_ALGORITHM)) {
        pPaddingInfo = &paddingInfo;
        dwFlags = BCRYPT_PAD_PKCS1;
    }

    // Prepare to sign hash
    status = BCryptSignHash(hKey, pPaddingInfo, pbHash, cbHashSize, NULL, 0, &cbSignatureSize, dwFlags);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for signature
    pbSignature = (PBYTE)malloc(cbSignatureSize);
    if (pbSignature == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }

    // Sign hash
    status = BCryptSignHash(hKey, pPaddingInfo, pbHash, cbHashSize, pbSignature, cbSignatureSize, &cbResult, dwFlags);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Write signature to file
    hFileOut = CreateFile(szFileOut, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileOut == INVALID_HANDLE_VALUE) {
        _ftprintf_s(stderr, _T("File error: Could not create signature file (%lu): '%s'\n"), GetLastError(), szFileIn);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    WriteFile(hFileOut, pbSignature, cbResult, &cbHashSize, NULL);

    Cleanup:

    if (hKey) BCryptDestroyKey(hKey);
    if (hSignAlg) BCryptCloseAlgorithmProvider(hSignAlg, 0);
    if (pbHash) { SecureZeroMemory(pbHash, cbHashSize); free(pbHash); }
    if (pbSignature) { SecureZeroMemory(pbSignature, cbSignatureSize); free(pbSignature); }
    if (hFileOut != INVALID_HANDLE_VALUE) CloseHandle(hFileOut);

    return status;
}


NTSTATUS CU_VerifyFile(LPCTSTR szFileIn, LPCTSTR szFileSig, LPCWSTR szHashAlg, LPCWSTR szSignAlg, LPBYTE pbPubKeyBlob, DWORD cbPubKeyBlobSize) {
    /**
     * @brief Verify file signature
     *
     * @param szFileIn: Input file path
     * @param szFileSig: Signature file path
     * @param szHashAlg: Hash algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
     * @param szSignAlg: Signature algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
     * @param pbPubKeyBlob: Pointer to public key blob
     * @param cbPubKeyBlobSize: Public key blob size
     *
     * @return NTSTATUS (0 on success)
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hSignAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = {szHashAlg};
    BCRYPT_PKCS1_PADDING_INFO *pPaddingInfo = NULL;
    DWORD dwFlags = 0;
    DWORD cbHashSize = 0;
    DWORD cbSignatureSize;
    PBYTE pbHash = NULL;
    PBYTE pbSignature = NULL;

    // Open file handles
    HANDLE hFileIn = CreateFile(szFileIn, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileIn == INVALID_HANDLE_VALUE) {
        _ftprintf_s(stderr, _T("File error: Could not open input file (%lu): '%s'\n"), GetLastError(), szFileIn);
        return STATUS_UNSUCCESSFUL;
    }
    HANDLE hFileSig = CreateFile(szFileSig, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileSig == INVALID_HANDLE_VALUE) {
        _ftprintf_s(stderr, _T("File error: Could not open signature file (%lu): '%s'\n"), GetLastError(), szFileSig);
        return STATUS_UNSUCCESSFUL;
    }

    // Get file hash using function
    status = CU_HashFile(szFileIn, szHashAlg, &pbHash, &cbHashSize);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Open signature algorithm handle
    status = BCryptOpenAlgorithmProvider(&hSignAlg, szSignAlg, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Load public key from blob
    status = BCryptImportKeyPair(hSignAlg, NULL, BCRYPT_PUBLIC_KEY_BLOB, &hKey, pbPubKeyBlob, cbPubKeyBlobSize, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // Allocate memory for signature
    cbSignatureSize = GetFileSize(hFileSig, NULL);
    pbSignature = (PBYTE)malloc(cbSignatureSize);
    if (pbSignature == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }

    // Read signature from file
    if (!ReadFile(hFileSig, pbSignature, cbSignatureSize, NULL, NULL)) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // For RSA: Use padding (PKCS#1)
    if (!wcscmp(szSignAlg, BCRYPT_RSA_ALGORITHM)) {
        pPaddingInfo = &paddingInfo;
        dwFlags = BCRYPT_PAD_PKCS1;
    }

    // Verify signature
    status = BCryptVerifySignature(hKey, pPaddingInfo, pbHash, cbHashSize, pbSignature, cbSignatureSize, dwFlags);

    Cleanup:

    if (hKey) BCryptDestroyKey(hKey);
    if (hSignAlg) BCryptCloseAlgorithmProvider(hSignAlg, 0);
    if (pbHash) { SecureZeroMemory(pbHash, cbHashSize); free(pbHash); }
    if (pbSignature) { SecureZeroMemory(pbSignature, cbSignatureSize); free(pbSignature); }
    CloseHandle(hFileIn);
    CloseHandle(hFileSig);

    return status;
}
