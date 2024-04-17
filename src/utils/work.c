/**
 * @file work.c
 *
 * Execute command based on ARGUMENTS struct
 */

#include <windows.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <stdio.h>
#include <tchar.h>

#include "cu.h"
#include "argparse.h"
#include "error.h"

#include "work.h"


#define DEFAULT_KEYFILE_NAME    _T( "key.bin" )
#define DEFAULT_PRIV_KEY_NAME   _T( "id_key" )
#define DEFAULT_PUB_KEY_NAME    _T( "id_key.pub" )
#define DEFAULT_ENC_SUFFIX      _T( ".enc" )
#define DEFAULT_SIG_SUFFIX      _T( ".sig" )


NTSTATUS ExecCommand(ARGUMENTS *args) {
    /**
     * @brief Execute command based on ARGUMENTS struct
     */

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    LPBYTE pbKeyBlob = NULL;
    LPBYTE pbPubKeyBlob = NULL;
    LPBYTE pbPrivKeyBlob = NULL;
    LPBYTE pbHash = NULL;
    LPBYTE pbKeyBuffer = NULL;
    LPTSTR pbHashHex = NULL;
    DWORD cbKeyBlobSize = 0;
    DWORD cbPubKeyBlobSize = 0;
    DWORD cbPrivKeyBlobSize = 0;
    DWORD cbHashSize = 0;

    // Default algorithms
    if (args->szAlgorithm == NULL) args->szAlgorithm = wcsdup(BCRYPT_AES_ALGORITHM);
    if (args->szHashAlgorithm == NULL) args->szHashAlgorithm = wcsdup(BCRYPT_SHA256_ALGORITHM);
    if (args->szSigAlgorithm == NULL) args->szSigAlgorithm = wcsdup(BCRYPT_ECDSA_P256_ALGORITHM);

    if (args->szAlgorithm == NULL || args->szHashAlgorithm == NULL || args->szSigAlgorithm == NULL)
        goto Cleanup;

    // Use CU_* functions defined in cu.h
    switch (args->command) {

        case CMD_ENCRYPT:

            // Check in files
            if (args->szInFile == NULL || args->szKeyFile == NULL) { _tprintf(_T("Please specify input and key files\n")); goto Cleanup; }

            // Default out file:  add .enc
            if (args->szOutFile == NULL) {
                args->szOutFile = malloc((_tcslen(args->szInFile) + _tcslen(DEFAULT_ENC_SUFFIX) + 1) * sizeof(TCHAR));
                if (args->szOutFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
                _tcscpy(args->szOutFile, args->szInFile);
                _tcscat(args->szOutFile, DEFAULT_ENC_SUFFIX);
            }
            
            status = CU_ImportKeyBlob(args->szKeyFile, &pbKeyBlob, &cbKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            // Use random or no IV (null)
            status = CU_EncryptFile(args->szInFile, args->szOutFile, args->szAlgorithm, args->szMode, pbKeyBlob, cbKeyBlobSize, NULL, 0);
            break;

            
        case CMD_DECRYPT:

            // Check in files
            if (args->szInFile == NULL || args->szKeyFile == NULL) { _tprintf(_T("Please specify input and key files\n")); goto Cleanup; }

            // Default out file:  remove .enc or throw error
            if (args->szOutFile == NULL) {
                LPTSTR suffix = _tcsrchr(args->szInFile, DEFAULT_ENC_SUFFIX[0]);

                if (suffix && !_tcsicmp(DEFAULT_ENC_SUFFIX, suffix)) {
                    args->szOutFile = _tcsdup(args->szInFile);
                    if (args->szOutFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
                    args->szOutFile[suffix - args->szInFile] = '\0';
                }
                else {
                    _tprintf(_T("Please specify output file (-o flag)\n"));
                    goto Cleanup;
                }
            }
            
            status = CU_ImportKeyBlob(args->szKeyFile, &pbKeyBlob, &cbKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }
            
            status = CU_DecryptFile(args->szInFile, args->szOutFile, args->szAlgorithm, args->szMode, pbKeyBlob, cbKeyBlobSize);
            break;

            
        case CMD_HASH:

            // Check in file
            if (args->szInFile == NULL) { _tprintf(_T("Please specify input file\n")); goto Cleanup; }

            status = CU_HashFile(args->szInFile, args->szHashAlgorithm, &pbHash, &cbHashSize);
            if (NT_SUCCESS(status)) {
                pbHashHex = CU_BytesToHex(pbHash, cbHashSize);
                _tprintf_s(_T("%s  %ls  %s\n"), args->szInFile, args->szHashAlgorithm, pbHashHex ? pbHashHex : _T("Error converting hash to hex"));
            }
            break;

            
        case CMD_SIGN:

            // Check in files
            if (args->szInFile == NULL || args->szPrivKeyFile == NULL) { _tprintf(_T("Please specify input and private key files\n")); goto Cleanup; }

            // Default out file:  add .sig
            if (args->szOutFile == NULL) {
                args->szOutFile = malloc((_tcslen(args->szInFile) + _tcslen(DEFAULT_SIG_SUFFIX) + 1) * sizeof(TCHAR));
                if (args->szOutFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
                _tcscpy(args->szOutFile, args->szInFile);
                _tcscat(args->szOutFile, DEFAULT_SIG_SUFFIX);
            }

            status = CU_ImportKeyBlob(args->szPrivKeyFile, &pbPrivKeyBlob, &cbPrivKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }
            
            status = CU_SignFile(args->szInFile, args->szOutFile, args->szHashAlgorithm, args->szSigAlgorithm, pbPrivKeyBlob, cbPrivKeyBlobSize);
            break;
            
            
        case CMD_VERIFY:

            // Check in files
            if (args->szInFile == NULL || args->szPubKeyFile == NULL) {
                _tprintf(_T("Please specify input and public key files\n"));
                goto Cleanup; 
            }

            // Default signature file:  add .sig
            if (args->szSigFile == NULL) {
                args->szSigFile = malloc((_tcslen(args->szInFile) + _tcslen(DEFAULT_SIG_SUFFIX) + 1) * sizeof(TCHAR));
                if (args->szSigFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
                _tcscpy(args->szSigFile, args->szInFile);
                _tcscat(args->szSigFile, DEFAULT_SIG_SUFFIX);
            }

            status = CU_ImportKeyBlob(args->szPubKeyFile, &pbPubKeyBlob, &cbPubKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }
            
            status = CU_VerifyFile(args->szInFile, args->szSigFile, args->szHashAlgorithm, args->szSigAlgorithm, pbPubKeyBlob, cbPubKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            _tprintf_s(_T("%s  OK\n"), args->szInFile);
            break;


        case CMD_GEN_KEY:

            // Default key file name
            if (args->szKeyFile == NULL) {
                if (args->szOutFile)
                    args->szKeyFile = _tcsdup(args->szOutFile);
                else
                    args->szKeyFile = _tcsdup(DEFAULT_KEYFILE_NAME);
                if (args->szKeyFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
            }

            // Check key size
            if (args->cbKeySize == 0) {
                // Default key size
                if      (!wcscmp(args->szAlgorithm, BCRYPT_DES_ALGORITHM)) args->cbKeySize = 64;
                else if (!wcscmp(args->szAlgorithm, BCRYPT_3DES_ALGORITHM)) args->cbKeySize = 192;
                else if (!wcscmp(args->szAlgorithm, BCRYPT_DESX_ALGORITHM)) args->cbKeySize = 192;
                else if (!wcscmp(args->szAlgorithm, BCRYPT_AES_ALGORITHM)) args->cbKeySize = 128;
                else if (!wcscmp(args->szAlgorithm, BCRYPT_RC2_ALGORITHM)) args->cbKeySize = 128;
                else if (!wcscmp(args->szAlgorithm, BCRYPT_RC4_ALGORITHM)) args->cbKeySize = 128;
                else {
                    _tprintf(_T("Please specify key size in bits (-c flag)\n"));
                    goto Cleanup;
                }
            }

            // Key size in bytes
            args->cbKeySize /= 8;

            // Generate raw key buffer
            pbKeyBuffer = (LPBYTE)malloc(args->cbKeySize);
            if (pbKeyBuffer == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }

            status = CU_GetRandomBytes(pbKeyBuffer, args->cbKeySize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            // Create key blob from buffer
            status = CU_CreateKeyBlob(args->szAlgorithm, pbKeyBuffer, args->cbKeySize, &pbKeyBlob, &cbKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            status = CU_ExportKeyBlob(args->szKeyFile, pbKeyBlob, cbKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            _tprintf_s(_T("Generated %lu-bit %ls key: '%s'\n"), args->cbKeySize * 8, args->szAlgorithm, args->szKeyFile);
            break;


        case CMD_GEN_PAIR:

            // Default key file names
            if (args->szPrivKeyFile == NULL) {
                args->szPrivKeyFile = _tcsdup(DEFAULT_PRIV_KEY_NAME);
                if (args->szPrivKeyFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
            }
            if (args->szPubKeyFile == NULL) {
                args->szPubKeyFile = _tcsdup(DEFAULT_PUB_KEY_NAME);
                if (args->szPubKeyFile == NULL) { status = STATUS_NO_MEMORY; goto Cleanup; }
            }

            // Check key size
            if (args->cbKeySize == 0) {
                // Default key size
                if      (!wcscmp(args->szSigAlgorithm, BCRYPT_ECDSA_P256_ALGORITHM)) args->cbKeySize = 256;
                else if (!wcscmp(args->szSigAlgorithm, BCRYPT_ECDSA_P384_ALGORITHM)) args->cbKeySize = 384;
                else if (!wcscmp(args->szSigAlgorithm, BCRYPT_ECDSA_P521_ALGORITHM)) args->cbKeySize = 521;
                else if (!wcscmp(args->szSigAlgorithm, BCRYPT_RSA_ALGORITHM)) args->cbKeySize = 2048;
                else if (!wcscmp(args->szSigAlgorithm, BCRYPT_DSA_ALGORITHM)) args->cbKeySize = 1024;
                else {
                    _tprintf(_T("Please specify key size in bits (-c flag)\n"));
                    goto Cleanup;
                }
            }

            // Generate key pair blobs
            status = CU_GenerateKeyPairBlob(args->szSigAlgorithm, args->cbKeySize, &pbPubKeyBlob, &cbPubKeyBlobSize, &pbPrivKeyBlob, &cbPrivKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            // Export key pair blobs to files
            status = CU_ExportKeyBlob(args->szPubKeyFile, pbPubKeyBlob, cbPubKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            status = CU_ExportKeyBlob(args->szPrivKeyFile, pbPrivKeyBlob, cbPrivKeyBlobSize);
            if (!NT_SUCCESS(status)) { PrintNTStatusError(status); goto Cleanup; }

            _tprintf_s(_T("Generated %lu-bit %ls key pair: '%s' (private), '%s' (public)\n"), args->cbKeySize, args->szSigAlgorithm, args->szPrivKeyFile, args->szPubKeyFile);
    }

    if (!NT_SUCCESS(status)) PrintNTStatusError(status);

    Cleanup:

    if (pbKeyBuffer) { SecureZeroMemory(pbKeyBuffer, args->cbKeySize); free(pbKeyBuffer); }
    if (pbKeyBlob) { SecureZeroMemory(pbKeyBlob, cbKeyBlobSize); free(pbKeyBlob); }
    if (pbPubKeyBlob) { SecureZeroMemory(pbPubKeyBlob, cbPubKeyBlobSize); free(pbPubKeyBlob); }
    if (pbPrivKeyBlob) { SecureZeroMemory(pbPrivKeyBlob, cbPrivKeyBlobSize); free(pbPrivKeyBlob); }
    if (pbHash) { SecureZeroMemory(pbHash, cbHashSize); free(pbHash); }
    if (pbHashHex) { SecureZeroMemory(pbHashHex, _tcsnlen(pbHashHex, 2*cbHashSize + 1)); free(pbHashHex); }

    return status;
}
