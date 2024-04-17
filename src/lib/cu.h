/**
 * @file cu.h
 *
 * Cryptography Utilities
 */

#pragma once

#include <windows.h>
#include <ntdef.h>


/**
 * @brief Custom NTSTATUS error
 */
#define STATUS_WRONG_ENCRYPTION_KEY ((NTSTATUS)0xC00002ABL)


/**
 * @brief Chunk size for encryption / hashing
 * (1024 blocks = 16-32 Kb)
 */
#define CHUNK_SIZE_BLOCKS    1024


/**
 * @brief Encrypt file using symmetric algorithm
 *
 * @param szFileIn: Input file path
 * @param szFileOut: Output file path
 * @param szAlgo: Algorithm name (e.g. BCRYPT_AES_ALGORITHM)
 * @param szMode [optional]: Chaining mode (e.g. BCRYPT_CHAIN_MODE_CBC)
 * @param pbKey: Key buffer
 * @param cbKey: Key buffer size
 * @param pbIv [optional]: IV buffer
 * @param cbIv [optional]: IV size
 *
 * @return NTSTATUS (0 on success)
 *
 * @note IV is generated randomly if pbIv == NULL
 * @note IV is written as a first block of the file
 */
NTSTATUS CU_EncryptFile(LPCTSTR szFileIn, LPCTSTR szFileOut,
                        LPCWSTR szAlgo, LPCWSTR szMode,
                        LPBYTE pbKey, DWORD cbKey,
                        LPBYTE pbIv, DWORD cbIv);


/**
 * @brief Decrypt file using symmetric algorithm
 *
 * @param szFileIn: Input file path
 * @param szFileOut: Output file path
 * @param szAlgo: Algorithm name (e.g. BCRYPT_AES_ALGORITHM)
 * @param szMode [optional]: Chaining mode (e.g. BCRYPT_CHAIN_MODE_CBC)
 * @param pbKey: Key buffer
 * @param cbKey: Key buffer size
 *
 * @return NTSTATUS (0 on success)
 *
 * @note IV is read as a first block of the file
 */
NTSTATUS CU_DecryptFile(LPCTSTR szFileIn, LPCTSTR szFileOut,
                        LPCWSTR szAlgo, LPCWSTR szMode,
                        LPBYTE pbKey, DWORD cbKey);


/**
 * @brief Allocate and get hash of file using the specified algorithm
 *
 * @param szFile: File path
 * @param szAlg: Algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
 * @param pbHash: Pointer to get hash buffer to
 * @param pcbHashSize: Pointer to get hash size to
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_HashFile(LPCTSTR szFile, LPCWSTR szAlg, LPBYTE *pbHash, DWORD *pcbHashSize);


/**
 * @brief Convert buffer to hex string
 *
 * @param pbBuf: Byte buffer
 * @param cbBufSize: Byte buffer size
 *
 * @return LPTSTR: Hex string
 */
LPTSTR CU_BytesToHex(LPBYTE pbBuf, DWORD cbBufSize);


/**
 * @brief Sign file using asymmetric algorithm
 *
 * @param hFileIn: Input file handle
 * @param hFileOut: Signature file handle
 * @param szHashAlg: Hash algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
 * @param szSignAlg: Signature algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
 * @param pbPrivKeyBlob: Pointer to private key blob
 * @param cbPrivKeyBlobSize: Private key blob size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_SignFile(LPCTSTR szFileIn, LPCTSTR szFileOut, LPCWSTR szHashAlg, LPCWSTR szSignAlg, LPBYTE pbPrivKeyBlob, DWORD cbPrivKeyBlobSize);


/**
 * @brief Verify file signature using asymmetric algorithm
 *
 * @param hFileIn: Input file handle
 * @param hFileSig: Signature file handle
 * @param szHashAlg: Hash algorithm name (e.g. BCRYPT_SHA256_ALGORITHM)
 * @param szSignAlg: Signature algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
 * @param pbPubKeyBlob: Pointer to public key blob
 * @param cbPubKeyBlobSize: Public key blob size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_VerifyFile(LPCTSTR szFileIn, LPCTSTR szFileSig, LPCWSTR szHashAlg, LPCWSTR szSignAlg, LPBYTE pbPubKeyBlob, DWORD cbPubKeyBlobSize);


/**
 * @brief Get random bytes
 *
 * @param pbBuffer: Buffer to store random bytes
 * @param cbBuffer: Buffer size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_GetRandomBytes(LPBYTE pbBuffer, DWORD cbBuffer);


/**
 * @brief Make blob from symmetric key buffer
 *
 * @param szAlgo: Algorithm name (e.g. BCRYPT_AES_ALGORITHM)
 * @param pbKey: Key buffer
 * @param cbKeySize: Key buffer size
 * @param pbKeyBlob: Pointer to key blob buffer
 * @param pcbKeyBlobSize: Key blob buffer size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_CreateKeyBlob(LPCWSTR szAlgo, LPBYTE pbKey, DWORD cbKeySize, LPBYTE *pbKeyBlob, DWORD *pcbKeyBlobSize);


/**
 * @brief Generate asymmetric key pair blobs
 *
 * @param szAlgo: Algorithm name (e.g. BCRYPT_RSA_ALGORITHM)
 * @param dwKeySize: Key size in bits
 * @param pbPubBlob: Pointer to public key blob buffer
 * @param pcbPubBlobSize: Public key blob size
 * @param pbPrivBlob: Pointer to private key blob buffer
 * @param pcbPrivBlobSize: Private key blob size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_GenerateKeyPairBlob(LPCWSTR szAlgo, DWORD dwKeySize, LPBYTE *pbPubBlob, DWORD *pcbPubBlobSize, LPBYTE *pbPrivBlob, DWORD *pcbPrivBlobSize);


/**
 * @brief Export key blob to file
 *
 * @param szPath: File path
 * @param pbBlob: Key blob buffer
 * @param cbBlobSize: Key blob buffer size
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_ExportKeyBlob(LPTSTR szPath, LPBYTE pbBlob, DWORD cbBlobSize);


/**
 * @brief Import key blob from file
 *
 * @param szPath: Key file path
 * @param pbPubBlob: Pointer to get key blob to
 * @param pcbPubBlobSize: Pointer to get blob size to
 *
 * @return NTSTATUS (0 on success)
 */
NTSTATUS CU_ImportKeyBlob(LPTSTR szPath, LPBYTE *pbBlob, DWORD *pcbBlobSize);
