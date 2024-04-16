# Lab 3: Cryptography Utilities

CU is a simple suite of cryptographic functions implemented as a library and as a command line tool. CU is built on top of the CNG API and provides a simplified interface for common cryptographic operations.

## Features

- Symmetric encryption and decryption of files using various algorithms.
- Generation of file hashes using specified algorithms.
- Creation of symmetric key blobs from key buffers.
- Generation of asymmetric key pair blobs.
- Exporting and importing of key blobs to and from files.
- Exporting and importing of asymmetric key blobs to and from files.
- Signing of files using asymmetric algorithms.
- Verification of file signatures using asymmetric algorithms.
- Generation of random bytes.

## Usage

### As a library

Include `cu.h` and use `CU_` functions. Here is a basic example of how to use CU to encrypt a file:

```c
#include "cu.h"

int main() {
    LPCTSTR szFileIn = "input.txt";
    LPCTSTR szFileOut = "input.txt.enc";
    LPCWSTR szAlgo = BCRYPT_AES_ALGORITHM;
    LPCWSTR szMode = BCRYPT_CHAIN_MODE_CBC;
    LPBYTE pbKey = (LPBYTE) "sixteen-byte-key";
    DWORD cbKey = 16;
    LPBYTE pbIv = (LPBYTE) "0123456789abcdef";
    DWORD cbIv = 16;

    NTSTATUS status = CU_EncryptFile(szFileIn, szFileOut, szAlgo, szMode, pbKey, cbKey, pbIv, cbIv);
    if (!NT_SUCCESS(status)) {
        // Handle error
    }

    return 0;
}
```

Many parameters are optional and have default values. For example, default algorithm is AES and default mode is CBC. IV should be NULL if not used by the algorithm.

Most functions return `NTSTATUS` values, which are Windows error codes. You can use the `NT_SUCCESS` macro to check if the operation was successful.

Functions that require a pointer to a pointer to a buffer (e.g., `CU_CreateKeyBlob`) will allocate memory for the buffer. You should free this memory with `free` when you are done with it. Remember to zero out sensitive data before freeing (e.g. with `SecureZeroMemory`).

### As a command line tool

Here are some examples of how to use CU from the command line:

- To generate an AES-256 key and encrypt a file in CBC mode:

```bash
lab3.exe gen-key -a AES -c 256 -o key.bin
```

```bash
lab3.exe encrypt input.txt key.bin -o input.txt.enc -a AES -m CBC
```

- To generate a key pair for ECDSA_P256, then sign and verify a file:

```bash
lab3.exe gen-pair -s ECDSA_P256 -c 256 priv_key.bin pub_key.bin
```

```bash
lab3.exe sign input.txt priv_key.bin -s ECDSA_P256 -a SHA256 -o signature.bin
```

```bash
lab3.exe verify input.txt pub_key.bin signature.bin -s ECDSA_P256 -a SHA256
```

For algorithms list, use `algo` command. For help, use `help`.

For more detailed usage guide, see the [USAGE.md](USAGE.md).


## Internal Architecture

Here's a brief overview of the project's architecture and execution flow:

1. **Argument Parsing (`argparse.c`):** parsing command-line arguments using the `ParseArgs` function. This function fills an `ARGUMENTS` structure with specified parameters.

2. **Command Execution (`work.c`):** After parsing the arguments, the `ExecCommand` function is called. This function calls the appropriate function based on the command.

3. **Cryptography Utilities (`cu` directory):** This directory makes a set of `CU_` functions for encryption, decryption, hashing, signing, and key generation.

    - **Encryption and Decryption (`encrypt.c`):** Symmetric key algorithms. The key and initialization vector (IV) are read from a file and used to encrypt or decrypt the input file.

    - **Hashing (`hash.c`):** Hashing operation. Reads an input file and computes its hash using the specified algorithm.

    - **Signing and Verification (`sign.c`):** Signing algorithms. Generates a digital signature for an input file or verifies the signature.

    - **Key Generation (`key.c` and `pubkey.c`):** Handling symmetric and asymmetric keys (create, import, export). The keys are saved to binary files.

4. **Error Handling (`error.c`):** This file contains functions for printing error and usage messages.


## Building

This project is built using CMake, as specified in the `CMakeLists.txt` file. The project is organized into a static library (`cu`) and an executable (`lab3.exe`) which is a command-line utility.

Supports Unicode and ANSI builds. To build an Unicode version, set `UNICODE` in `CMakeLists.txt`.

To build the project, follow these steps:

1. Create a build directory: `mkdir build && cd build`
2. Generate build files: `cmake ..`
3. Build the project: `cmake --build .`

## TODO

- Shell extension for context menu integration (lab 4)
- ~~GUI for easier key management (lab 5)~~ 
