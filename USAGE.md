# CU Usage

Available commands for CU and their usage:

- `encrypt <in_file> <key_file>`: Encrypts the input file. Default output: `<in_file>.enc`
- `decrypt <in_file> <key_file>`: Decrypts the input file. Default output: `<in_file>` without `.enc`
- `sign <in_file> <priv_key_file>`: Signs the input file. Default output: `<in_file>.sig`
- `verify <in_file> <pub_key_file> [sig_file]`: Verifies the signature of the input file.
- `hash <in_file>`: Generates a hash of the input file.
- `gen-key [-a <algorithm>] [-c <key_size_bits>] [out_file]`: Generates a symmetric key. Default output: `key.bin`
- `gen-pair [-a <sig_algorithm>] [-c <key_size_bits>] [priv_out_file] [pub_out_file]`: Generates a signature key pair. Default output: `id_key.priv`, `id_key.pub`
- `algo`: Prints the list of supported algorithms.
- `help`: Prints usage information.

## Options

In addition to the main commands, CU also supports several options to customize the behavior of the commands:

- `-o <out_file>`: Output file for the operation. _For key pair generation, `-o` is omitted._
- `-a <algorithm>`: Encryption / hashing algorithm. Default: AES for encryption, SHA256 for hashing.
- `-m <mode>`: Chaining mode. Default: CBC, if used.
- `-s <sig_algorithm>`: Signature algorithm. Default: ECDSA_P256.
- `-c <key_size_bits>`: Size of the key to generate. Default: _algorithm-based_.

## Examples

Here are a few examples of how to use CU. All options are written explicitly for demonstration.

- To generate a 256-bit AES key and save it to a file named `key.bin`, you would use the following command:

```bash
lab3.exe gen-key -a AES -c 256 key.bin
```

- To encrypt a file named `input.txt` using the key in `key.bin` with AES algorithm and CBC mode, and save the encrypted data to `output.txt`, you would use the following command:

```bash
lab3.exe encrypt input.txt key.bin -o output.enc -a AES -m CBC
```

- To decrypt a file named `output.txt` using the key in `key.bin` with AES algorithm and CBC mode, and save the decrypted data to `decrypted.txt`, you would use the following command:

```bash
lab3.exe decrypt output.enc key.bin -o decrypted.txt -a AES -m CBC
```

- To generate a hash of a file named `input.txt` using the SHA256 algorithm, you would use the following command:

```bash
lab3.exe hash -a SHA256 input.txt 
```

- To sign a file named `input.txt` using the private key in `priv_key.bin` with ECDSA_P256 algorithm and save the signature to `signature.bin`, you would use the following commands:

```bash
lab3.exe gen-pair -s ECDSA_P256 -c 256 priv_key.bin pub_key.bin
```
```bash
lab3.exe sign input.txt priv_key.bin -o signature.bin -s ECDSA_P256 -a SHA256
```

- To verify the signature of a file named `input.txt` using `pub_key.bin` and `signature.bin` with ECDSA_P256 algorithm, you would use the following command:

```bash
lab3.exe verify input.txt pub_key.bin signature.bin -s ECDSA_P256 -a SHA256
```

Use `help` command to get a quick overview of the available commands and options:

```bash
lab3.exe help
```

Use `algo` command to get a list of supported algorithms:

```bash
lab3.exe algo
```
```
Encryption:                Modes:
    AES (default)              CBC (default)
    DES                        CFB
    DESX                       ECB
    3DES
    RC2
    RC4

Hashing:                   Signature:
    SHA256 (default)           ECDSA_P256 (default) 
    SHA384                     ECDSA_P384
    SHA512                     ECDSA_P521
    SHA1                       DSA
    MD4                        RSA
    MD5
```

<br>

[Back to README](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

<br>
