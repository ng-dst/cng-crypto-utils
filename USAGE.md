# CU Usage

Here's a brief overview of the available commands and their usage:

- `encrypt <in_file> <key_file>`: Encrypts the input file using the key provided in the key file.
- `decrypt <in_file> <key_file>`: Decrypts the input file using the key provided in the key file.
- `sign <in_file> <priv_key_file>`: Signs the input file using the private key provided in the key file.
- `verify <in_file> <pub_key_file> [sig_file]`: Verifies the signature of the input file using the public key provided in the key file.
- `hash <in_file>`: Generates a hash of the input file.
- `gen-key -c <key_size_bits> [out_file]`: Generates a symmetric key of the specified size.
- `gen-pair -c <key_size_bits> -s <sig_algorithm> [priv_out_file] [pub_out_file]`: Generates an asymmetric key pair of the specified size.
- `algo`: Prints the list of supported algorithms.
- `help`: Prints usage information.

## Options

In addition to the main commands, CU also supports several options to customize the behavior of the commands:

- `-o <out_file>`: Specifies the output file for the operation.
- `-a <algorithm>`: Specifies the algorithm to use for the operation. The default is AES.
- `-m <mode>`: Specifies the mode to use for the operation. The default is CBC.
- `-s <sig_algorithm>`: Specifies the signature algorithm to use for the operation. The default is ECDSA_P256.
- `-c <key_size_bits>`: Specifies the size of the key in bits.

## Examples

Here are a few examples of how to use CU:

- To generate a 256-bit AES key and save it to a file named `key.bin`, you would use the following command:

```bash
lab3.exe gen-key -a AES -c 256 -o key.bin
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
lab3.exe hash input.txt -a SHA256
```

- To sign a file named `input.txt` using the private key in `priv_key.bin` with ECDSA_P256 algorithm and save the signature to `signature.bin`, you would use the following commands:

```bash
lab3.exe gen-pair -s ECDSA_P256 -c 256 priv_key.bin pub_key.bin
```
```bash
lab3.exe sign input.txt priv_key.bin -o signature.bin -s ECDSA_P256
```

- To verify the signature of a file named `input.txt` using the public key in `pub_key.bin` and the signature in `signature.bin` with ECDSA_P256 algorithm, you would use the following command:

```bash
lab3.exe verify input.txt pub_key.bin signature.bin -s ECDSA_P256
```

Use `help` command to get a quick overview of the available commands and options:

```bash
lab3.exe help
```

Use `algo` command to get a list of supported algorithms:

```bash
lab3.exe algo
```

<br>

[Back to README](https://www.youtube.com/watch?v=dQw4w9WgXcQ)
