import sys
import argparse
from utils.config_manager import ConfigManager
from block_cipher import Framework
from my_custom_cipher import ervin_block_encrypt, ervin_block_decrypt
from des_cipher import des_block_encrypt, des_block_decrypt


def get_cipher_functions(algorithm):
    if algorithm == 'ervin':
        return ervin_block_encrypt, ervin_block_decrypt
    elif algorithm == 'des':
        return des_block_encrypt, des_block_decrypt
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def encrypt_file(input_path, output_path, config_path):
    config = ConfigManager.load_config(config_path)
    
    print(f"Algorithm: {config['algorithm']}")
    print(f"Mode: {config['mode']}")
    print(f"Block size: {config['block_size_bits']} bits")
    print(f"Padding: {config['padding']}")
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    file_size = len(plaintext)

    encrypt_func, _ = get_cipher_functions(config['algorithm'])
    
    framework = Framework(config)

    ciphertext = framework.encrypt(plaintext, encrypt_func, config['key'])
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

    print("encryption complete")


def decrypt_file(input_path: str, output_path: str, config_path: str):
    config = ConfigManager.load_config(config_path)
    
    print(f"Algorithm: {config['algorithm']}")
    print(f"Mode: {config['mode']}")
    print(f"Block size: {config['block_size_bits']} bits")
    print(f"Padding: {config['padding']}")
    
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    
    encrypt_func, decrypt_func = get_cipher_functions(config['algorithm'])
    
    framework = Framework(config)
    plaintext = framework.decrypt(ciphertext, decrypt_func, encrypt_func, config['key'])
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print("decryption complete")


def verify_files_match(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        content1 = f1.read()
        content2 = f2.read()
        return content1 == content2


def main():
    parser = argparse.ArgumentParser(
        description='Block Cipher Framework'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input', help='Input file path')
    encrypt_parser.add_argument('output', help='Output file path')
    encrypt_parser.add_argument('config', help='Configuration file path')
    
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input', help='Input file path')
    decrypt_parser.add_argument('output', help='Output file path')
    decrypt_parser.add_argument('config', help='Configuration file path')
    
    verify_parser = subparsers.add_parser('verify', help='Verify two files match')
    verify_parser.add_argument('file1', help='First file path')
    verify_parser.add_argument('file2', help='Second file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'encrypt':
            encrypt_file(args.input, args.output, args.config)
        elif args.command == 'decrypt':
            decrypt_file(args.input, args.output, args.config)
        elif args.command == 'verify':
            if verify_files_match(args.file1, args.file2):
                print("Files match!")
            else:
                print("Files do not match!")
                sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()