import os
import json
import subprocess
import sys
from pathlib import Path
from utils.config_manager import ConfigManager


def create_test_file(filepath, size_mb = 1.5):
    size_bytes = int(size_mb * 1024 * 1024)

    data = bytearray()
    for i in range(size_bytes):
        data.append((i * 137 + i // 256 * 73) % 256)
    
    with open(filepath, 'wb') as f:
        f.write(data)


def create_test_configs():
    
    configs_dir = Path('test_configs')
    configs_dir.mkdir(exist_ok=True)
    
    algorithms = ['ervin', 'des']
    modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    padding_modes = ['zero', 'des', 'schneier_ferguson']
    
    configs = []
    
    for algo in algorithms:
        for mode in modes:
            padding = padding_modes[len(configs) % len(padding_modes)]
            
            config_name = f"{algo}_{mode}_{padding}.json"
            config_path = configs_dir / config_name
            
            if algo == 'des':
                config = {
                    "algorithm": "des",
                    "block_size_bits": 64,
                    "mode": mode,
                    "padding": padding,
                    "key": "0123456789ABCDEF",
                }
            else:  # ervin
                config = {
                    "algorithm": "ervin",
                    "block_size_bits": 128,
                    "mode": mode,
                    "padding": padding,
                    "key": "0123456789ABCDEF0123456789ABCDEF",
                }
            
            if mode in ['CBC', 'CFB', 'OFB', 'CTR']:
                block_bytes = config['block_size_bits'] // 8
                config['iv'] = "00" * block_bytes
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            configs.append(str(config_path))
    
    return configs


def run_test(test_file, config_path, output_dir):

    config_name = Path(config_path).stem
    encrypted_file = output_dir / f"{config_name}.enc"
    decrypted_file = output_dir / f"{config_name}.dec"
    
    try:
        result = subprocess.run(
            [sys.executable, 'main.py', 'encrypt', test_file, 
             str(encrypted_file), config_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"Encryption failed!")
            print(result.stderr)
            return False
        
        print(result.stdout)

        result = subprocess.run(
            [sys.executable, 'main.py', 'decrypt', str(encrypted_file),
             str(decrypted_file), config_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"Decryption failed!")
            print(result.stderr)
            return False
        
        print(result.stdout)
        
        print("Verifying...")
        result = subprocess.run(
            [sys.executable, 'main.py', 'verify', test_file, 
             str(decrypted_file)],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"Verification failed - files do not match!")
            return False
        
        print(result.stdout)
        print(f"Test passed: {config_name}")
        return True
        
    except subprocess.TimeoutExpired:
        print(f"Test timed out!")
        return False
    except Exception as e:
        print(f"Test error: {e}")
        return False


def main():
    print("Block Cipher Framework - Test")
    
    output_dir = Path('test_output')
    output_dir.mkdir(exist_ok=True)
    
    test_file = 'test_data.bin'
    if not os.path.exists(test_file):
        create_test_file(test_file, size_mb=1.5)
    else:
        print(f"Using existing test file: {test_file}")
        print(f"Size: {os.path.getsize(test_file)} bytes")
    
    configs = create_test_configs()
    print(f"Created {len(configs)} configurations")
    
    results = {}
    
    for config_path in configs:
        config_name = Path(config_path).stem
        passed = run_test(test_file, config_path, output_dir)
        results[config_name] = passed
    
    print("TEST SUMMARY")
    
    passed_count = sum(1 for passed in results.values() if passed)
    total_count = len(results)
    
    for config_name, passed in sorted(results.items()):
        status = "PASS" if passed else "FAIL"
        print(f"{status}: {config_name}")
    
    print(f"\n{passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n All tests passed!")
        return 0
    else:
        print(f"\n {total_count - passed_count} tests failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())