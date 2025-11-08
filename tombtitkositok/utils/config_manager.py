import json
import os


class ConfigManager:
    
    REQUIRED_FIELDS = ['algorithm', 'block_size_bits', 'mode', 'padding']
    VALID_ALGORITHMS = ['ervin', 'des'] 
    VALID_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    VALID_PADDING = ['zero', 'des', 'schneier_ferguson']
    MODES_REQUIRING_IV = ['CBC', 'CFB', 'OFB', 'CTR']
    
    def load_config(path):

        if not os.path.exists(path):
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        with open(path, 'r') as f:
            config = json.load(f)
        
        ConfigManager.validate_required_fields(config)
        
        ConfigManager.validate_algorithm(config)
        ConfigManager.validate_block_size(config)
        ConfigManager.validate_mode(config)
        ConfigManager.validate_padding(config)
        ConfigManager.validate_key(config)
        ConfigManager.validate_iv(config)
        
        # hex strings to bytes
        config['key'] = bytes.fromhex(config['key'])
        if 'iv' in config and config['iv']:
            config['iv'] = bytes.fromhex(config['iv'])
        
        return config
    
    def validate_required_fields(config):
        missing = [field for field in ConfigManager.REQUIRED_FIELDS 
                   if field not in config]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
    
    def validate_algorithm(config):
        algorithm = config['algorithm']
        if algorithm not in ConfigManager.VALID_ALGORITHMS:
            raise ValueError(
                f"Invalid algorithm '{algorithm}'. "
                f"Must be one of: {', '.join(ConfigManager.VALID_ALGORITHMS)}"
            )
    
    def validate_block_size(config) :
        block_size = config['block_size_bits']
        
        if not isinstance(block_size, int):
            raise ValueError("block_size_bits must be an integer")
        
        if block_size <= 0:
            raise ValueError("block_size_bits must be positive")
        
        if block_size % 8 != 0:
            raise ValueError("block_size_bits must be a multiple of 8")
        
        if config['algorithm'] == 'des' and block_size != 64:
            raise ValueError("DES requires block_size_bits = 64")
    
    def validate_mode(config):
        mode = config['mode']
        if mode not in ConfigManager.VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. "
                f"Must be one of: {', '.join(ConfigManager.VALID_MODES)}"
            )
    
    def validate_padding(config):
        padding = config['padding']
        if padding not in ConfigManager.VALID_PADDING:
            raise ValueError(
                f"Invalid padding '{padding}'. "
                f"Must be one of: {', '.join(ConfigManager.VALID_PADDING)}"
            )
    
    def validate_key(config):
        if 'key' not in config:
            raise ValueError("Missing required field: key")
        
        key = config['key']
        if not isinstance(key, str):
            raise ValueError("Key must be a hex string")
        
        try:
            key_bytes = bytes.fromhex(key)
        except ValueError:
            raise ValueError("Key must be a valid hex string")
        
        if config['algorithm'] == 'des':
            if len(key_bytes) != 8:
                raise ValueError("DES requires an 8-byte (16 hex character) key")
    
    def validate_iv(config):
        mode = config['mode']
        
        if mode in ConfigManager.MODES_REQUIRING_IV:
            if 'iv' not in config or not config['iv']:
                raise ValueError(f"IV is required for {mode} mode")
            
            iv = config['iv']
            if not isinstance(iv, str):
                raise ValueError("IV must be a hex string")
            
            try:
                iv_bytes = bytes.fromhex(iv)
            except ValueError:
                raise ValueError("IV must be a valid hex string")
            
            expected_size = config['block_size_bits'] // 8
            if len(iv_bytes) != expected_size:
                raise ValueError(
                    f"IV must be {expected_size} bytes "
                    f"({expected_size * 2} hex characters) for block size "
                    f"{config['block_size_bits']} bits"
                )