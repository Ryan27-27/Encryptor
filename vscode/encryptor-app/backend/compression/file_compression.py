import os
import zlib
import brotli

def compress_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Compress using zlib
    compressed_data_zlib = zlib.compress(file_data)
    
    # Compress using Brotli
    compressed_data_brotli = brotli.compress(file_data)
    
    # Save compressed files
    zlib_compressed_path = f"{file_path}.zlib"
    brotli_compressed_path = f"{file_path}.br"

    with open(zlib_compressed_path, 'wb') as zlib_file:
        zlib_file.write(compressed_data_zlib)

    with open(brotli_compressed_path, 'wb') as brotli_file:
        brotli_file.write(compressed_data_brotli)

    return zlib_compressed_path, brotli_compressed_path

def decompress_file(compressed_file_path):
    if compressed_file_path.endswith('.zlib'):
        with open(compressed_file_path, 'rb') as file:
            compressed_data = file.read()
        return zlib.decompress(compressed_data)
    
    elif compressed_file_path.endswith('.br'):
        with open(compressed_file_path, 'rb') as file:
            compressed_data = file.read()
        return brotli.decompress(compressed_data)
    
    else:
        raise ValueError("Unsupported file format for decompression.")