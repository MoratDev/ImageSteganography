# Image Steganography Tool

## What is Image Steganography?

Image steganography is the practice of hiding data inside digital images without visibly altering them. Unlike encryption which scrambles data, steganography conceals the very existence of the data. The hidden information is embedded in the least significant bits of pixel values, making changes imperceptible to the human eye.

This technique has applications in:
- **Digital watermarking** for copyright protection
- **Covert communication** in security-sensitive environments  
- **Data exfiltration** detection in cybersecurity
- **Privacy protection** for sensitive file transmission

## How This Implementation Works

### Encryption Layer
- **Algorithm**: Fernet encryption (AES-128-CBC + HMAC-SHA256)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: 16-byte random salt per operation for unique keys
- **Security**: Each file gets a unique encryption key, preventing pattern analysis

### Steganography Process
1. **File Preparation**: Original file is encrypted and serialized with metadata
2. **Header Embedding**: Metadata (filename, size, salt) stored in first pixels
3. **Data Hiding**: Encrypted file data embedded using LSB (Least Significant Bit) technique
4. **Extraction**: Process reversed using the encryption key to recover original file

### Data Format
```
[Header Length: 2 bytes] → [Metadata: Variable] → [Encrypted File Data]
```

## Technical Methods Used

### Performance Optimization
- **NumPy Vectorization**: Entire image processed as arrays instead of pixel-by-pixel loops
- **Memory Management**: Images handled as memory-mapped arrays for large file support
- **Bit Manipulation**: Direct binary operations for efficient LSB embedding

```python
# Vectorized pixel modification
modified_flat_array[bit_index] = np.uint8((pixel & 0xFE) | bit_value)
```

### Threading Architecture
- **Non-blocking UI**: File operations run in background threads
- **Progress Callbacks**: Real-time progress updates during processing
- **Error Handling**: Graceful failure recovery with detailed error messages

### GUI Implementation
- **Custom Components**: HoverButton with state management
- **Dynamic Previews**: Real-time image and capacity analysis
- **Modular Design**: Separate business logic from presentation layer

### Data Handling
- **Binary Serialization**: Pickle for metadata, raw bytes for file content
- **Format Support**: Universal file type support through binary handling
- **Capacity Calculation**: Mathematical determination of embedding limits

```python
capacity = (width * height * 3) // 8 - header_size
```

## Installation & Usage

```bash
pip install pillow cryptography numpy
python app.py
```

## Examples

*[Image examples to be added]*
