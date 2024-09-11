
# CUDA AES-CTR 128 Project



This project implements the AES-CTR 128-bit encryption algorithm using CUDA for GPU acceleration and C++ for CPU, allowing a performance comparison between the two platforms. The code is designed to demonstrate the block encryption process of AES-CTR mode, showcasing the advantages of parallel processing with GPUs.

- **AES-CTR (Counter Mode)**: A mode of operation for block ciphers where the encryption of each block is dependent on a counter. Each block of plaintext is XORed with the encrypted counter value, ensuring fast and parallelizable encryption.
- The project focuses on analyzing runtime and clock cycles for both GPU and CPU implementations.

## Features

- AES-CTR 128-bit encryption utilizing both CPU and GPU (CUDA).
- Customizable inputs for plaintext, cipher key, and counter.
- Output of specific encrypted blocks to validate encryption.
- Detailed runtime and clock cycle performance analysis for CUDA-accelerated encryption versus traditional CPU processing.

## Tech Stack

This project is developed using:

- **CUDA Toolkit 12.6** - For the GPU implementation of AES encryption.
- **Microsoft Visual Studio** - For compiling and managing the project.
- **C++** - Standard C++ for the CPU implementation.

## Installation

### Prerequisites

- **Operating System**: Windows 10 or Linux (e.g., Ubuntu)
- **GPU**: NVIDIA CUDA-capable GPU (e.g., RTX 2070 Super or similar)
- **Tools**: CUDA Toolkit 12.6, Microsoft Visual Studio, and a C++ compiler like `g++`.

### Compiling and Running

Follow the installation and setup instructions provided in the project files to compile and run the code on both CPU and GPU. Ensure the CUDA environment is correctly set up, and GPU drivers are up-to-date.

## Usage

- Customize the plaintext, cipher key, and counter in the code.
- Control which encrypted block is output for verification.
- Analyze performance in terms of runtime and clock cycles to compare GPU and CPU implementations.

## Help

If issues arise, ensure that the CUDA Toolkit is installed correctly and that your GPU drivers are up-to-date.

## Authors

- **Yinon Coscas** and **Tom Shahar**

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Acknowledgments

- [CUDA Programming Guide](https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html)
- [AES-CTR Mode Explanation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))


