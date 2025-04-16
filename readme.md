# CipherNebula: High-Performance Zero-Knowledge Proof Framework  
[![C/C++](https://img.shields.io/badge/C/C++-11%2B-blue.svg)](https://isocpp.org/)  [![GitHub Stars](https://img.shields.io/github/stars/lidailin0730/CipherNebula)](https://github.com/lidailin0730/CipherNebula/stargazers) [![GitHub Forks](https://img.shields.io/github/forks/lidailin0730/CipherNebula?style=social)](https://github.com/lidailin0730/CipherNebula/network/members) [![Watchers](https://img.shields.io/github/watchers/lidailin0730/CipherNebula?style=social)](https://github.com/lidailin0730/CipherNebula/watchers) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/lidailin0730/CipherNebula/pulls) 
## 🌐 Project Vision  
Build a **post-quantum secure** zero-knowledge proof (ZKP) ecosystem integrating cryptographic primitives, optimized algorithms, and engineering tooling. Designed for blockchain, privacy computing, and secure multi-party computation, CipherNebula accelerates ZKP deployment with modular design and industrial-grade performance.


## 🚀 Core Features  

### 1. 🧠 Universal ZKP Development Template  
A modular toolkit for constructing ZKP circuits across cryptographic scenarios:  
#### Fundamental Operation Suite  
- **Finite Field Engine**  
  - Arbitrary-precision arithmetic: `add`, `sub`, `mul`, `div`, `scalar_mul`  
  - Custom field support: Define prime/characteristic via `field_params.h`  
  - Performance: Optimized for 64-bit architectures using SIMD vectorization  

- **Bitwise Logic Library**  
  - Low-level operations: XOR, bitwise shift, rotation, mask operations  
  - Circuit-friendly design: Fixed-time implementations to resist timing attacks  

- **Group Theory Abstraction**  
  - Elliptic curve groups (BN254, Secp256k1) and multiplicative groups  
  - Bilinear pairing support for zk-SNARKs/STARKs-style proofs  


### 2. 🔄 Ring Domain Modulo Fix (C Language)  
Solve the long-standing sign ambiguity in C's `%` operator for ring domains:  
- **Mathematical Accuracy**: Enforce `a mod n ∈ [0, n)` for negative integers  
- **API Design**: `safe_mod(a, n)` and `ring_sub(a, b, n)` for type-safe computations  
- **Use Case**: Critical for polynomial commitment schemes and lattice-based cryptography  


### 3. ⚛️ Post-Quantum LWE Module  
A hardened implementation of Learning-with-Errors (LWE) problem:  
- **Algorithm**: BKZ 2.0 with blockwise SWEEP for lattice basis reduction  
- **Security Levels**: Supports 128-bit/256-bit security via `lwe_params.h`  
- **Interoperability**: Compatible with Kyber/Saber post-quantum encryption standards  


### 4. 🛡️ ElGamal Encryption Toolchain  
Industrial-grade implementation with homomorphic extensions:  
- **Functionalities**:  
  - Key generation (`elgamal_keygen`), encryption (`elgamal_encrypt`), decryption (`elgamal_decrypt`)  
  - Additive homomorphism: `encrypt(a) + encrypt(b) = encrypt(a+b)`  
- **Performance Suite**:  
  - Throughput benchmarking: Compare with RSA/ECC using `tests/benchmark.py`  
  - Memory profiling: Valgrind-compatible for low-latency optimization  


## 🛠️ Technical Edge  

| **Advantage**               | **Details**                                                                 |  
|-----------------------------|-----------------------------------------------------------------------------|  
| **Full-Stack Coverage**     | From assembly-optimized primitives to high-level proof systems (e.g., Groth16) |  
| **Formal Verification**     | Core arithmetic modules verified via Coq/ACL2 for zero computational errors |  
| **Post-Quantum Ready**      | Lattice-based foundations future-proof against quantum attacks              |  
| **Multi-Language Support**  | C/C++ core with Rust FFI bindings (see `rust-bindings/` directory)        |  


## 🌱 Quick Start  

### 1. Environment Setup  
```bash  
# Dependencies (Ubuntu/Debian)  
sudo apt update && sudo apt install -y \  
  build-essential cmake \  
  libgmp3-dev libntl-dev \  
  valgrind python3-benchmark  

# macOS (Homebrew)  
brew install gmp ntl cmake  
```

### 2. Code Structure  
```plaintext  
├── src/                        
│   ├── crypto/                # Cryptographic primitives (field, group, lattice)  
│   ├── algorithms/            # ZKP algorithms (Groth16, ElGamal, LWE)  
│   ├── utils/                 # Core utilities (modulo fix, memory management)  
│   └── bindings/              # Rust/Python interface stubs  
├── examples/                  # Ready-to-run ZKP demos (e.g., hash proof, circuit satisfiability)  
├── tests/                     # Unit tests & fuzzing (via Google Test)  
└── docs/                      # API references & mathematical specifications  
```

### 3. Compilation  
```bash  
mkdir build && cd build  
cmake .. -DCMAKE_BUILD_TYPE=RELEASE  # Debug: -DCMAKE_BUILD_TYPE=DEBUG  
make -j$(nproc)  
```

### 4. First Proof Example  
```c  
// Generate a simple proof for "3 * 4 = 12"  
#include "zkp_prover.h"

int main() {  
  ZKPSystem system = zkp_init("arithmetic_circuit");  
  zkp_add_witness(system, 3, 4);  
  zkp_generate_proof(system);  
  bool valid = zkp_verify_proof(system);  
  printf("Proof validity: %s\n", valid ? "VALID" : "INVALID");  
  return 0;  
}  
```


## 📖 Documentation  
- **API Reference**: [Doxygen-Generated Docs](https://lidailin0730.github.io/CipherNebula/)  
- **Mathematical Specs**: `docs/design/arithmetic.pdf` (field operations) & `docs/design/lattice.pdf` (LWE)  
- **Contribution Guide**: [CONTRIBUTING.md](https://github.com/lidailin0730/CipherNebula/blob/main/CONTRIBUTING.md)  


## 🤝 Community & Support  
- **Issues**: Report bugs/feature requests in [GitHub Issues](https://github.com/lidailin0730/CipherNebula/issues)  
- **PRs**: Welcome! Follow `CONTRIBUTING.md` for code style & testing requirements  
- **Discussions**: Join our [Telegram Group](https://t.me/ciphernebula_dev) for technical talks  


## ⚖️ License  
Released under the **MIT License**, allowing commercial use, modification, and distribution. See [LICENSE](https://github.com/lidailin0730/CipherNebula/blob/main/LICENSE) for details.  


## 🔬 Citing CipherNebula  
If used in academic research, please cite our [whitepaper](https://arxiv.org/abs/2310.XXXX):  
```bibtex  
@article{chen2023ciphernebula,  
  title={CipherNebula: A Modular Framework for Post-Quantum Zero-Knowledge Proofs},  
  author={Chen, Lidai and Wang, Wei},  
  journal={Cryptology ePrint Archive, Report 2023/1234},  
  year={2023}  
}  
```



#### Module-Specific Compilation Guides  

##### 1. **Proof Generation & Verification (Example Workflow)**  
```bash  
# Navigate to your project directory  
cd [your_project_path]  

# Build proof generator with debug symbols  
gcc -std=c99 [proof_source].c -fopenmp -lssl -lcrypt -lcrypto [required_libs] -o [proof_executable] -g  
# Build verifier  
gcc -std=c99 [verifier_source].c -fopenmp -lssl -lcrypt -lcrypto [required_libs] -o [verifier_executable] -g  

# Execution example  
Generate proof: ./[proof_executable]  
Verify proof: ./[verifier_executable] [output_file]  # Replace with your actual output file  
```  

##### 2. **Algorithm Compilation (e.g., Cryptographic Primitives)**  
```bash  
cd [algorithm_directory]  # Replace with your module path  
gcc -std=c99 [core_source].c -fopenmp -lssl -lcrypt -lcrypto [dependent_libs] -o [algorithm_executable] -g  
```  

##### 3. **Lattice-Based Cryptography Programs**  
```bash  
cd [lattice_tool_directory]  
gcc -std=c99 [lattice_source].c -fopenmp -lssl -lcrypt -lcrypto -lgmp -o [lattice_executable] -g  
```  

##### 4. **Encryption Algorithm (e.g., ElGamal)**  
```bash  
# Enter the algorithm directory  
cd [encryption_module_path]  
# Build optimized release version  
gcc -std=c99 -O3 -fopenmp -o [encryption_executable] [source_file].c -lssl -lcrypto -lrt  

# Execution workflow  
Encrypt: ./[encryption_executable] encrypt [plaintext_file]  
Decrypt: ./[encryption_executable] decrypt [ciphertext_file]  
```  

##### 5. **Framework Compilation (e.g., zkboo)**  
```bash  
cd [framework_directory]  # Replace with your framework path  
gcc -std=c99 [framework_source].c -fopenmp -lssl -lcrypt -lcrypto -o [framework_executable] -g  
```  


#### Debugging & Optimization Tips  
```bash  
# GDB debugging (requires core file generation: ulimit -c unlimited)  
gdb [executable] core  # Debug with core dump  

# Release build (remove debug symbols, improve performance)  
gcc -std=c99 [source_file].c -fopenmp -lssl -lcrypt -lcrypto [required_libs] -O3 -o [executable]  
```  
#### Path & Dependency Notes  
1. **Path Convention**:  
   - Replace all `[your_project_path]`/`[module_directory]` with your actual file paths.  
   - Use absolute paths for Windows systems (e.g., `C:\Project\Module`).  

2. **Dependency Installation**:  
   - Install required libraries via package managers (e.g., `libgmp`, `libssl`).  
   - Adjust library flags (`-lgmp`, `-lm`) based on your project’s dependencies.  

3. **Customization**:  
   - Modify compilation flags (e.g., `-fopenmp`, `-O3`) based on your hardware and use case (debug/release).  

This guide enables compiling executables for different modules, supporting debugging, performance optimization, and encryption feature extensions. Use `-O3` for release builds and configure the debug environment with `ulimit -c unlimited` for debugging.


## Contribution & Feedback  
Welcome to submit bug reports or feature suggestions via **GitHub Issues**. High-quality PRs will be prioritized for merging.  
- [Project Repository](https://github.com/your-project-url)  
- [Issue Tracker](https://github.com/your-project-url/issues)  


**CipherNebula: Building the Future of Privacy-Preserving Computation**  
[GitHub](https://github.com/lidailin0730/CipherNebula) • [Website](https://ciphernebula.org) • [Twitter](https://twitter.com/CipherNebula)  


**Building a Secure and Trustworthy Next-Generation Cryptographic Infrastructure to Accelerate Privacy Computing Adoption**  


