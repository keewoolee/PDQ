# PDQ: Private Database Query

A proof of concept implementation of PDQ, a private database query scheme using fully homomorphic encryption with **SIMD-aware homomorphic compression**.

## To Build

(based on Ubuntu 24.04 LTS)

### Dependencies
- C++ build environment (C++17)
- CMake build infrastructure
- [NTL](https://libntl.org/) library
- [OpenFHE](https://github.com/openfheorg/openfhe-development) library (tested with v1.4.0)
- [HEXL](https://github.com/intel/hexl) library (optional; optimized for processors with AVX512_IFMA support, e.g., Intel IceLake)

⚠️ To implement ring-switching, we use OpenFHE in a manner not officially supported by its APIs, which may be incompatible with future OpenFHE versions.

### Scripts to install the dependencies and build the library

1. Install CMake, GMP, and NTL (if needed).

```bash
sudo apt-get update
sudo apt-get install build-essential cmake libgmp3-dev libntl-dev
```

2. Install [OpenFHE + HEXL](https://github.com/openfheorg/openfhe-hexl) by following the instruction in the link, or run:

```bash
git clone https://github.com/openfheorg/openfhe-configurator.git
cd openfhe-configurator
scripts/configure.sh

# Would you like to stage an openfhe-development build?     [y/n] : n
# Would you like to stage an openfhe-hexl build?            [y/n] : y

sudo scripts/build-openfhe-development.sh
```

3. Build the library.

```bash
cd ..  # if still in openfhe-configurator directory
git clone https://github.com/keewoolee/PDQ.git  # clone this repository
cd PDQ
mkdir build
cd build
cmake .. -DCMAKE_PREFIX_PATH=~/openfhe-configurator/openfhe-staging/install # adjust the path to the location of the openfhe libraries
make
```

4. Basic test. On success, the output will show `Verification: PASSED`.

```bash
./test
```

## To Run

### Quick start

```bash
# Run with default parameters (N=16384, s=16)
./test

# Show help
./test --help
```

### Available configurations

```bash
# ./test <N> <s>
# N: number of records in database
# s: maximum number of matching records

# Vary s (N=16384)
./test 16384 8
./test 16384 16
./test 16384 32
./test 16384 64
./test 16384 128

# Vary N (s=16)
./test 8192 16
./test 16384 16
./test 32768 16
./test 65536 16
./test 131072 16
./test 262144 16
./test 524288 16
```

### Full benchmarks

To run all benchmarks presented in the paper (15 compute-minutes):

```bash
python3 -u ../benchmark.py > benchmark.txt 2>&1
```

### Custom parameters

To run with custom parameters, modify the values in `src/global.cpp` and rebuild:

```bash
./test
```

⚠️ Custom parameters may result in incorrect, insecure, or inefficient outcomes. Only recommended if you are sufficiently knowledgeable.
