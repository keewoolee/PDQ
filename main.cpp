#include "pdq.h"
#include "param.h"
#include "global.h"
#include <iostream>
#include <cstring>

void printUsage() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  ./test              Run with default parameters (defined in global.cpp)" << std::endl;
    std::cout << "  ./test N s          Run with specified configuration" << std::endl;
    std::cout << "  ./test -h, --help   Show this help message" << std::endl;
    std::cout << "\nAvailable configurations:" << std::endl;
    std::cout << "  Vary num_matching (N=16384):  s = 8, 16, 32, 64, 128" << std::endl;
    std::cout << "  Vary num_records (s=16):      N = 8192, 16384, 32768, 65536, 131072, 262144, 524288" << std::endl;
}

int main(int argc, char* argv[]) {
    // No arguments: use default parameters from global.cpp
    if (argc == 1) {
        std::cout << "Using default parameters from global.cpp: N=" << num_records
                  << ", s=" << num_matching << std::endl;
        std::cout << "Run './test --help' for usage.\n" << std::endl;
        pdq();
        return 0;
    }

    // Help flag
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printUsage();
        return 0;
    }

    // Parse N and s
    if (argc < 3) {
        std::cerr << "Error: Invalid arguments. Run './test --help' for usage." << std::endl;
        return 1;
    }

    int N = std::atoi(argv[1]);
    int s = std::atoi(argv[2]);

    bool valid = false;
    if (N == 16384) {
        switch (s) {
            case 8:   param_PDQ_16384_8();   valid = true; break;
            case 16:  param_PDQ_16384_16();  valid = true; break;
            case 32:  param_PDQ_16384_32();  valid = true; break;
            case 64:  param_PDQ_16384_64();  valid = true; break;
            case 128: param_PDQ_16384_128(); valid = true; break;
        }
    } else if (s == 16) {
        switch (N) {
            case 8192:   param_PDQ_8192_16();   valid = true; break;
            case 16384:  param_PDQ_16384_16();  valid = true; break;
            case 32768:  param_PDQ_32768_16();  valid = true; break;
            case 65536:  param_PDQ_65536_16();  valid = true; break;
            case 131072: param_PDQ_131072_16(); valid = true; break;
            case 262144: param_PDQ_262144_16(); valid = true; break;
            case 524288: param_PDQ_524288_16(); valid = true; break;
        }
    }

    if (!valid) {
        std::cerr << "Error: Invalid configuration (N=" << N << ", s=" << s << "). "
                  << "Run './test --help' for usage." << std::endl;
        return 1;
    }

    pdq();
    return 0;
}
