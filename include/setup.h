#pragma once

#include "openfhe.h"
#include <vector>
#include <cstdint>

void updateGlobal();
void initBFVParams(lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>& params);
void initBFVParams_trace(lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>& params);
void enableFeatures(lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context);
std::vector<int32_t> computeRotationIndices();

// Ring-switch setup
void injectCompatibleRoot();
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> GenCryptoContextWithModuliFrom(
    const lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>& params,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& sourceContext);
void liftSecretKey(lbcrypto::KeyPair<lbcrypto::DCRTPoly>& keyPair_main,
                   const lbcrypto::KeyPair<lbcrypto::DCRTPoly>& keyPair_trace);

// Test data for PDQ
struct TestData {
    std::vector<int64_t> keys;
    std::vector<int64_t> values;
    std::vector<int> matching_indices;
    int64_t query_value;
};

TestData generateTestData(int seed = 42);

// Encrypted database: keys and values
struct EncryptedDB {
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> keys;
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> values;
};

EncryptedDB encryptDB(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
    const TestData& data);
