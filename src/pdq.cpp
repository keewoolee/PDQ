#include "pdq.h"
#include "global.h"
#include "setup.h"
#include "match.h"
#include "mask.h"
#include "ringswitch.h"
#include "compress.h"
#include "decompress.h"
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <set>
#include <chrono>

using namespace lbcrypto;

namespace {

double getFileSizeKB(const std::string& path) {
    return static_cast<double>(std::filesystem::file_size(path)) / 1024.0;
}

}  // namespace

void pdq() {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point t_start, t_end;

    updateGlobal();
    injectCompatibleRoot();

    // Create main context
    CCParams<CryptoContextBFVRNS> params;
    initBFVParams(params);
    auto context = GenCryptoContext(params);
    enableFeatures(context);

    // Generate main keys
    auto keypair = context->KeyGen();
    context->EvalMultKeyGen(keypair.secretKey);

    // Create trace context with matching moduli from main context
    CCParams<CryptoContextBFVRNS> params_trace;
    initBFVParams_trace(params_trace);
    auto context_trace = GenCryptoContextWithModuliFrom(params_trace, context);
    enableFeatures(context_trace);

    // TODO: Investigate why this is needed. Without this dummy MakePackedPlaintext
    // call on the main context, packed encoding fails silently after ring-switch.
    (void)context->MakePackedPlaintext(std::vector<int64_t>(degree, 0));

    // Generate trace keys
    auto keypair_trace = context_trace->KeyGen();
    context_trace->EvalMultKeyGen(keypair_trace.secretKey);
    auto rotIndices = computeRotationIndices();
    if (!rotIndices.empty()) {
        context_trace->EvalRotateKeyGen(keypair_trace.secretKey, rotIndices);
    }

    // Generate switch target keypair in MAIN context and lift it
    auto keypair_switch_target = context->KeyGen();
    liftSecretKey(keypair_switch_target, keypair_trace);

    // Create switch key: main key -> lifted key (both in main context)
    auto switch_key = context->GetScheme()->KeySwitchGen(
        keypair.secretKey, keypair_switch_target.secretKey);

    // Generate and encrypt test data
    auto testData = generateTestData();
    auto encryptedDB = encryptDB(context, keypair.publicKey, testData);
    auto ctxt_query = context->Encrypt(keypair.publicKey,
        context->MakePackedPlaintext(std::vector<int64_t>(degree, testData.query_value)));

    std::cout << "Setup complete. Starting benchmark...\n" << std::endl;

    // =========================================================================
    // Match
    // =========================================================================
    t_start = Clock::now();
    auto ctxt_index = match(encryptedDB.keys, ctxt_query);
    t_end = Clock::now();
    double time_match = std::chrono::duration<double>(t_end - t_start).count();
    std::cout << "Match time: " << time_match << "sec" << std::endl;

    // =========================================================================
    // Mask
    // =========================================================================
    t_start = Clock::now();
    auto ctxt_masked = mask(encryptedDB.values, ctxt_index);
    t_end = Clock::now();
    double time_mask = std::chrono::duration<double>(t_end - t_start).count();
    std::cout << "Mask time: " << time_mask << "sec" << std::endl;

    // =========================================================================
    // Ring-switch
    // =========================================================================
    t_start = Clock::now();
    auto ctxt_index_trace = ringswitch(context_trace, keypair_trace.publicKey->GetKeyTag(), switch_key, ctxt_index);
    auto ctxt_masked_trace = ringswitch(context_trace, keypair_trace.publicKey->GetKeyTag(), switch_key, ctxt_masked);
    t_end = Clock::now();
    double time_ringswitch = std::chrono::duration<double>(t_end - t_start).count();
    std::cout << "RingSwitch time: " << time_ringswitch << "sec" << std::endl;

    // =========================================================================
    // Compress
    // =========================================================================
    t_start = Clock::now();
    auto ctxt_digest = compress(ctxt_masked_trace, ctxt_index_trace);
    t_end = Clock::now();
    double time_compress = std::chrono::duration<double>(t_end - t_start).count();
    std::cout << "Compress time: " << time_compress << "sec" << std::endl;

    // =========================================================================
    // Decompress (client-side)
    // =========================================================================
    t_start = Clock::now();
    auto recovered = recover(keypair_trace.secretKey, ctxt_digest);
    t_end = Clock::now();
    double time_decompress = std::chrono::duration<double, std::milli>(t_end - t_start).count();
    std::cout << "Decompress time: " << time_decompress << "ms" << std::endl;

    // =========================================================================
    // Verification
    // =========================================================================
    std::set<int64_t> true_indices_set(testData.matching_indices.begin(), testData.matching_indices.end());
    bool correct = checkResult(recovered, testData.values, true_indices_set);
    std::cout << "\nVerification: " << (correct ? "PASSED" : "FAILED") << std::endl;

    // =========================================================================
    // Communication cost measurement
    // =========================================================================
    std::cout << "\n[Communication]" << std::endl;

    // Create data directory if it doesn't exist
    std::filesystem::create_directories("data");

    // Per-query: digest (server -> client)
    Serial::SerializeToFile("data/digest.bin", ctxt_digest, SerType::BINARY);
    std::cout << "Digest size: " << getFileSizeKB("data/digest.bin") << " KB" << std::endl;

    // Per-query: query ciphertext (client -> server)
    Serial::SerializeToFile("data/query.bin", ctxt_query, SerType::BINARY);
    std::cout << "Query size: " << getFileSizeKB("data/query.bin") << " KB" << std::endl;

    // One-time setup: eval mult key (main context)
    std::ofstream evalkey_file("data/evalkey.bin", std::ios::binary);
    context->SerializeEvalMultKey(evalkey_file, SerType::BINARY);
    evalkey_file.close();
    std::cout << "EvalKey size: " << getFileSizeKB("data/evalkey.bin") << " KB" << std::endl;

    // One-time setup: rotation keys (trace context)
    std::ofstream rotkey_file("data/rotkey.bin", std::ios::binary);
    context_trace->SerializeEvalAutomorphismKey(rotkey_file, SerType::BINARY);
    rotkey_file.close();
    std::cout << "RotKey size: " << getFileSizeKB("data/rotkey.bin") << " KB" << std::endl;

    // One-time setup: switch key
    Serial::SerializeToFile("data/swkey.bin", switch_key, SerType::BINARY);
    std::cout << "SwitchKey size: " << getFileSizeKB("data/swkey.bin") << " KB" << std::endl;
}
