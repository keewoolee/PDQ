#pragma once

#include "openfhe.h"
#include <vector>
#include <set>

// Full decompression: decrypt and recover from combined digest
std::vector<std::pair<int64_t, int64_t>> recover(
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ctxt_digest);

// Verify correctness against ground truth
bool checkResult(
    const std::vector<std::pair<int64_t, int64_t>>& recovered,
    const std::vector<int64_t>& original_db,
    const std::set<int64_t>& true_indices
);
