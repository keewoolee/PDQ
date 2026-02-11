#pragma once

#include "openfhe.h"
#include <vector>

// Compress ring-switched ciphertexts into single digest with power sums and weighted sums
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> compress(
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxt_masked,
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxt_index);
