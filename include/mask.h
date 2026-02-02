#pragma once

#include "openfhe.h"
#include <vector>

// Mask values with index indicators
std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> mask(
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxt_values,
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxt_index);
