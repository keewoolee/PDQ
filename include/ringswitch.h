#pragma once

#include "openfhe.h"
#include <vector>

// Apply ring-switch to multiple ciphertexts
std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ringswitch(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context_trace,
    const std::string& keyTag,
    const lbcrypto::EvalKey<lbcrypto::DCRTPoly>& switch_key,
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxts);
