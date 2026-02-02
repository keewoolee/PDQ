#pragma once

#include "openfhe.h"
#include <vector>

// Match query against encrypted database
std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> match(
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ctxt_db,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ctxt_query);
