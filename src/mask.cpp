#include "mask.h"
#include "global.h"

using namespace lbcrypto;

std::vector<Ciphertext<DCRTPoly>> mask(
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_values,
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_index) {

    auto context = ctxt_values[0]->GetCryptoContext();

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(ctxt_values.size());

    for (size_t i = 0; i < ctxt_values.size(); i++) {
        result.push_back(context->EvalMult(ctxt_values[i], ctxt_index[i]));
    }

    return result;
}
