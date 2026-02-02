#include "match.h"
#include "global.h"

using namespace lbcrypto;

namespace {

// Equality check using Fermat's Little Theorem
// Returns 1 if x == 0, 0 otherwise
// Computes: 1 - x^(p-1) where p = ptxt_modulus
Ciphertext<DCRTPoly> equalityCheck(const Ciphertext<DCRTPoly>& ctxt) {
    auto context = ctxt->GetCryptoContext();

    // Square-and-multiply for x^(p-1)
    Ciphertext<DCRTPoly> result;
    Ciphertext<DCRTPoly> curr = ctxt;

    int64_t exp = ptxt_modulus - 1;
    bool first = true;

    while (exp > 0) {
        if (exp % 2 == 0) {
            exp /= 2;
            context->EvalSquareInPlace(curr);
        } else {
            exp -= 1;
            if (first) {
                result = curr;
                first = false;
            } else {
                result = context->EvalMult(result, curr);
            }
        }
    }

    // Return 1 - x^(p-1)
    std::vector<int64_t> ones(degree, 1);
    Plaintext ptxt_one = context->MakePackedPlaintext(ones);
    return context->EvalSub(ptxt_one, result);
}

}  // namespace

std::vector<Ciphertext<DCRTPoly>> match(
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_db,
    const Ciphertext<DCRTPoly>& ctxt_query) {

    auto context = ctxt_query->GetCryptoContext();

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(ctxt_db.size());

    for (const auto& ctxt_db_i : ctxt_db) {
        auto diff = context->EvalSub(ctxt_db_i, ctxt_query);
        auto match = equalityCheck(diff);
        result.push_back(match);
    }

    return result;
}
