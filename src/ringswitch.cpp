#include "ringswitch.h"
#include "global.h"

using namespace lbcrypto;

namespace {

std::vector<Ciphertext<DCRTPoly>> ringswitchCore(
    const Ciphertext<DCRTPoly>& ciphertext,
    const CryptoContext<DCRTPoly>& context_trace,
    const PublicKey<DCRTPoly>& publicKey_trace) {

    auto context_main = ciphertext->GetCryptoContext();

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(dim_trace);

    // Compute level for plaintext to match ciphertext tower count
    size_t totalTowers = context_main->GetCryptoParameters()->GetElementParams()->GetParams().size();
    size_t ctxtTowers = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t level = totalTowers - ctxtTowers;
    size_t numLimbs = ctxtTowers;  // After compress, ciphertext has same limbs as trace context

    for (int chunk = 0; chunk < dim_trace; chunk++) {
        // Create masking vector for this chunk
        std::vector<int64_t> vec_mask(degree, 0);
        for (int i = 0; i < degree_trace_half; i++) {
            vec_mask[chunk * degree_trace_half + i] = dim_trace;
            vec_mask[degree_half + chunk * degree_trace_half + i] = dim_trace;
        }
        auto ptxt_mask = context_main->MakePackedPlaintext(vec_mask, 1, level);

        // Apply masking
        auto ctxt_masked = context_main->EvalMult(ciphertext, ptxt_mask);

        // Create trace context ciphertext shell (encrypting zeros to get proper structure)
        auto ctxt_trace = context_trace->Encrypt(publicKey_trace,
            context_trace->MakePackedPlaintext(std::vector<int64_t>(degree_trace, 0)));

        // Extract coefficients at positions 0, dim_trace, 2*dim_trace, ...
        auto poly_main = ctxt_masked->GetElements();
        auto poly_trace = ctxt_trace->GetElements();

        for (int i = 0; i < 2; i++) {
            poly_main[i].SwitchFormat();
            poly_trace[i].SwitchFormat();
        }

        for (int i = 0; i < 2; i++) {
            for (size_t limb = 0; limb < numLimbs; limb++) {
                auto limb_main = poly_main[i].GetElementAtIndex(limb);
                auto limb_trace = poly_trace[i].GetElementAtIndex(limb);
                for (int k = 0; k < degree_trace; k++) {
                    limb_trace[k] = limb_main[dim_trace * k];
                }
                poly_trace[i].SetElementAtIndex(limb, limb_trace);
            }
        }

        for (int i = 0; i < 2; i++) {
            poly_trace[i].SwitchFormat();
        }

        ctxt_trace->SetElements(poly_trace);
        result.push_back(ctxt_trace);
    }

    return result;
}

}  // namespace

std::vector<Ciphertext<DCRTPoly>> ringswitch(
    const CryptoContext<DCRTPoly>& context_trace,
    const PublicKey<DCRTPoly>& publicKey_trace,
    const EvalKey<DCRTPoly>& switch_key,
    const std::vector<Ciphertext<DCRTPoly>>& ctxts) {

    auto context_main = ctxts[0]->GetCryptoContext();
    size_t towers = context_trace->GetCryptoParameters()
                        ->GetElementParams()->GetParams().size();

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(ctxts.size() * dim_trace);

    for (const auto& ctxt : ctxts) {
        // Compress and key-switch
        auto ctxt_switched = context_main->Compress(ctxt, towers);
        context_main->GetScheme()->KeySwitchInPlace(ctxt_switched, switch_key);

        // Apply ring-switch (masking + coefficient extraction)
        for (auto& tc : ringswitchCore(ctxt_switched, context_trace, publicKey_trace)) {
            result.push_back(tc);
        }
    }
    return result;
}
