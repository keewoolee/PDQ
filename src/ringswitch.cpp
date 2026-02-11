#include "ringswitch.h"
#include "global.h"

using namespace lbcrypto;

namespace {

int64_t modpow(int64_t base, int64_t exp, int64_t mod) {
    base %= mod;
    if (base < 0) base += mod;
    int64_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Precompute twiddle factors applied during coefficient extraction.
// twiddles[r][k-1] for r=0..d-1, k=1..d-1
// Slot j' of twiddle (r,k):
//   First half:  (ζ^{τ^r · 5^{j'} mod m})^k
//   Second half: (ζ^{-(τ^r · 5^{j'} mod m)})^k
// where τ = 5^{n'/2} mod m, m = 2n.
std::vector<std::vector<DCRTPoly>> precomputeTwiddles(
    const CryptoContext<DCRTPoly>& context_trace) {

    int64_t p = ptxt_modulus;
    int64_t m = 2 * degree;

    // Compute ζ (primitive m-th root of unity mod p)
    NativeInteger zeta_ni = RootOfUnity<NativeInteger>(m, NativeInteger(p));
    int64_t zeta = static_cast<int64_t>(zeta_ni.ConvertToInt());

    // τ = 5^{n'/2} mod m
    int64_t tau = modpow(5, degree_trace_half, m);

    // τ^r mod m for r = 0..d-1
    std::vector<int64_t> tau_r(dim_trace);
    tau_r[0] = 1;
    for (int r = 1; r < dim_trace; r++)
        tau_r[r] = tau_r[r-1] * tau % m;

    std::vector<std::vector<DCRTPoly>> twiddles(dim_trace,
        std::vector<DCRTPoly>(dim_trace - 1));

    for (int r = 0; r < dim_trace; r++) {
        for (int k = 1; k < dim_trace; k++) {
            // Build slot vector
            std::vector<int64_t> slot_vec(degree_trace);

            int64_t pow5 = 1;
            for (int jp = 0; jp < degree_trace_half; jp++) {
                int64_t base_exp = tau_r[r] * pow5 % m;

                // First half: ζ^{k · base_exp mod m} mod p
                slot_vec[jp] = modpow(zeta, k * base_exp % m, p);

                // Second half: ζ^{m - (k · base_exp mod m)} mod p
                int64_t neg_exp = (m - k * base_exp % m) % m;
                slot_vec[degree_trace_half + jp] = modpow(zeta, neg_exp, p);

                pow5 = pow5 * 5 % m;
            }

            // Encode slot vector → DCRTPoly via packed encoding
            auto pt = context_trace->MakePackedPlaintext(slot_vec);
            DCRTPoly tw = pt->GetElement<DCRTPoly>();
            if (tw.GetFormat() != Format::EVALUATION)
                tw.SwitchFormat();

            twiddles[r][k-1] = std::move(tw);
        }
    }

    return twiddles;
}

void ringswitchCore(
    const Ciphertext<DCRTPoly>& ciphertext,
    const CryptoContext<DCRTPoly>& context_trace,
    const std::string& keyTag,
    const std::vector<std::vector<DCRTPoly>>& twiddles,
    std::vector<Ciphertext<DCRTPoly>>& result) {

    size_t numLimbs = ciphertext->GetElements()[0].GetNumOfElements();

    auto poly_main = ciphertext->GetElements();
    for (int i = 0; i < 2; i++) {
        poly_main[i].SwitchFormat();
    }

    auto traceParams = context_trace->GetCryptoParameters()->GetElementParams();

    // acc[r][i]: accumulator for output ciphertext r, component i
    std::vector<std::vector<DCRTPoly>> acc(dim_trace, std::vector<DCRTPoly>(2));
    for (int r = 0; r < dim_trace; r++) {
        for (int i = 0; i < 2; i++) {
            acc[r][i] = DCRTPoly(traceParams, Format::EVALUATION, true);
        }
    }

    for (int chunk = 0; chunk < dim_trace; chunk++) {
        // Extract coefficients at offset chunk with stride dim_trace
        std::vector<DCRTPoly> poly_trace(2);
        for (int i = 0; i < 2; i++) {
            poly_trace[i] = DCRTPoly(traceParams, Format::COEFFICIENT, true);
            for (size_t limb = 0; limb < numLimbs; limb++) {
                auto limb_main = poly_main[i].GetElementAtIndex(limb);
                auto limb_trace = poly_trace[i].GetElementAtIndex(limb);
                for (int k = 0; k < degree_trace; k++) {
                    limb_trace[k] = limb_main[dim_trace * k + chunk];
                }
                poly_trace[i].SetElementAtIndex(limb, limb_trace);
            }
            poly_trace[i].SwitchFormat();
        }

        // Fused multiply-accumulate
        if (chunk == 0) {
            for (int r = 0; r < dim_trace; r++) {
                for (int i = 0; i < 2; i++) {
                    acc[r][i] += poly_trace[i];
                }
            }
        } else {
            for (int r = 0; r < dim_trace; r++) {
                for (int i = 0; i < 2; i++) {
                    acc[r][i] += twiddles[r][chunk-1] * poly_trace[i];
                }
            }
        }
    }

    // Construct d ciphertexts from accumulators
    for (int r = 0; r < dim_trace; r++) {
        auto ctxt_trace = std::make_shared<CiphertextImpl<DCRTPoly>>(context_trace);
        ctxt_trace->SetElements({acc[r][0], acc[r][1]});
        ctxt_trace->SetKeyTag(keyTag);
        ctxt_trace->SetEncodingType(PACKED_ENCODING);
        result.push_back(std::move(ctxt_trace));
    }
}

}  // namespace

std::vector<Ciphertext<DCRTPoly>> ringswitch(
    const CryptoContext<DCRTPoly>& context_trace,
    const std::string& keyTag,
    const EvalKey<DCRTPoly>& switch_key,
    const std::vector<Ciphertext<DCRTPoly>>& ctxts) {

    auto context_main = ctxts[0]->GetCryptoContext();
    size_t towers = context_trace->GetCryptoParameters()
                        ->GetElementParams()->GetParams().size();

    // Precompute twiddles once (depends only on context_trace and globals)
    static auto twiddles = precomputeTwiddles(context_trace);

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(ctxts.size() * dim_trace);

    for (const auto& ctxt : ctxts) {
        auto ctxt_switched = context_main->Compress(ctxt, towers);
        context_main->GetScheme()->KeySwitchInPlace(ctxt_switched, switch_key);
        ringswitchCore(ctxt_switched, context_trace, keyTag, twiddles, result);
    }

    return result;
}
