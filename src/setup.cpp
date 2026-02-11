#include "setup.h"
#include "global.h"
#include "encoding/encodingparams.h"
#include <random>
#include <algorithm>
#include <cmath>

using namespace lbcrypto;

// =============================================================================
// Global initialization
// =============================================================================

void updateGlobal() {
    degree_half = degree / 2;
    degree_trace_half = degree_trace / 2;
    dim_trace = degree / degree_trace;
    num_ctxts = (num_records + degree - 1) / degree;
    numrow_po2 = 1;
    while (numrow_po2 < num_matching) numrow_po2 *= 2;

    // BSGS split: minimize total rotations = numctxt*(b-1) + (g-1)
    // Baby rotations are per-ciphertext, so optimal b = sqrt(numrow_po2 / numctxt)
    int numctxt_total = num_ctxts * dim_trace;
    b_bsgs = std::max(1, static_cast<int>(std::round(
        std::sqrt(static_cast<double>(numrow_po2) / numctxt_total))));
    g_bsgs = static_cast<int>(std::ceil(static_cast<double>(numrow_po2) / b_bsgs));
}

// =============================================================================
// Context setup
// =============================================================================

void initBFVParams(CCParams<CryptoContextBFVRNS>& params) {
    params.SetPlaintextModulus(ptxt_modulus);
    params.SetRingDim(degree);
    params.SetMultiplicativeDepth(MultiplicativeDepth);
    params.SetScalingModSize(ScalingModSize);
    params.SetNumLargeDigits(NumLargeDigits);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetSecurityLevel(HEStd_128_classic);
}

void initBFVParams_trace(CCParams<CryptoContextBFVRNS>& params) {
    params.SetPlaintextModulus(ptxt_modulus);
    params.SetRingDim(degree_trace);
    params.SetMultiplicativeDepth(MultiplicativeDepth_trace);
    params.SetScalingModSize(ScalingModSize);
    params.SetNumLargeDigits(NumLargeDigits_trace);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetSecurityLevel(HEStd_128_classic);
}

void enableFeatures(CryptoContext<DCRTPoly>& context) {
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
}

std::vector<int32_t> computeRotationIndices() {
    std::vector<int32_t> rots;

    // Baby step: only rotation by 1 is used (applied iteratively)
    rots.push_back(1);

    // Giant step: only rotation by b_bsgs is used (applied iteratively)
    if (b_bsgs > 1) {
        rots.push_back(b_bsgs);
    }

    // Power-of-2 aggregation rotations
    for (int j = 1; j < degree_trace_half / numrow_po2; j *= 2) {
        rots.push_back(numrow_po2 * j);
    }

    // Half rotation for combining both halves
    rots.push_back(degree_trace_half);

    return rots;
}

// =============================================================================
// Ring-switch setup
// =============================================================================

void injectCompatibleRoot() {
    uint32_t mMain = 2 * degree;
    uint32_t mTrace = 2 * degree_trace;
    NativeInteger p(ptxt_modulus);

    NativeInteger zetaMain = RootOfUnity<NativeInteger>(mMain, p);
    NativeInteger zetaTrace = zetaMain.ModExp(dim_trace, p);

    PackedEncoding::Destroy();

    auto mainParams = std::make_shared<EncodingParamsImpl>(ptxt_modulus);
    mainParams->SetPlaintextRootOfUnity(zetaMain);
    PackedEncoding::SetParams(mMain, mainParams);

    auto traceParams = std::make_shared<EncodingParamsImpl>(ptxt_modulus);
    traceParams->SetPlaintextRootOfUnity(zetaTrace);
    PackedEncoding::SetParams(mTrace, traceParams);
}

CryptoContext<DCRTPoly> GenCryptoContextWithModuliFrom(
    const CCParams<CryptoContextBFVRNS>& params,
    const CryptoContext<DCRTPoly>& sourceContext) {

    auto cc = GenCryptoContext(params);

    auto sourceElemParams = sourceContext->GetCryptoParameters()->GetElementParams();
    auto targetElemParams = cc->GetCryptoParameters()->GetElementParams();

    size_t numTowers = std::min(targetElemParams->GetParams().size(),
                                sourceElemParams->GetParams().size());

    std::vector<NativeInteger> moduli(numTowers);
    std::vector<NativeInteger> roots(numTowers);
    for (size_t i = 0; i < numTowers; i++) {
        moduli[i] = sourceElemParams->GetParams()[i]->GetModulus();
        auto sourceRoot = sourceElemParams->GetParams()[i]->GetRootOfUnity();
        roots[i] = sourceRoot.ModExp(NativeInteger(dim_trace), moduli[i]);
    }

    auto elementParams = std::make_shared<ILDCRTParams<BigInteger>>(
        2 * degree_trace, moduli, roots);

    auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(
        std::const_pointer_cast<CryptoParametersBase<DCRTPoly>>(cc->GetCryptoParameters()));
    cryptoParams->SetElementParams(elementParams);
    cryptoParams->PrecomputeCRTTables(
        cryptoParams->GetKeySwitchTechnique(),
        cryptoParams->GetScalingTechnique(),
        cryptoParams->GetEncryptionTechnique(),
        cryptoParams->GetMultiplicationTechnique(),
        cryptoParams->GetNumPerPartQ(),
        cryptoParams->GetAuxBits(),
        cryptoParams->GetExtraBits());

    return cc;
}

void liftSecretKey(KeyPair<DCRTPoly>& keyPair_main,
                   const KeyPair<DCRTPoly>& keyPair_trace) {
    auto sk_main = keyPair_main.secretKey->GetPrivateElement();
    auto sk_trace = keyPair_trace.secretKey->GetPrivateElement();

    sk_main.SwitchFormat();
    sk_trace.SwitchFormat();

    // Use first limb of trace key (ternary values are same across all limbs)
    auto limb_trace = sk_trace.GetElementAtIndex(0);

    for (size_t i = 0; i < sk_main.GetNumOfElements(); i++) {
        auto limb_main = sk_main.GetElementAtIndex(i);
        auto mod = limb_main.GetModulus();

        for (int j = 0; j < degree; j++) limb_main[j] = 0;
        for (int j = 0; j < degree_trace; j++) {
            auto val = limb_trace[j];
            if (val == 1) limb_main[j * dim_trace] = 1;
            else if (val != 0) limb_main[j * dim_trace] = mod - 1;
        }
        sk_main.SetElementAtIndex(i, limb_main);
    }

    sk_main.SwitchFormat();
    keyPair_main.secretKey->SetPrivateElement(sk_main);
}

// =============================================================================
// Test data
// =============================================================================

TestData generateTestData(int seed) {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<int64_t> val_dist(1, ptxt_modulus - 1);
    std::uniform_int_distribution<int> idx_dist(0, num_records - 1);

    TestData data;
    data.query_value = val_dist(gen);

    data.keys.resize(num_records);
    data.values.resize(num_records);
    for (int i = 0; i < num_records; i++) {
        do { data.keys[i] = val_dist(gen); } while (data.keys[i] == data.query_value);
        data.values[i] = val_dist(gen);
    }

    while (static_cast<int>(data.matching_indices.size()) < num_matching) {
        int idx = idx_dist(gen);
        if (std::find(data.matching_indices.begin(), data.matching_indices.end(), idx) == data.matching_indices.end()) {
            data.matching_indices.push_back(idx);
            data.keys[idx] = data.query_value;
        }
    }
    std::sort(data.matching_indices.begin(), data.matching_indices.end());

    return data;
}

EncryptedDB encryptDB(
    const CryptoContext<DCRTPoly>& context,
    const PublicKey<DCRTPoly>& publicKey,
    const TestData& data) {

    EncryptedDB db;
    for (int c = 0; c < num_ctxts; c++) {
        std::vector<int64_t> key_batch(degree, 0);
        std::vector<int64_t> val_batch(degree, 0);
        int start = c * degree;
        for (int i = 0; i < degree && start + i < num_records; i++) {
            key_batch[i] = data.keys[start + i];
            val_batch[i] = data.values[start + i];
        }
        db.keys.push_back(context->Encrypt(publicKey, context->MakePackedPlaintext(key_batch)));
        db.values.push_back(context->Encrypt(publicKey, context->MakePackedPlaintext(val_batch)));
    }
    return db;
}
