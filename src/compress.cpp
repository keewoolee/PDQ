#include "compress.h"
#include "global.h"

using namespace lbcrypto;

namespace {

std::vector<std::vector<int64_t>> buildVandermondeMatrix() {
    std::vector<std::vector<int64_t>> C(num_matching, std::vector<int64_t>(num_records));

    for (int i = 0; i < num_records; i++) {
        int64_t val = 1;
        int64_t base = (i + 1) % ptxt_modulus;
        for (int j = 0; j < num_matching; j++) {
            val = (val * base) % ptxt_modulus;
            C[j][i] = val;
        }
    }

    return C;
}

// Precomputed BSGS plaintexts: ptxts[g_][i][b]
using BSGSPlaintexts = std::vector<std::vector<std::vector<Plaintext>>>;

// Precompute all plaintexts for BSGS matrix-vector multiply.
// After ring-switching, each main ciphertext produces dim_trace trace ciphertexts.
// Trace ciphertext i has the following slot-to-db_idx mapping:
//   slot j:                     db_idx = orig_ctxt_idx * degree + trace_idx * degree_trace_half + j
//   slot degree_trace_half + j: db_idx = orig_ctxt_idx * degree + degree_half + trace_idx * degree_trace_half + j
BSGSPlaintexts precomputeBSGSPlaintexts(
    const std::vector<std::vector<int64_t>>& M,
    const CryptoContext<DCRTPoly>& context) {

    int num_trace_ctxts = num_ctxts * dim_trace;

    BSGSPlaintexts ptxts(g_bsgs,
        std::vector<std::vector<Plaintext>>(num_trace_ctxts,
            std::vector<Plaintext>(b_bsgs)));

    std::vector<int64_t> ptxt_vec(degree_trace);

    for (int g_ = 0; g_ < g_bsgs; g_++) {
        int g = g_bsgs - g_ - 1;

        for (int i = 0; i < num_trace_ctxts; i++) {
            int orig_ctxt_idx = i / dim_trace;
            int trace_idx = i % dim_trace;

            for (int b = 0; b < b_bsgs; b++) {
                if (g * b_bsgs + b >= numrow_po2) break;

                int idxr = (numrow_po2 - g * b_bsgs) % numrow_po2;

                for (int k1 = 0; k1 < degree_trace_half; k1++) {
                    int j = (k1 + b) % degree_trace_half;
                    int row = (idxr + k1) % numrow_po2;

                    // First half
                    int db_idx = orig_ctxt_idx * degree + trace_idx * degree_trace_half + j;
                    ptxt_vec[k1] = (row < num_matching && db_idx < num_records)
                        ? M[row][db_idx] : 0;

                    // Second half
                    int db_idx2 = orig_ctxt_idx * degree + degree_half + trace_idx * degree_trace_half + j;
                    ptxt_vec[degree_trace_half + k1] = (row < num_matching && db_idx2 < num_records)
                        ? M[row][db_idx2] : 0;
                }

                ptxts[g_][i][b] = context->MakePackedPlaintext(ptxt_vec);
            }
        }
    }

    return ptxts;
}

// BSGS matrix-vector multiply using precomputed plaintexts.
Ciphertext<DCRTPoly> evalBSGS(
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_v,
    const BSGSPlaintexts& ptxts) {

    auto context = ctxt_v[0]->GetCryptoContext();
    int num_trace_ctxts = ctxt_v.size();

    std::vector<std::vector<Ciphertext<DCRTPoly>>> rotated(num_trace_ctxts,
        std::vector<Ciphertext<DCRTPoly>>(b_bsgs));
    for (int i = 0; i < num_trace_ctxts; i++) {
        rotated[i][0] = ctxt_v[i];
        for (int b = 1; b < b_bsgs; b++) {
            rotated[i][b] = context->EvalRotate(rotated[i][b-1], 1);
        }
    }

    std::vector<Ciphertext<DCRTPoly>> giant(num_trace_ctxts);
    Ciphertext<DCRTPoly> digest;

    for (int g_ = 0; g_ < g_bsgs; g_++) {
        int g = g_bsgs - g_ - 1;

        for (int i = 0; i < num_trace_ctxts; i++) {
            for (int b = 0; b < b_bsgs; b++) {
                if (g * b_bsgs + b >= numrow_po2) break;

                if (b == 0) {
                    giant[i] = context->EvalMult(rotated[i][b], ptxts[g_][i][b]);
                } else {
                    context->EvalAddInPlace(giant[i],
                        context->EvalMult(rotated[i][b], ptxts[g_][i][b]));
                }
            }
        }

        Ciphertext<DCRTPoly> sum = giant[0];
        for (int i = 1; i < num_trace_ctxts; i++) {
            context->EvalAddInPlace(sum, giant[i]);
        }

        if (g_ == 0) {
            digest = sum;
        } else {
            digest = context->EvalRotate(digest, b_bsgs);
            context->EvalAddInPlace(digest, sum);
        }
    }

    for (int j = 1; j < degree_trace_half / numrow_po2; j *= 2) {
        auto temp = context->EvalRotate(digest, numrow_po2 * j);
        context->EvalAddInPlace(digest, temp);
    }
    auto temp = context->EvalRotate(digest, degree_trace_half);
    context->EvalAddInPlace(digest, temp);

    return digest;
}

}  // namespace

Ciphertext<DCRTPoly> compress(
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_masked,
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_index) {

    auto context = ctxt_masked[0]->GetCryptoContext();

    static auto C = buildVandermondeMatrix();

    auto ptxts = precomputeBSGSPlaintexts(C, context);
    auto ctxt_e = evalBSGS(ctxt_masked, ptxts);
    auto ctxt_w = evalBSGS(ctxt_index, ptxts);

    // Build masks to isolate different repetitions
    // mask_e: 1s in first repetition [0, numrow_po2), 0s elsewhere
    // mask_w: 1s in second repetition [numrow_po2, 2*numrow_po2), 0s elsewhere
    std::vector<int64_t> mask_e_vec(degree_trace, 0);
    std::vector<int64_t> mask_w_vec(degree_trace, 0);

    for (int j = 0; j < numrow_po2; j++) {
        mask_e_vec[j] = 1;
        mask_e_vec[degree_trace_half + j] = 1;
        mask_w_vec[numrow_po2 + j] = 1;
        mask_w_vec[degree_trace_half + numrow_po2 + j] = 1;
    }

    auto mask_e = context->MakePackedPlaintext(mask_e_vec);
    auto mask_w = context->MakePackedPlaintext(mask_w_vec);

    // Mask and combine into single ciphertext
    auto ctxt_e_masked = context->EvalMult(ctxt_e, mask_e);
    auto ctxt_w_masked = context->EvalMult(ctxt_w, mask_w);
    auto digest = context->EvalAdd(ctxt_e_masked, ctxt_w_masked);

    // Compress to reduce number of limbs
    digest = context->Compress(digest, 1);

    return digest;
}
