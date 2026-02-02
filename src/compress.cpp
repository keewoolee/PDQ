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

// BSGS matrix-vector multiply for ring-switched ciphertexts.
//
// Ring-switch changes the slot layout. An original ciphertext with degree slots
// becomes dim_trace trace ciphertexts, each with degree_trace slots:
//   trace[k].slot[j]                   <- original slot k * degree_trace_half + j              (first half)
//   trace[k].slot[degree_trace_half + j]    <- original slot degree_half + k * degree_trace_half + j (second half)
//
// This function accounts for this mapping when building Vandermonde plaintext vectors.
Ciphertext<DCRTPoly> matVecMultBSGS(
    const std::vector<std::vector<int64_t>>& M,
    const std::vector<Ciphertext<DCRTPoly>>& ctxt_v) {

    auto context = ctxt_v[0]->GetCryptoContext();
    int numctxt = ctxt_v.size();

    std::vector<std::vector<Ciphertext<DCRTPoly>>> rotated(numctxt, std::vector<Ciphertext<DCRTPoly>>(b_bsgs));
    for (int i = 0; i < numctxt; i++) {
        rotated[i][0] = ctxt_v[i];
        for (int b = 1; b < b_bsgs; b++) {
            rotated[i][b] = context->EvalRotate(rotated[i][b-1], 1);
        }
    }

    std::vector<Ciphertext<DCRTPoly>> giant(numctxt);
    std::vector<int64_t> ptxt_vec(degree_trace);
    Ciphertext<DCRTPoly> digest;

    for (int g_ = 0; g_ < g_bsgs; g_++) {
        int g = g_bsgs - g_ - 1;

        for (int i = 0; i < numctxt; i++) {
            // i = orig_ctxt_idx * dim_trace + trace_idx
            int orig_ctxt_idx = i / dim_trace;
            int trace_idx = i % dim_trace;

            for (int b = 0; b < b_bsgs; b++) {
                if (g * b_bsgs + b >= numrow_po2) break;

                int idxr = (numrow_po2 - g * b_bsgs) % numrow_po2;

                // Fill plaintext vector with correct Vandermonde entries
                // After rotation by b, slot k1 contains original slot (k1 + b) mod degree_trace_half
                for (int k1 = 0; k1 < degree_trace_half; k1++) {
                    // First half: slot k1 after rotation by b contains original trace slot (k1+b) mod degree_trace_half
                    int orig_trace_slot = (k1 + b) % degree_trace_half;
                    // This came from original ciphertext slot: trace_idx * degree_trace_half + orig_trace_slot
                    int orig_slot = trace_idx * degree_trace_half + orig_trace_slot;
                    int record_idx = orig_ctxt_idx * degree + orig_slot;

                    int row = (idxr + k1) % numrow_po2;
                    if (row >= num_matching || record_idx >= num_records) {
                        ptxt_vec[k1] = 0;
                    } else {
                        ptxt_vec[k1] = M[row][record_idx];
                    }

                    // Second half: slot (degree_trace_half + k1) after rotation by b
                    // contains original trace slot degree_trace_half + (k1+b) mod degree_trace_half
                    // This came from original ciphertext slot: degree_half + trace_idx * degree_trace_half + (k1+b) mod degree_trace_half
                    int orig_slot2 = degree_half + trace_idx * degree_trace_half + (k1 + b) % degree_trace_half;
                    int record_idx2 = orig_ctxt_idx * degree + orig_slot2;

                    if (row >= num_matching || record_idx2 >= num_records) {
                        ptxt_vec[degree_trace_half + k1] = 0;
                    } else {
                        ptxt_vec[degree_trace_half + k1] = M[row][record_idx2];
                    }
                }

                auto ptxt = context->MakePackedPlaintext(ptxt_vec);

                if (b == 0) {
                    giant[i] = context->EvalMult(rotated[i][b], ptxt);
                } else {
                    context->EvalAddInPlace(giant[i], context->EvalMult(rotated[i][b], ptxt));
                }
            }
        }

        Ciphertext<DCRTPoly> sum = giant[0];
        for (int i = 1; i < numctxt; i++) {
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
    auto C = buildVandermondeMatrix();

    // Compute matrix-vector products (results are replicated across slots)
    auto ctxt_e = matVecMultBSGS(C, ctxt_masked);
    auto ctxt_w = matVecMultBSGS(C, ctxt_index);

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

