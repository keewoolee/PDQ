#include "decompress.h"
#include "global.h"

#include <NTL/ZZ_pXFactoring.h>
#include <iostream>

using namespace lbcrypto;

namespace {

// Reconstruct index set from power sums using Newton's identity + root-finding
std::set<int64_t> decompressIndex(const std::vector<int64_t>& w) {
    // Algorithm 1: ReconstIdx - recover index set from power sums
    // w[k] = sum of i^(k+1) for all matching indices i (0-indexed)
    int s = w.size();
    std::set<int64_t> result;

    // Set NTL modulus
    NTL::ZZ_p::init(NTL::ZZ(ptxt_modulus));

    // Step 1: Compute elementary symmetric polynomials using Newton's identity
    // a_k = (1/k) * sum_{i=1}^{k} (-1)^{i-1} * a_{k-i} * w_{i-1}
    std::vector<NTL::ZZ_p> a(s + 1);
    a[0] = NTL::ZZ_p(1);

    for (int k = 1; k <= s; k++) {
        NTL::ZZ_p sum(0);
        for (int i = 1; i <= k; i++) {
            NTL::ZZ_p term = a[k - i] * NTL::ZZ_p(w[i - 1]);
            if (i % 2 == 1) {
                sum += term;
            } else {
                sum -= term;
            }
        }
        a[k] = sum * NTL::inv(NTL::ZZ_p(k));
    }

    // Step 2: Build polynomial f(X) = sum_{k=0}^{s} (-1)^k * a_k * X^{s-k}
    // f(X) = X^s - a_1*X^{s-1} + a_2*X^{s-2} - ... + (-1)^s * a_s
    NTL::ZZ_pX f;
    for (int k = 0; k <= s; k++) {
        NTL::ZZ_p coeff = a[k];
        if (k % 2 == 1) {
            coeff = -coeff;
        }
        NTL::SetCoeff(f, s - k, coeff);
    }

    // Step 3: Find roots using NTL's factorization
    NTL::vec_pair_ZZ_pX_long factors;
    NTL::CanZass(factors, f);

    // Extract linear factors (roots)
    for (long i = 0; i < factors.length(); i++) {
        if (NTL::deg(factors[i].a) == 1) {
            // Linear factor (X - root) -> root = -constant/leading
            NTL::ZZ_p root = -NTL::ConstTerm(factors[i].a) / NTL::LeadCoeff(factors[i].a);
            long root_val = NTL::conv<long>(NTL::rep(root));
            if (root_val > 0 && root_val <= num_records) {
                // Convert from 1-based index to 0-based
                result.insert(root_val - 1);
            }
        }
    }

    return result;
}

// Reconstruct data values from compressed data and index set
// Uses transposed Björck-Pereyra algorithm for Vandermonde systems (O(s²))
std::vector<std::pair<int64_t, int64_t>> reconstruct(
    const std::vector<int64_t>& e,
    const std::set<int64_t>& index_set) {

    std::vector<std::pair<int64_t, int64_t>> result;
    int ell = index_set.size();

    if (ell == 0) return result;

    NTL::ZZ_p::init(NTL::ZZ(ptxt_modulus));

    std::vector<int64_t> indices(index_set.begin(), index_set.end());

    // Nodes: x_k = indices[k] + 1 (1-based)
    std::vector<NTL::ZZ_p> x(ell);
    for (int k = 0; k < ell; k++)
        x[k] = NTL::ZZ_p((indices[k] + 1) % ptxt_modulus);

    // The system is C * d = e where C[j][k] = x_k^{j+1}.
    // Substituting d'_k = x_k * d_k gives the transposed Vandermonde:
    //   W * d' = e  where W[j][k] = x_k^j
    std::vector<NTL::ZZ_p> w(ell);
    for (int j = 0; j < ell; j++)
        w[j] = NTL::ZZ_p(e[j]);

    // Phase 1: Forward elimination
    for (int i = 0; i < ell - 1; i++)
        for (int j = ell - 1; j >= i + 1; j--)
            w[j] = w[j] - x[i] * w[j-1];

    // Phase 2: Divided differences + back substitution
    for (int i = ell - 2; i >= 0; i--) {
        for (int j = i + 1; j < ell; j++)
            w[j] = w[j] / (x[j] - x[j-i-1]);
        for (int j = i; j < ell - 1; j++)
            w[j] = w[j] - w[j+1];
    }

    // w[k] = d'_k = x_k * d_k, so d_k = w[k] / x_k
    for (int k = 0; k < ell; k++) {
        int64_t idx = indices[k];
        int64_t val = NTL::conv<long>(NTL::rep(w[k] / x[k]));
        result.push_back({idx, val});
    }

    return result;
}

}  // namespace

std::vector<std::pair<int64_t, int64_t>> recover(
    const PrivateKey<DCRTPoly>& sk,
    const Ciphertext<DCRTPoly>& ctxt_digest) {

    auto context = ctxt_digest->GetCryptoContext();

    // Decrypt combined digest
    Plaintext ptxt;
    context->Decrypt(sk, ctxt_digest, &ptxt);
    ptxt->SetLength(numrow_po2 + num_matching);
    auto vals = ptxt->GetPackedValue();

    // Extract e from first repetition [0, num_matching)
    // Extract w from second repetition [numrow_po2, numrow_po2 + num_matching)
    std::vector<int64_t> e(num_matching);
    std::vector<int64_t> w(num_matching);

    for (int j = 0; j < num_matching; j++) {
        e[j] = ((vals[j] % ptxt_modulus) + ptxt_modulus) % ptxt_modulus;
        w[j] = ((vals[numrow_po2 + j] % ptxt_modulus) + ptxt_modulus) % ptxt_modulus;
    }

    // Reconstruct index set from power sums w
    auto index_set = decompressIndex(w);

    // Reconstruct data from e and index set
    return reconstruct(e, index_set);
}

bool checkResult(
    const std::vector<std::pair<int64_t, int64_t>>& recovered,
    const std::vector<int64_t>& original_db,
    const std::set<int64_t>& true_indices
) {
    // Verify correctness: check that recovered (index, value) pairs match ground truth

    // Check that we recovered the correct number of entries
    if (recovered.size() != true_indices.size()) {
        std::cout << "  Index count mismatch: recovered " << recovered.size()
                  << ", expected " << true_indices.size() << std::endl;
        return false;
    }

    // Check each recovered entry
    bool success = true;
    for (const auto& [idx, val] : recovered) {
        // Check index is in true set
        if (true_indices.find(idx) == true_indices.end()) {
            std::cout << "  Unexpected index: " << idx << std::endl;
            success = false;
            continue;
        }

        // Check value matches
        if (idx < static_cast<int64_t>(original_db.size()) && original_db[idx] != val) {
            std::cout << "  Value mismatch at index " << idx
                      << ": recovered " << val << ", expected " << original_db[idx] << std::endl;
            success = false;
        }
    }

    return success;
}
