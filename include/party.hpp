#pragma once

#include "crypto.hpp"

using namespace std;
using namespace lbcrypto;
using namespace BS;

/* -------------------------------------- */

inline void encrypt_single(const CryptoContext<DCRTPoly> &bfv_ctx, const PK &pk, PT *pt, CT *ct)
{
  *ct = bfv_ctx->Encrypt(pk, *pt);
}

inline void encrypt_zero_single(const CryptoContext<DCRTPoly> &bfv_ctx, const PK &pk, CT *ct)
{
  PT pt;
  bfv_ctx->MakePackedPlaintext({0});
  *ct = bfv_ctx->Encrypt(pk, pt);
}

inline void subtract_single(const CryptoContext<DCRTPoly> &bfv_ctx, const CT *a, const PT *b, CT *res)
{
  *res = bfv_ctx->EvalSub(*a, *b);
}

inline void multiply_single(const CryptoContext<DCRTPoly> &bfv_ctx, const CT *a, const PT *b, CT *res)
{
  *res = bfv_ctx->EvalMult(*b, *a);
}

inline void add_single_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, CT *a, const CT *b)
{
  bfv_ctx->EvalAddInPlace(*a, *b);
}

inline void randomize_single_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, CT *a, size_t plain_mod, size_t ring_dim)
{
  random_device rd;
  mt19937 generator(rd());
  vector<int64_t> int_vec(ring_dim);

  for (size_t i = 0; i < ring_dim; i++)
  {
    int_vec[i] = generator() % plain_mod;
  }
  PT pt = bfv_ctx->MakePackedPlaintext(int_vec);
  CT res;
  multiply_single(bfv_ctx, a, &pt, &res);
  *a = res;
}

inline size_t decrypt_check_one(const CryptoContext<DCRTPoly> &bfv_ctx, const SK &sk, const CT *ct, size_t nbits, PackingType pack_type)
{
  PT pt;
  bfv_ctx->Decrypt(sk, *ct, &pt);

  if (pack_type == SINGLE)
  {
    vector<uint8_t> unpacked;
    unpack_bitwise_single(pt, &unpacked, nbits);
    return (size_t)is_zero(&unpacked);
  }

  vector<vector<uint8_t>> unpacked;
  size_t plain_mod_bits = get_bitsize(bfv_ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
  size_t num_hashes_per_pt = n_hashes_in_pt(pack_type, bfv_ctx->GetRingDimension(), plain_mod_bits, nbits);
  // cout << "num_hashes_per_pt = " << num_hashes_per_pt << endl;

  if (pack_type == MULTIPLE)
    unpack_bitwise_multiple(pt, &unpacked, num_hashes_per_pt, nbits);
  else if (pack_type == MULTIPLE_COMPACT)
    unpack_multiple_compact(pt, &unpacked, bits_to_bytes(nbits));

  size_t n_zeros = 0;
  for (size_t i = 0; i < num_hashes_per_pt; i++)
    n_zeros += (size_t)is_zero(&unpacked[i]);
  return n_zeros;
}

/* -------------------------------------- */

struct Party
{
  shared_ptr<CCParams<CryptoContextBFVRNS>> enc_parms;
  CryptoContext<DCRTPoly> bfv_ctx;
  ProtocolParameters pro_parms;

  Party() {}

  Party(shared_ptr<CCParams<CryptoContextBFVRNS>> &enc_parms_, ProtocolParameters &pro_parms_)
  {
    pro_parms = pro_parms_;
    enc_parms = enc_parms_;
    bfv_ctx = gen_crypto_ctx(enc_parms);
  }

  /* -------------------------------------- */

  size_t decrypt_check_all(const SK &sk, const vector<CT> &B)
  {
    // cout << "Decrypting " << B.size() << " ciphertexts." << endl;
    BS::thread_pool pool(pro_parms.num_threads);
    BS::multi_future<size_t> res_fut(B.size());
    size_t nbits = pro_parms.hash_sz * 8;
    size_t count = 0;
    for (size_t i = 0; i < B.size(); i++)
      res_fut[i] = pool.submit(decrypt_check_one, bfv_ctx, sk, &B[i], nbits, pro_parms.pack_type);
    vector<size_t> counts = res_fut.get();
    for (size_t i = 0; i < B.size(); i++)
      count += counts[i];
    return count;
  }

  void encrypt_all(vector<CT> &M, vector<PT> &pt)
  {
    // Stopwatch sw;
    // sw.start();
    M.resize(pt.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < M.size(); i++)
      pool.push_task(encrypt_single, bfv_ctx, pro_parms.pk, &pt[i], &M[i]);
    pool.wait_for_tasks();
    // printf("encrypted %lu plaintexts (took %5.2fs).", pt.size(), sw.elapsed());
  }

  void add_all_inplace(vector<CT> &A, const vector<CT> &B)
  {
    // Stopwatch sw;
    // sw.start();
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(add_single_inplace, bfv_ctx, &A[i], &B[i]);
    pool.wait_for_tasks();
    // printf("added %lu ciphertexts (took %5.2fs).", A.size(), sw.elapsed());
  }

  void multiply_all(const vector<CT> &A, const vector<PT> &B, vector<CT> &dest)
  {
    // Stopwatch sw;
    // sw.start();
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(multiply_single, bfv_ctx, &A[i], &B[i], &dest[i]);
    pool.wait_for_tasks();
    // printf("multiplied %lu plaintexts from ciphertexts (took %5.2fs).", B.size(), sw.elapsed());
  }

  void subtract_all(const vector<CT> &A, const vector<PT> &B, vector<CT> &dest)
  {
    // Stopwatch sw;
    // sw.start();
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(subtract_single, bfv_ctx, &A[i], &B[i], &dest[i]);
    pool.wait_for_tasks();
    // printf("subtracted %lu plaintexts from ciphertexts (took %5.2fs).", B.size(), sw.elapsed());
  }

  void randomize_all_inplace(vector<CT> &A)
  {
    // Stopwatch sw;
    // sw.start();
    thread_pool pool(pro_parms.num_threads);
    size_t plain_mod = bfv_ctx->GetCryptoParameters()->GetPlaintextModulus();
    size_t ring_dim = bfv_ctx->GetRingDimension();
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(randomize_single_inplace, bfv_ctx, &A[i], plain_mod, ring_dim);
    pool.wait_for_tasks();
    // printf("randomized %lu plaintexts from ciphertexts (took %5.2fs).", A.size(), sw.elapsed());
  }

  void prepare_hashmap(HashMap &hm, vector<PT> &hm_pt, vector<PT> &hm_1hot, vector<PT> &hm_0hot, const vector<string> &X)
  {
    hm.insert(X);
    hm.hot_encoding_mask(bfv_ctx, hm_1hot, false);
    hm.hot_encoding_mask(bfv_ctx, hm_0hot, true);
    hm.serialize(bfv_ctx, hm_pt, (pro_parms.party_id == 1));
  }

  /* -------------------------------------- */

  void compute_on_r(const vector<CT> *M, vector<CT> *R, const vector<string> &X, bool iu, bool run_sum)
  {
    Stopwatch sw;

    print_line();
    string protocol = string(iu ? "MPSIU" : "MPSI") + string(run_sum ? "-Sum" : "");
    cout << protocol << ": Party " << pro_parms.party_id << endl;
    print_line();

    sw.start();

    HashMap hm(pro_parms);
    size_t m_sz = M->size();
    vector<PT> hm_pt(m_sz), hm_1hot(m_sz), hm_0hot(m_sz);

    prepare_hashmap(hm, hm_pt, hm_1hot, hm_0hot, X);

    // Compute R => R + (M - Enc(hm))
    cout << "Computing R => R + (M - Enc(hm))" << endl;
    vector<CT> Mdiff_temp(m_sz);
    subtract_all(*M, hm_pt, Mdiff_temp);

    if (pro_parms.party_id == 1)
    {
      *R = Mdiff_temp;
    }
    else
    {
      if (iu)
      {
        vector<CT> Mdiff(m_sz), Rdiff(m_sz);
        multiply_all(Mdiff_temp, hm_1hot, Mdiff);
        multiply_all(*R, hm_0hot, Rdiff);
        add_all_inplace(Rdiff, Mdiff);
        *R = Rdiff;
      }
      else
      {
        vector<CT> Mdiff(m_sz);
        multiply_all(Mdiff_temp, hm_1hot, Mdiff);
        add_all_inplace(*R, Mdiff);
      }
    }

    // The last party randomizes the ciphertexts
    if (pro_parms.party_id == pro_parms.num_parties - 1)
      randomize_all_inplace(*R);

    printf("\nTime: %5.2fs\n", sw.elapsed());
  }
};
