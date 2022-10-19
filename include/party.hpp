#pragma once

#include <bitset>
#include "crypto.hpp"

using namespace std;
using namespace lbcrypto;
using namespace BS;

/* -------------------------------------- */

inline void encrypt_single(const CryptoContext<DCRTPoly> &ctx, const PK &pk, PT *pt, CT *ct)
{
  *ct = ctx->Encrypt(pk, *pt);
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

inline void add_single_ct_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, CT *a, const CT *b)
{
  bfv_ctx->EvalAddInPlace(*a, *b);
}

inline void add_single_pt_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, CT *a, const PT *b)
{
  bfv_ctx->EvalAddInPlace(*a, *b);
}

// (a, b) \in (M, C)
inline void randomize_single_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, const CryptoContext<DCRTPoly> &ckks_ctx, CT *a, CT *b, size_t plain_mod, size_t ring_dim, size_t num_cf_per_hash)
{
  vector<int64_t> int_vec(ring_dim);

  for (size_t i = 0; i < ring_dim; i++)
    int_vec[i] = random_int(plain_mod);

  PT pt = bfv_ctx->MakePackedPlaintext(int_vec);
  CT res;
  multiply_single(bfv_ctx, a, &pt, &res);
  *a = res;

  if (b != nullptr)
  {
    vector<double> dbl_vec = {0.0};
    pt = ckks_ctx->MakeCKKSPackedPlaintext(dbl_vec);
    add_single_pt_inplace(ckks_ctx, b, &pt);
  }
  // else
  // {
  //   size_t num_hashes_per_pt = ring_dim / num_cf_per_hash;
  //   usint mult = 1 + (generator() % (num_hashes_per_pt - 1));
  //   bfv_ctx->EvalRotate(*a, mult * num_cf_per_hash);
  // }
}

inline void decrypt_check_one(const CryptoContext<DCRTPoly> &bfv_ctx, const SK &sk, const CT *ct, size_t nbits, PackingType pack_type, vector<bool> *ret, size_t batch_size)
{
  PT pt;
  bfv_ctx->Decrypt(sk, *ct, &pt);

  if (pack_type == SINGLE)
  {
    ret->resize(1);
    vector<uint8_t> unpacked;
    unpack_bitwise_single(pt, &unpacked, nbits);
    (*ret)[0] = is_zero(&unpacked);
    return;
  }

  vector<vector<uint8_t>> unpacked;
  if (pack_type == MULTIPLE)
    unpack_bitwise_multiple(pt, &unpacked, batch_size, nbits);
  else if (pack_type == MULTIPLE_COMPACT)
    unpack_multiple_compact(pt, &unpacked, bits_to_bytes(nbits));

  ret->resize(batch_size);
  for (size_t i = 0; i < batch_size; i++)
    (*ret)[i] = is_zero(&unpacked[i]);
}

/* -------------------------------------- */

struct Party
{
  shared_ptr<CCParams<CryptoContextBFVRNS>> bfv_parms;
  shared_ptr<CCParams<CryptoContextCKKSRNS>> ckks_parms;
  CryptoContext<DCRTPoly> bfv_ctx;
  CryptoContext<DCRTPoly> ckks_ctx;
  ProtocolParameters pro_parms;
  SK sk_i;

  Party() {}

  Party(ProtocolParameters &pp, shared_ptr<CCParams<CryptoContextBFVRNS>> &bfv_p, shared_ptr<CCParams<CryptoContextCKKSRNS>> &ckks_p)
  {
    pro_parms = pp;
    bfv_parms = bfv_p;
    ckks_parms = ckks_p;
    bfv_ctx = gen_crypto_ctx(bfv_parms);
    ckks_ctx = gen_crypto_ctx(ckks_p);

    // if (pro_parms.party_id == pro_parms.num_parties - 1)
    //   bfv_ctx->InsertEvalAutomorphismKey(pro_parms.ek);
  }

  /* -------------------------------------- */

  size_t decrypt_check_all(const SK &bfv_sk, const Tuple<vector<CT>> *B, CT &result)
  {
    BS::thread_pool pool(pro_parms.num_threads);
    vector<vector<bool>> ret(B->e0.size());
    size_t nbits = pro_parms.hash_sz * 8;
    size_t count = 0;
    for (size_t i = 0; i < B->e0.size(); i++)
      pool.push_task(decrypt_check_one, bfv_ctx, bfv_sk, &(B->e0[i]), nbits, pro_parms.pack_type, &ret[i], pro_parms.batch_size);
    pool.wait_for_tasks();
    vector<bool> one_hot_matches(ret.size() * ret[0].size());
    for (size_t i = 0; i < ret.size(); i++)
    {
      for (size_t j = 0; j < ret[i].size(); j++)
      {
        count += (size_t)ret[i][j];
        one_hot_matches[(i * ret[i].size()) + j] = ret[i][j];
      }
    }
    if (pro_parms.with_ad)
    {
      one_hot_matches.resize(pro_parms.batch_size * B->e1.size());
      CT res;
      PT res_pt;
      for (size_t i = 0; i < B->e1.size(); i++)
      {
        size_t start = i * pro_parms.batch_size;
        vector<double> vec(pro_parms.batch_size, 0);
        for (size_t j = 0; j < pro_parms.batch_size; j++)
          vec[j] = ((double)one_hot_matches[j + start]);
        PT pt = ckks_ctx->MakeCKKSPackedPlaintext(vec);
        if (i == 0)
          result = ckks_ctx->EvalMult(pt, B->e1[i]);
        else
          ckks_ctx->EvalAddInPlace(result, ckks_ctx->EvalMult(pt, B->e1[i]));
      }
      result = ckks_ctx->EvalSum(result, pro_parms.batch_size);
    }
    return count;
  }

  void encrypt_all(const CryptoContext<DCRTPoly> &ctx, PK &pk, vector<CT> &M, vector<PT> &pt)
  {
    // Stopwatch sw;
    // sw.start();
    M.resize(pt.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < M.size(); i++)
      pool.push_task(encrypt_single, ctx, pk, &pt[i], &M[i]);
    pool.wait_for_tasks();
    // printf("encrypted %lu plaintexts (took %5.2fs).", pt.size(), sw.elapsed());
  }

  void add_all_inplace(vector<CT> &A, const vector<CT> &B)
  {
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(add_single_ct_inplace, bfv_ctx, &A[i], &B[i]);
    pool.wait_for_tasks();
  }

  void multiply_all(const vector<CT> &A, const vector<PT> &B, vector<CT> &dest)
  {
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(multiply_single, bfv_ctx, &A[i], &B[i], &dest[i]);
    pool.wait_for_tasks();
  }

  void subtract_all(const vector<CT> &A, const vector<PT> &B, vector<CT> &dest)
  {
    assert(A.size() == B.size());
    thread_pool pool(pro_parms.num_threads);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(subtract_single, bfv_ctx, &A[i], &B[i], &dest[i]);
    pool.wait_for_tasks();
  }

  void randomize_all_inplace(Tuple<vector<CT>> *B)
  {
    Stopwatch sw;
    sw.start();

    thread_pool pool(pro_parms.num_threads);
    size_t plain_mod = bfv_ctx->GetCryptoParameters()->GetPlaintextModulus();
    size_t ring_dim = bfv_ctx->GetRingDimension();
    size_t num_cf_per_hash = ring_dim / pro_parms.batch_size;
    size_t b_size = B->e0.size();

    if (pro_parms.with_ad)
    {
      for (size_t i = 0; i < b_size; i++)
        pool.push_task(randomize_single_inplace, bfv_ctx, ckks_ctx, &(B->e0[i]), &(B->e1[i]), plain_mod, ring_dim, num_cf_per_hash);
    }
    else
    {
      for (size_t i = 0; i < b_size; i++)
        pool.push_task(randomize_single_inplace, bfv_ctx, ckks_ctx, &(B->e0[i]), nullptr, plain_mod, ring_dim, num_cf_per_hash);
    }

    vector<size_t> idx_vec(b_size);
    for (size_t i = 0; i < b_size; i++)
      idx_vec[i] = i;

    random_device rd;
    mt19937 gen(rd());
    shuffle(idx_vec.begin(), idx_vec.end(), gen);

    if (pro_parms.with_ad)
    {
      for (size_t i = 0; i < b_size; i++)
      {
        swap(B->e0[i], B->e0[idx_vec[i]]);
        swap(B->e1[i], B->e1[idx_vec[i]]);
      }
    }
    else
    {
      for (size_t i = 0; i < b_size; i++)
        swap(B->e0[i], B->e0[idx_vec[i]]);
    }

    pool.wait_for_tasks();
    printf("\nRandomization: %5.2fs\n", sw.elapsed());
  }

  /* -------------------------------------- */

  vector<CT> joint_decrypt(vector<CT> &agg_res)
  {
    if (pro_parms.party_id == 0)
      return ckks_ctx->MultipartyDecryptLead(agg_res, sk_i);
    else
      return ckks_ctx->MultipartyDecryptMain(agg_res, sk_i);
  }

  /*
    apk   Agg. Public Key
    ask   Agg. EvalSum Key
  */
  void dkg(PK &apk, shared_ptr<EvalKeys> &ask)
  {
    KeyPair<DCRTPoly> kp;
    if (pro_parms.party_id == 0)
    {
      kp = ckks_ctx->KeyGen();
      ckks_ctx->EvalSumKeyGen(kp.secretKey, kp.publicKey);
      *ask = ckks_ctx->GetEvalSumKeyMap(kp.secretKey->GetKeyTag());
      // aak = ckks_ctx->KeySwitchGen(kp.secretKey, kp.secretKey);
    }
    else
    {
      kp = ckks_ctx->MultipartyKeyGen(apk);
      shared_ptr<EvalKeys> ask_i = ckks_ctx->MultiEvalSumKeyGen(kp.secretKey, ask, kp.publicKey->GetKeyTag());
      ask = ckks_ctx->MultiAddEvalSumKeys(ask, ask_i, kp.publicKey->GetKeyTag());
      // aak = ckks_ctx->MultiKeySwitchGen(kp.secretKey, kp.secretKey, aak);
    }
    sk_i = kp.secretKey;
    apk = kp.publicKey;
  }

  void compute_on_r(const Tuple<vector<CT>> *M, Tuple<vector<CT>> *R, const vector<string> &X, bool iu, bool run_sum)
  {
    Stopwatch sw;
    string protocol = string(iu ? "MPSIU" : "MPSI") + string(run_sum ? "-Sum" : "");
    print_title(protocol + ": Party " + to_string(pro_parms.party_id));
    sw.start();

    HashMap hm(pro_parms);
    size_t m_sz = M->e0.size();
    vector<PT> hm_pt(m_sz), hm_1hot(m_sz), hm_0hot(m_sz);

    vector<PT> v_pt;
    hm.insert(X);
    hm.hot_encoding_mask(bfv_ctx, hm_1hot, false, pro_parms.batch_size);
    hm.hot_encoding_mask(bfv_ctx, hm_0hot, true, pro_parms.batch_size);
    hm.serialize(bfv_ctx, ckks_ctx, hm_pt, v_pt, (pro_parms.party_id == 1), pro_parms.batch_size);

    // Compute R => R + (M - Enc(hm))
    cout << "Computing R => R + (M - Enc(hm))" << endl;
    vector<CT> Mdiff_temp(m_sz);
    subtract_all(M->e0, hm_pt, Mdiff_temp);

    if (pro_parms.party_id == 1)
    {
      R->e0 = Mdiff_temp;
      R->e1 = M->e1;
    }
    else
    {
      vector<CT> Mdiff(m_sz);
      multiply_all(Mdiff_temp, hm_1hot, Mdiff);
      if (iu)
      {
        vector<CT> Rdiff(m_sz);
        multiply_all(R->e0, hm_0hot, Rdiff);
        add_all_inplace(Rdiff, Mdiff);
        R->e0 = Rdiff;
      }
      else
        add_all_inplace(R->e0, Mdiff);
    }

    // The last party randomizes the ciphertexts
    if (pro_parms.party_id == pro_parms.num_parties - 1)
      randomize_all_inplace(R);

    printf("\nTime: %5.2fs\n", sw.elapsed());
  }
};
