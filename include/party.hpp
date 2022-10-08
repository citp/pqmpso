#pragma once

#include "crypto.hpp"

using namespace std;
using namespace lbcrypto;
using namespace BS;

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

inline void add_single_inplace(const CryptoContext<DCRTPoly> &bfv_ctx, CT *a, const CT *b)
{
  bfv_ctx->EvalAddInPlace(*a, *b);
}

// inline void encrypt_zero_single(shared_ptr<Encryptor> encryptor, Ciphertext *ct)
// {
//   encryptor->encrypt_zero(*ct);
// }

struct Party
{
  shared_ptr<CCParams<CryptoContextBFVRNS>> enc_parms;
  CryptoContext<DCRTPoly> bfv_ctx;
  // unique_ptr<SEALContext> bfv_ctx;
  // shared_ptr<Encryptor> encryptor;
  // shared_ptr<Evaluator> evaluator;
  ProtocolParameters pro_parms;

  Party() {}

  Party(shared_ptr<CCParams<CryptoContextBFVRNS>> &enc_parms_, ProtocolParameters &pro_parms_)
  {
    pro_parms = pro_parms_;
    enc_parms = enc_parms_;
    bfv_ctx = gen_crypto_ctx(enc_parms);
    // bfv_ctx = make_unique<SEALContext>(enc_parms);
    // evaluator = make_shared<Evaluator>(*bfv_ctx);
    // if (pro_parms.pk != NULL)
    // encryptor = make_shared<Encryptor>(*bfv_ctx, *pro_parms.pk);
  }

  /* -------------------------------------- */

  void encrypt_all(vector<CT> &M, vector<PT> &pt)
  {
    Stopwatch sw;
    sw.start();
    M.resize(pt.size());
    thread_pool pool(32);
    for (size_t i = 0; i < M.size(); i++)
      pool.push_task(encrypt_single, bfv_ctx, pro_parms.pk, &pt[i], &M[i]);
    pool.wait_for_tasks();
    printf("encrypted %lu plaintexts (took %fs).", pt.size(), sw.elapsed());
  }

  void add_all_inplace(vector<CT> &A, const vector<CT> &B)
  {
    Stopwatch sw;
    sw.start();
    assert(A.size() == B.size());
    thread_pool pool(32);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(add_single_inplace, bfv_ctx, &A[i], &B[i]);
    pool.wait_for_tasks();
    printf("added %lu ciphertexts (took %fs).", A.size(), sw.elapsed());
  }

  // void subtract_all_inplace(vector<Ciphertext> &R, vector<Plaintext> &pt)
  // {
  //   Stopwatch sw;
  //   sw.start();
  //   assert(pt.size() == R.size());
  //   for (size_t i = 0; i < R.size(); i++)
  //     evaluator->sub_plain_inplace(R[i], pt[i]);
  //   printf("Subtracted %lu plaintexts from ciphertexts (took %fs).\n", pt.size(), sw.elapsed());
  // }

  void subtract_all(const vector<CT> &A, const vector<PT> &B, vector<CT> &dest)
  {
    Stopwatch sw;
    sw.start();
    assert(A.size() == B.size());
    thread_pool pool(32);
    for (size_t i = 0; i < A.size(); i++)
      pool.push_task(subtract_single, bfv_ctx, &A[i], &B[i], &dest[i]);
    pool.wait_for_tasks();
    printf("subtracted %lu plaintexts from ciphertexts (took %fs).", B.size(), sw.elapsed());
  }

  // void randomize_all_inplace(vector<Ciphertext> &R)
  // {
  //   // TODO: Implement
  // }

  void encrypt_zero_all_inplace(vector<CT> &R)
  {
    Stopwatch sw;
    thread_pool pool(32);
    for (size_t i = 0; i < R.size(); i++)
    {
      cout << "i = " << i << endl;
      cout << pro_parms.pk->GetKeyTag() << endl;
      pool.push_task(encrypt_zero_single, bfv_ctx, pro_parms.pk, &R[i]);
    }

    pool.wait_for_tasks();
    printf("encrypted %lu zero plaintexts (took %fs).", R.size(), sw.elapsed());
  }

  /* -------------------------------------- */

  void mpsiu(const vector<CT> &M, vector<CT> &R, const vector<string> &X)
  {
    Stopwatch sw;

    print_line();
    cout << "MPSIU: Party " << pro_parms.party_id << endl;
    print_line();

    // if (pro_parms.party_id == 1)
    //   encrypt_zero_all_inplace(R);

    // cout << "Encrypted zeros" << endl;

    HashMap hm(pro_parms);
    vector<PT> pt(M.size());
    vector<CT> Mdiff(M.size());
    hm.insert(X);
    hm.serialize(bfv_ctx, pt, (pro_parms.party_id == 1));

    // Compute R => R + (M - Enc(hm))
    cout << "Computing R => R + (M - Enc(hm))" << endl;
    subtract_all(M, pt, Mdiff);

    if (pro_parms.party_id == 1)
      R = Mdiff;
    else
      add_all_inplace(R, Mdiff);
    // subtract_all_inplace(R, pt);
    // add_all_inplace(R, Rdiff);

    // if (pro_parms.party_id == pro_parms.num_parties - 1)
    // randomize_all_inplace(R);

    cout << "Elapsed: " << sw.elapsed() << "s" << endl;
  }
};