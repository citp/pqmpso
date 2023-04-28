#pragma once

#include "party.hpp"

using namespace std;
using namespace lbcrypto;

struct IC
{
  SK bfv_sk;
  ServiceProvider party;

  IC(ProtocolParameters &pro_parms, shared_ptr<CCParams<CryptoContextBFVRNS>> &bfv_parms, shared_ptr<CCParams<CryptoContextCKKSRNS>> &ckks_parms)
  {
    party = ServiceProvider(pro_parms, bfv_parms, ckks_parms);

    KeyPair<DCRTPoly> kp = party.bfv_ctx->KeyGen();
    bfv_sk = kp.secretKey;
    party.pro_parms.pk = kp.publicKey;

    // gen_rot_keys();
  }

  /* -------------------------------------- */

  void gen_rot_keys()
  {
    Stopwatch sw;
    sw.start();

    size_t ring_dim = party.bfv_ctx->GetRingDimension();
    size_t num_cf_per_hash = ring_dim / party.pro_parms.batch_size;

    vector<usint> idx_list;
    for (size_t i = num_cf_per_hash; i < ring_dim; i += num_cf_per_hash)
      idx_list.push_back((usint)i);

    party.pro_parms.ek = party.bfv_ctx->EvalAutomorphismKeyGen(bfv_sk, party.bfv_ctx->FindAutomorphismIndices(idx_list));

    cout << "Generated rotation keys" << endl;
    printf("\nTime: %5.2fs\n", sw.elapsed());
  }

  PT joint_decrypt_final(vector<CT> &partials)
  {
    PT res;
    party.ckks_ctx->MultipartyDecryptFusion(partials, &res);
    return res;
  }

  Tuple<vector<CT>> round1(vector<string> &X, vector<int64_t> &ad)
  {
    Stopwatch sw;
    print_title("IC: Round 1");
    sw.start();

    HashMap hm(party.pro_parms);
    if (party.pro_parms.with_ad)
      hm.insert(X, ad);
    else
      hm.insert(X);
    vector<PT> X_pt, V_pt;
    hm.serialize(party.bfv_ctx, party.ckks_ctx, X_pt, V_pt, true, party.pro_parms.batch_size, party.pro_parms.num_threads);

    Tuple<vector<CT>> ret;
    party.encrypt_all(party.bfv_ctx, party.pro_parms.pk, ret.e0, X_pt);
    if (party.pro_parms.with_ad)
      party.encrypt_all(party.ckks_ctx, party.pro_parms.apk, ret.e1, V_pt);

    // cout << "Ciphertext size: " << ret.e0[0]->GetMetadataByKey()
    printf("\nTime: %5.2fs\n", sw.elapsed());
    return ret;
  }

  size_t round2(const Tuple<vector<CT>> *B, vector<CT> &agg_res)
  {
    Stopwatch sw;
    print_title("IC: Round 2");
    sw.start();

    if (party.pro_parms.with_ad)
      party.ckks_ctx->InsertEvalSumKey(party.pro_parms.ask);

    size_t int_size = party.decrypt_check_all(bfv_sk, B, agg_res[0]);
    printf("Time: %5.2fs\n", sw.elapsed());

    return int_size;
  }

  void round2_fix(Tuple<vector<CT>> *B, vector<PT> *pt)
  {
    Stopwatch sw;
    print_title("IC: Round 2 (fixed)");
    sw.start();

    party.decrypt_all(bfv_sk, B, pt);
    printf("Time: %5.2fs\n", sw.elapsed());
  }
};