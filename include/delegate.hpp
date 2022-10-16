#pragma once

#include "party.hpp"

using namespace std;
using namespace lbcrypto;

struct Delegate
{
  SK bfv_sk, ckks_sk;
  PK ckks_pk;
  Party party;

  Delegate(ProtocolParameters &pro_parms, shared_ptr<CCParams<CryptoContextBFVRNS>> &bfv_parms, shared_ptr<CCParams<CryptoContextCKKSRNS>> &ckks_parms)
  {
    party = Party(pro_parms, bfv_parms, ckks_parms);

    KeyPair<DCRTPoly> kp = party.bfv_ctx->KeyGen();
    bfv_sk = kp.secretKey;
    party.pro_parms.pk = kp.publicKey;

    kp = party.ckks_ctx->KeyGen();
    ckks_sk = kp.secretKey;
    ckks_pk = kp.publicKey;
    party.ckks_ctx->EvalSumKeyGen(ckks_sk, ckks_pk);
    party.ckks_ctx->EvalMultKeyGen(ckks_sk);

    size_t ring_dim = party.bfv_ctx->GetRingDimension();
    size_t plain_mod_bits = get_bitsize(party.bfv_ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
    size_t num_hashes_per_pt = n_hashes_in_pt(pro_parms.pack_type, ring_dim, plain_mod_bits, pro_parms.hash_sz * 8);
    size_t num_cf_per_hash = ring_dim / num_hashes_per_pt;

    vector<usint> idx_list;
    for (size_t i = num_cf_per_hash; i < ring_dim; i += num_cf_per_hash)
      idx_list.push_back((usint)i);

    party.pro_parms.ek = party.bfv_ctx->EvalAutomorphismKeyGen(bfv_sk, party.bfv_ctx->FindAutomorphismIndices(idx_list));

    cout << "Generated rotation keys" << endl;
  }

  /* -------------------------------------- */

  PT joint_decrypt(vector<CT> &partials)
  {
    PT res;
    // vector<CT> inp(party.pro_parms.num_parties);
    // for (size_t i = 0; i < inp.size(); i++)
    //   inp[i] = partials[i][0];

    party.ckks_ctx->MultipartyDecryptFusion(partials, &res);
    return res;
  }

  Tuple<vector<CT>> start(vector<string> &X, vector<int64_t> &ad)
  {
    Stopwatch sw;

    print_line();
    cout << "DelegateStart" << endl;
    print_line();

    sw.start();

    HashMap hm(party.pro_parms);
    if (party.pro_parms.with_ad)
      hm.insert(X, ad);
    else
      hm.insert(X);
    vector<PT> X_pt, V_pt;
    hm.serialize(party.bfv_ctx, party.ckks_ctx, X_pt, V_pt, true);

    Tuple<vector<CT>> ret;
    party.encrypt_all(party.bfv_ctx, party.pro_parms.pk, ret.e0, X_pt);
    if (party.pro_parms.with_ad)
      party.encrypt_all(party.ckks_ctx, ckks_pk, ret.e1, V_pt);
    // party.pro_parms.apk

    printf("\nTime: %5.2fs\n", sw.elapsed());
    return ret;
  }

  vector<CT> finish(const Tuple<vector<CT>> *B)
  {
    Stopwatch sw;

    print_line();
    cout << "DelegateFinish" << endl;
    print_line();

    sw.start();
    party.ckks_ctx->InsertEvalSumKey(party.pro_parms.ask);
    vector<CT> agg_res(1);
    size_t int_size = party.decrypt_check_all(bfv_sk, ckks_sk, B, agg_res[0]);
    cout << "Computed intersection: " << int_size << endl;

    // lead_partial = party.ckks_ctx->MultipartyDecryptLead(agg_res, ckks_sk);

    printf("Time: %5.2fs\n", sw.elapsed());

    return agg_res;
  }
};