#pragma once

#include <bitset>
#include "crypto.hpp"

using namespace std;
using namespace lbcrypto;
using namespace BS;

inline void remove_randomization(const CryptoContext<DCRTPoly> &bfv_ctx, PT &a, PT &b, size_t nbits, PackingType pack_type, vector<bool> *ret, size_t batch_size)
{
  assert (pack_type == MULTIPLE_COMPACT);
  vector<int64_t> unpacked_a = a->GetPackedValue();
  vector<int64_t> unpacked_b = b->GetPackedValue();
  size_t num_cf_per_hash = (unpacked_a.size() / batch_size);

  ret->resize(batch_size);
  for (size_t i = 0; i < batch_size; i++)
  {
    (*ret)[i] = true;
    for (size_t j = 0; j < num_cf_per_hash; j++)
    {
      if ((unpacked_a[num_cf_per_hash*i + j] - unpacked_b[num_cf_per_hash*i + j]) % 65537 != 0)
      {
        (*ret)[i] = false;
        break;
      }
    }
  }
}

struct Oversight {
  shared_ptr<CCParams<CryptoContextBFVRNS>> bfv_parms;
  shared_ptr<CCParams<CryptoContextCKKSRNS>> ckks_parms;
  CryptoContext<DCRTPoly> bfv_ctx;
  CryptoContext<DCRTPoly> ckks_ctx;
  ProtocolParameters pro_parms;

  ~Oversight() {}

  Oversight(ProtocolParameters &pp, shared_ptr<CCParams<CryptoContextBFVRNS>> &bfv_p, shared_ptr<CCParams<CryptoContextCKKSRNS>> &ckks_p)
  {
    pro_parms = pp;
    bfv_parms = bfv_p;
    ckks_parms = ckks_p;
    bfv_ctx = gen_crypto_ctx(bfv_parms);
    ckks_ctx = gen_crypto_ctx(ckks_p);
  }

  /* -------------------------------------- */

  size_t compute_result(const Tuple<vector<CT>> *R, vector<PT> &ic, vector<PT> &srv, vector<CT> &result)
  {
    Stopwatch sw;
    print_title("Oversight: Round 1");
    sw.start();

    assert(ic.size() == srv.size());
    BS::thread_pool pool(pro_parms.num_threads);
    size_t nbits = pro_parms.hash_sz * 8;
    vector<vector<bool>> ret(ic.size());

    for (size_t i = 0; i < ic.size(); i++)
      pool.push_task(remove_randomization, bfv_ctx, ic[i], srv[i], nbits, pro_parms.pack_type, &ret[i], pro_parms.batch_size);
    pool.wait_for_tasks();

    vector<bool> one_hot_matches;
    size_t count = get_one_hot(ret, one_hot_matches);

    if (pro_parms.with_ad)
    {
      ckks_ctx->InsertEvalSumKey(pro_parms.ask);
      one_hot_matches.resize(pro_parms.batch_size * R->e1.size());
      CT res;
      PT res_pt;
      for (size_t i = 0; i < R->e1.size(); i++)
      {
        size_t start = i * pro_parms.batch_size;
        vector<double> vec(pro_parms.batch_size, 0);
        for (size_t j = 0; j < pro_parms.batch_size; j++)
          vec[j] = ((double)one_hot_matches[j + start]);
        PT pt = ckks_ctx->MakeCKKSPackedPlaintext(vec);
        if (i == 0)
          result[0] = ckks_ctx->EvalMult(pt, R->e1[i]);
        else
          ckks_ctx->EvalAddInPlace(result[0], ckks_ctx->EvalMult(pt, R->e1[i]));
      }
      result[0] = ckks_ctx->EvalSum(result[0], pro_parms.batch_size);
    }

    printf("Time: %5.2fs\n", sw.elapsed());
    return count;
  }
};