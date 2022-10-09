#pragma once

#include "party.hpp"

using namespace std;
using namespace lbcrypto;

struct Delegate
{
  SK sk;
  Party party;

  Delegate(shared_ptr<CCParams<CryptoContextBFVRNS>> &enc_parms, ProtocolParameters &pro_parms)
  {
    party = Party(enc_parms, pro_parms);
  }

  /* -------------------------------------- */

  /* -------------------------------------- */

  vector<CT> start(vector<string> &X)
  {
    Stopwatch sw;

    print_line();
    cout << "DelegateStart" << endl;
    print_line();

    sw.start();

    KeyPair<DCRTPoly> kp = party.bfv_ctx->KeyGen();
    sk = kp.secretKey;
    party.pro_parms.pk = kp.publicKey;

    HashMap hm(party.pro_parms);
    hm.insert(X);
    vector<PT> pt;
    hm.serialize(party.bfv_ctx, pt, true);

    vector<CT> M;
    party.encrypt_all(M, pt);

    printf("\nTime: %5.2fs\n", sw.elapsed());
    return M;
  }

  size_t finish(const vector<CT> *B)
  {
    Stopwatch sw;

    print_line();
    cout << "DelegateFinish" << endl;
    print_line();

    sw.start();

    size_t int_size = party.decrypt_check_all(sk, *B);
    printf("Time: %5.2fs\n", sw.elapsed());
    cout << int_size << endl;
    return int_size;
  }
};