#pragma once

#include "crypto.hpp"

using namespace std;
using namespace seal;

struct ProtocolParameters
{
  size_t map_sz;
};

struct Delegate
{
  unique_ptr<SEALContext> bfv_ctx;
  SecretKey sk;
  PublicKey pk;
  shared_ptr<Encryptor> encryptor;
  ProtocolParameters parms;

  Delegate(EncryptionParameters &enc_parms, ProtocolParameters &pro_parms)
  {
    bfv_ctx = make_unique<SEALContext>(enc_parms);
    parms = pro_parms;
  }

  HashMap<Ciphertext> start(vector<string> &X)
  {
    cout << "Delegate-Start" << endl;

    KeyGenerator keygen(*bfv_ctx);
    sk = keygen.secret_key();
    keygen.create_public_key(pk);
    encryptor = make_shared<Encryptor>(*bfv_ctx, pk);

    HashMap<Ciphertext> hm(parms.map_sz);
    vector<Ciphertext> ct = encrypt_all(X, encryptor);
    hm.insert_all(X, ct);

    // for (size_t i = 0; i < X.size(); i++)
    // {
    //   hm.insert(X[i], )
    // }
    return hm;
  }
};