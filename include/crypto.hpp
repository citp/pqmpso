#pragma once

#include <vector>
#include <seal/seal.h>

#include "BS_thread_pool.hpp"

using namespace std;
using namespace seal;

EncryptionParameters gen_enc_params()
{
  size_t poly_modulus_degree = 2048, plain_modulus = 1024;
  EncryptionParameters parms(scheme_type::bfv);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus);
  return parms;
}

/* Parallel Encrypt / Decrypt */

vector<Ciphertext> encrypt_all(vector<string> &msg, shared_ptr<Encryptor> encryptor)
{
  BS::thread_pool pool;
  cout << "#Threads: " << pool.get_thread_count() << endl;
  BS::multi_future<Ciphertext> mf_ct;

  for (size_t i = 0; i < msg.size(); i++)
  {
    mf_ct.push_back(pool.submit(
        [msg, i, encryptor]
        {
      Plaintext pt(msg[i]);
      Ciphertext ct;
      encryptor->encrypt(pt, ct);
      return ct; }));
  }

  return mf_ct.get();
}

// typedef struct Params
// {
//   uint64_t t, q;
// };

// typedef FVSecretKey ;

// typedef enum FVParamSuite
// {

// };

// void FVInit(FVParams &params, )
// {
//   params.t =
// }
