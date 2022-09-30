#pragma once

#include <seal/seal.h>

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
