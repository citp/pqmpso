#include <iostream>
#include <algorithm>

#include "ut.hpp"
// #include "crypto.hpp"

#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace boost::ut;
using namespace lbcrypto;
using namespace std;

int main()
{
  CCParams<CryptoContextBFVRNS> enc_params;
  enc_params.SetPlaintextModulus(2);
  enc_params.SetMultiplicativeDepth(1);
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(enc_params);
  ctx->Enable(PKE);
  ctx->Enable(KEYSWITCH);
  ctx->Enable(LEVELEDSHE);

  "MPSIU"_test = [ctx]
  {
    KeyPair<DCRTPoly> keyPair = ctx->KeyGen();
    cout << "The key pair has been generated." << endl;

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 0};
    Plaintext plaintext1 = ctx->MakePackedPlaintext(vectorOfInts1);

    std::cout << "\nOriginal Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;
  };
  return 0;
}

// int main()
// {
//   EncryptionParameters enc_parms = gen_enc_params();
//   shared_ptr<SEALContext> bfv_ctx = make_shared<SEALContext>(enc_parms);
//   KeyGenerator keygen(*bfv_ctx);
//   SecretKey sk = keygen.secret_key();
//   PublicKey pk;
//   keygen.create_public_key(pk);
//   shared_ptr<Encryptor> encryptor = make_shared<Encryptor>(*bfv_ctx, pk);
//   shared_ptr<Evaluator> evaluator = make_shared<Evaluator>(*bfv_ctx);
//   shared_ptr<Decryptor> decryptor = make_shared<Decryptor>(*bfv_ctx, sk);

//   "pack_bitwise_single"_test = [bfv_ctx, encryptor, evaluator, decryptor]
//   {
//     size_t bitsize = 256;
//     Plaintext pt1(bitsize), pt2(bitsize), pt3(bitsize);
//     Ciphertext ct1(*bfv_ctx), ct2(*bfv_ctx);
//     vector<uint8_t> m1(bitsize / 8), m2(bitsize / 8);

//     for (size_t i = 0; i < 100; i++)
//     {
//       random_bytes(m1.data(), bitsize / 8);
//       pack_bitwise_single(&pt1, &m1, 0);
//       pack_bitwise_single(&pt2, &m1, 0);
//       encryptor->encrypt(pt1, ct1);
//       evaluator->sub_plain_inplace(ct1, pt2);
//       decryptor->decrypt(ct1, pt3);
//       unpack_bitwise_single(&pt3, &m2, 0);
//       expect(m2.size() > 0);
//       for (size_t j = 0; j < m2.size(); j++)
//       {
//         expect(m2[j] == 0);
//       }
//     }
//   };

//   return 0;
// }