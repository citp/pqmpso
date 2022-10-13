#include <iostream>
#include <algorithm>

#include "ut.hpp"
#include "crypto.hpp"

#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace boost::ut;
using namespace lbcrypto;
using namespace std;

// base is b
// void pack_base_int_arr(vector<int64_t> &int_vec, const size_t a, const size_t b)
// {
//   size_t rem = a;
//   while (rem > 0)
//   {
//     int_vec.push_back(rem % b);
//     rem /= b;
//   }
// }

size_t unpack_base_int_arr(const vector<int64_t> &int_vec, const size_t b)
{
  size_t s = 0, pw = 1;
  for (size_t i = 0; i < int_vec.size(); i++)
  {
    int64_t val = (int_vec[i] >= 0) ? int_vec[i] : int_vec[i] + b;
    s += (val * pw);
    pw *= b;
  }
  return s;
}

void print_vec(vector<int64_t> &int_vec)
{
  size_t sz = int_vec.size();
  cout << "size: " << sz << endl;
  for (size_t i = 0; i < sz; i++)
  {
    cout << int_vec[i] << " ";
  }
  cout << endl;
}

int main()
{
  CCParams<CryptoContextBFVRNS> enc_params;
  enc_params.SetPlaintextModulus(65537);
  // enc_params.SetMultiplicativeDepth(1);
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(enc_params);
  ctx->Enable(PKE);
  ctx->Enable(KEYSWITCH);
  ctx->Enable(LEVELEDSHE);

  // "MPSIU"_test = [ctx]
  // {
  //   KeyPair<DCRTPoly> keyPair = ctx->KeyGen();
  //   cout << "The key pair has been generated." << endl;

  //   std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 0};
  //   Plaintext plaintext1 = ctx->MakePackedPlaintext(vectorOfInts1);

  //   std::cout << "\nOriginal Plaintext #1: \n";
  //   std::cout << plaintext1 << std::endl;
  // };

  "Sum"_test = [ctx]
  {
    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    cout << "The key pair has been generated." << endl;

    size_t ntests = 100, base = 65537, count = 0;
    random_device rd;
    mt19937 generator(rd());
    vector<CT> ct(ntests);
    CT ct_sum;

    for (size_t i = 0; i < ntests; i++)
    {
      size_t num = generator() % UINT64_MAX;
      vector<int64_t> vec1;
      pack_base_int_arr(vec1, num, base);
      expect(num == unpack_base_int_arr(vec1, base));
      ct[i] = ctx->Encrypt(kp.publicKey, ctx->MakePackedPlaintext(vec1));
      Plaintext pt;
      ctx->Decrypt(kp.secretKey, ct[i], &pt);
      expect(num == unpack_base_int_arr(pt->GetPackedValue(), base));
      if (i == 0)
        ct_sum = ct[i];
      else
        ctx->EvalAddInPlace(ct_sum, ct[i]);
      count += num;
    }
    cout << "actual count: " << count << endl;
    PT pt_sum;
    ctx->Decrypt(kp.secretKey, ct_sum, &pt_sum);
    cout << "decrypted count: " << unpack_base_int_arr(pt_sum->GetPackedValue(), base) << endl;
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