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

void print_vec(const vector<int64_t> &int_vec, size_t sz)
{
  if (sz == 0)
    sz = int_vec.size();
  cout << "size: " << sz << endl;
  for (size_t i = 0; i < sz; i++)
  {
    cout << int_vec[i] << " ";
  }
  cout << endl;
}

// void print_vec(const vector<complex<double>> &vec, size_t sz)
// {
//   if (sz == 0)
//     sz = vec.size();
//   cout << "size: " << sz << endl;
//   for (size_t i = 0; i < sz; i++)
//   {
//     cout << vec[i] << " ";
//   }
//   cout << endl;
// }

struct AddResult
{
  CT sum, carry;
};

AddResult half_adder(const CryptoContext<DCRTPoly> &ctx, const CT &a, const CT &b)
{
  return AddResult{
      ctx->EvalMult(ctx->EvalAdd(a, b), ctx->EvalAdd(ctx->EvalNegate(a), ctx->EvalNegate(b))),
      ctx->EvalMult(a, b),
  };
  // return AddResult{ctx->EvalAdd(ctx->EvalMult(ctx->EvalNegate(a), b), ctx->EvalMult(a, ctx->EvalNegate(b))), ctx->EvalMult(a, b)};
}

AddResult full_adder(const CryptoContext<DCRTPoly> &ctx, const CT &a, const CT &b, const CT &c_in)
{
  AddResult r1 = half_adder(ctx, a, b);
  AddResult r2 = half_adder(ctx, r1.sum, c_in);
  return AddResult{r2.sum, ctx->EvalAdd(r1.carry, r2.carry)};
}

void base_encode_int_arr_vertical(vector<vector<int64_t>> &bit_vec, vector<uint32_t> &ints)
{
  size_t sz = ints.size();
  bit_vec.resize(32);
  for (size_t i = 0; i < 32; i++)
  {
    bit_vec[i].resize(sz);
  }
  for (size_t i = 0; i < sz; i++)
  {
    size_t idx = 0;
    size_t rem = ints[i];
    while (rem > 0)
    {
      bit_vec[idx][i] = (rem % 2);
      rem /= 2;
      idx++;
    }
  }
}

void pack_bitwise_vertical(CryptoContext<DCRTPoly> &bfv_ctx, vector<PT> &pts, vector<uint32_t> &ints)
{
  pts.resize(32);
  vector<vector<int64_t>> bit_vec;
  base_encode_int_arr_vertical(bit_vec, ints);
  for (size_t i = 0; i < 32; i++)
    pts[i] = bfv_ctx->MakePackedPlaintext(bit_vec[i]);
}

int main()
{
  CCParams<CryptoContextCKKSRNS> enc_params;
  enc_params.SetMultiplicativeDepth(1);

  // enc_params.SetKeySwitchCount(0);
  // enc_params.SetDigitSize()
  enc_params.SetSecurityLevel(HEStd_192_classic);
  // enc_params.SetPlaintextModulus(2147483647);
  // enc_params.SetScalingModSize();
  // enc_params.SetRingDim(8192);
  // enc_params.SetScalingModSize(0);
  cout << "Security = " << enc_params.GetSecurityLevel() << endl;
  // cout << "PlainMod = " << enc_params.GetPlaintextModulus() << endl;
  // cout << "FirstModSize = " << enc_params.GetFirstModSize() << endl;
  cout << "ScalingModSize = " << enc_params.GetScalingModSize() << endl;
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(enc_params);
  ctx->Enable(PKE);
  // ctx->Enable(KEYSWITCH);
  ctx->Enable(LEVELEDSHE);
  ctx->Enable(ADVANCEDSHE);
  cout << "RingDim = " << ctx->GetRingDimension() << endl;

  cout << "Generated context" << endl;

  "Addition"_test = [ctx]
  {
    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    ctx->EvalSumKeyGen(kp.secretKey, kp.publicKey);
    // ctx->EvalMultKeyGen(kp.secretKey);
    cout << "Generated keys." << endl;
    vector<double> a = {1 << 20, 1 << 21}, b = {1 << 18, 1 << 19};
    PT pt_a = ctx->MakeCKKSPackedPlaintext(a), pt_b = ctx->MakeCKKSPackedPlaintext(b);
    CT ct_a = ctx->Encrypt(kp.publicKey, pt_a), ct_b = ctx->Encrypt(kp.publicKey, pt_b);
    CT ct_sum = ctx->EvalAdd(ct_a, ct_b);
    PT pt_sum;
    ctx->Decrypt(kp.secretKey, ct_sum, &pt_sum);
    print_vec(pt_sum->GetCKKSPackedValue(), 2);
    ct_sum = ctx->EvalSum(ct_sum, 4096);
    PT pt_res;
    ctx->Decrypt(kp.secretKey, ct_sum, &pt_res);
    print_vec(pt_res->GetCKKSPackedValue(), 1);
  };
}

int old_main()
{
  CCParams<CryptoContextBFVRNS> enc_params;
  enc_params.SetPlaintextModulus(65537);
  enc_params.SetMultiplicativeDepth(2);
  // enc_params.Set
  // enc_params.SetBatchSize(0);
  cout << "BatchSize = " << enc_params.GetBatchSize() << endl;
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(enc_params);
  ctx->Enable(PKE);
  ctx->Enable(KEYSWITCH);
  ctx->Enable(LEVELEDSHE);

  "Vertical"_test = [ctx]
  {
    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    ctx->EvalMultKeyGen(kp.secretKey);

    cout << "Test: Bitwise Packing (Vertical)" << endl;

    vector<PT> pts;
    vector<uint32_t> ints = {4343403, 9432035};
    // pack_bitwise_vertical(ctx, pts, ints);
  };

  "Encode"_test = [ctx]
  {
    return;
    cout << "Starting test." << endl;
    size_t x1 = 4343403, x2 = 9432035; // 13,775,438 -> 13,709,901
    vector<int64_t> v1, v2;

    pack_base_int_arr(v1, x1, 65537);
    pack_base_int_arr(v2, x2, 65537);
    print_vec(v1, 2);
    print_vec(v2, 2);
    PT pt1 = ctx->MakePackedPlaintext(v1), pt2 = ctx->MakePackedPlaintext(v2);

    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    ctx->EvalMultKeyGen(kp.secretKey);
    CT ct1 = ctx->Encrypt(kp.publicKey, pt1), ct2 = ctx->Encrypt(kp.publicKey, pt2);
    CT ct_sum = ctx->EvalAdd(ct1, ct2);
    PT pt_sum;
    ctx->Decrypt(kp.secretKey, ct_sum, &pt_sum);
    vector<int64_t> v3 = pt_sum->GetPackedValue();
    // print_vec(v3);
    vector<int64_t> v4 = {0, 0};
    PT pt_zero = ctx->MakePackedPlaintext(v4);
    CT ct_zero = ctx->Encrypt(kp.publicKey, pt_zero);

    AddResult res = full_adder(ctx, ct1, ct2, ct_zero);
    PT pt3, pt4;
    ctx->Decrypt(kp.secretKey, res.sum, &pt3);
    ctx->Decrypt(kp.secretKey, res.carry, &pt4);
    print_vec(pt3->GetPackedValue(), 2);
    print_vec(pt4->GetPackedValue(), 2);
  };

  "Add"_test = [ctx]
  {
    return;
    cout << "Starting test." << endl;
    vector<int64_t> v1(4), v2(4);
    vector<uint8_t> t1(sizeof(int64_t)), t2(sizeof(int64_t));
    int64_t x1 = 42, x2 = 43;

    memcpy(t1.data(), &x1, sizeof(int64_t));
    memcpy(t2.data(), &x2, sizeof(int64_t));
    pack_compact_int_arr(&v1, &t1, 0);
    pack_compact_int_arr(&v2, &t2, 0);

    PT pt1 = ctx->MakePackedPlaintext(v1), pt2 = ctx->MakePackedPlaintext(v2);
    CT ct1, ct2;

    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    ctx->EvalMultKeyGen(kp.secretKey);
    ct1 = ctx->Encrypt(kp.publicKey, pt1);
    ct2 = ctx->Encrypt(kp.publicKey, pt2);

    PT pt3, pt4;
    ctx->Decrypt(kp.secretKey, ct1, &pt3);
    ctx->Decrypt(kp.secretKey, ct2, &pt4);

    vector<vector<uint8_t>> unp1, unp2;
    unpack_multiple_compact(pt3, &unp1, sizeof(int64_t));
    unpack_multiple_compact(pt4, &unp2, sizeof(int64_t));

    int64_t x3 = *(int64_t *)unp1[0].data(), x4 = *(int64_t *)unp2[0].data();

    expect(x3 == x1);
    expect(x4 == x2);

    vector<int64_t> v3;
    PT pt_zero = ctx->MakePackedPlaintext(v3);
    CT ct_zero = ctx->Encrypt(kp.publicKey, pt_zero);
    AddResult res = full_adder(ctx, ct1, ct2, ct_zero);

    PT pt_sum, pt_carry;
    ctx->Decrypt(kp.secretKey, res.sum, &pt_sum);
    ctx->Decrypt(kp.secretKey, res.carry, &pt_carry);
    vector<vector<uint8_t>> unp3, unp4;
    unpack_multiple_compact(pt_sum, &unp3, sizeof(int64_t));
    unpack_multiple_compact(pt_carry, &unp4, sizeof(int64_t));
    int64_t x_sum = *(int64_t *)unp3[0].data(), x_carry = *(int64_t *)unp4[0].data();

    cout << "sum = " << x_sum << endl
         << "carry = " << x_carry << endl;

    // ctx->Eval
  };

  "Sum"_test = [ctx]
  {
    return;
    KeyPair<DCRTPoly> kp = ctx->KeyGen();
    cout << "The key pair has been generated." << endl;

    size_t ntests = 1, base = 65537, count = 0;
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
//   EncryptionParameters enc_parms = gen_bfv_params();
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