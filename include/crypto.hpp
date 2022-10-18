#pragma once

#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include "utils.hpp"
#include "BS_thread_pool.hpp"

using namespace std;
using namespace lbcrypto;

/* -------------------------------------- */

typedef Plaintext PT;
typedef Ciphertext<DCRTPoly> CT;
typedef PublicKey<DCRTPoly> PK;
typedef PrivateKey<DCRTPoly> SK;
typedef map<usint, EvalKey<DCRTPoly>> EvalKeys;

enum PackingType
{
  SINGLE,
  MULTIPLE,
  MULTIPLE_COMPACT
};

struct ProtocolParameters
{
  size_t party_id, num_parties, map_sz, hash_sz, num_threads;
  bool with_ad;
  PackingType pack_type;
  PK pk, apk;
  shared_ptr<EvalKeys> ek, ask;
};

template <typename T>
struct Tuple
{
  T e0, e1;
};

struct AggKeys
{
  PK apk;
  EvalKeys ask;
};

/* -------------------------------------- */

void random_bytes(uint8_t *buf, size_t sz)
{
  RAND_bytes(buf, sz);
}

shared_ptr<CCParams<CryptoContextBFVRNS>> gen_bfv_params()
{
  shared_ptr<CCParams<CryptoContextBFVRNS>> parms = make_shared<CCParams<CryptoContextBFVRNS>>();
  // parms->SetToDefaults(BFVRNS_SCHEME);
  parms->SetPlaintextModulus(65537);
  // parms->SetPlaintextModulus(4294967297);
  parms->SetMultiplicativeDepth(1);
  parms->SetEvalAddCount(0);
  // parms->SetBatchSize(2048);
  // parms->SetDigitSize(2048);
  parms->SetRingDim(8192);
  // parms->SetFirstModSize(35);
  // parms->SetScalingModSize(0);
  parms->SetSecurityLevel(HEStd_192_classic);
  // parameters.SetMaxRelinSkDeg(3);
  // cout << "Secret Key Distribution: " << parms->GetSecretKeyDist() << endl;
  cout << "Ring Dimension: " << parms->GetRingDim() << endl;
  cout << "Plaintext Modulus: " << parms->GetPlaintextModulus() << endl;
  cout << "First Mod Size: " << parms->GetFirstModSize() << endl;
  cout << "Security Level: " << parms->GetSecurityLevel() << endl;
  print_sep();
  return parms;
}

shared_ptr<CCParams<CryptoContextCKKSRNS>> gen_ckks_params()
{
  shared_ptr<CCParams<CryptoContextCKKSRNS>> parms = make_shared<CCParams<CryptoContextCKKSRNS>>();
  parms->SetMultiplicativeDepth(16);
  parms->SetSecurityLevel(HEStd_192_classic);
  // parms->SetRingDim(65536);
  parms->SetBatchSize(32768);
  parms->SetScalingModSize(59);
  parms->SetMaxRelinSkDeg(16);
  cout << "Scaling Mod Size: " << parms->GetScalingModSize() << endl;
  cout << "Security Level: " << parms->GetSecurityLevel() << endl;
  cout << "Batch Size: " << parms->GetBatchSize() << endl;
  print_sep();
  return parms;
}

CryptoContext<DCRTPoly> gen_crypto_ctx(shared_ptr<CCParams<CryptoContextBFVRNS>> &enc_parms)
{
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(*enc_parms);
  ctx->Enable(PKE);
  ctx->Enable(LEVELEDSHE);
  ctx->Enable(MULTIPARTY);
  return ctx;
}

CryptoContext<DCRTPoly> gen_crypto_ctx(shared_ptr<CCParams<CryptoContextCKKSRNS>> &enc_parms)
{
  CryptoContext<DCRTPoly> ctx = GenCryptoContext(*enc_parms);
  ctx->Enable(PKE);
  ctx->Enable(LEVELEDSHE);
  ctx->Enable(ADVANCEDSHE);
  ctx->Enable(MULTIPARTY);
  ctx->Enable(KEYSWITCH);
  return ctx;
}

vector<uint8_t> sha384(const string x)
{
  uint32_t digest_length = SHA384_DIGEST_LENGTH;
  const EVP_MD *algorithm = EVP_sha3_384();
  vector<uint8_t> digest(digest_length);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  EVP_DigestInit_ex(context, algorithm, nullptr);
  EVP_DigestUpdate(context, x.c_str(), x.size());
  EVP_DigestFinal_ex(context, digest.data(), &digest_length);
  EVP_MD_CTX_destroy(context);
  return digest;
}

inline size_t n_hashes_in_pt(PackingType pack_type, size_t poly_mod_deg, size_t plain_mod_bits, size_t nbits_entry)
{
  switch (pack_type)
  {
  case SINGLE:
    return 1;
  case MULTIPLE:
    return (poly_mod_deg / nbits_entry);
  case MULTIPLE_COMPACT:
    return ((plain_mod_bits * poly_mod_deg) / nbits_entry);
  default:
    throw runtime_error("Packing not supported.");
  }
}

/* -------------------------------------- */

inline void pack_bitwise_int_arr(vector<int64_t> *int_vec, vector<uint8_t> *to_pack, size_t start_idx)
{
  for (size_t i = 0; i < to_pack->size(); i++)
  {
    for (uint8_t k = 0; k < 8; k++)
    {
      (*int_vec)[start_idx + (i * 8 + k)] = (is_bit_set(to_pack->at(i), k) ? 1 : 0);
    }
  }
}

inline void unpack_bitwise_int_arr(vector<int64_t> *int_vec, vector<uint8_t> *unpacked)
{
  size_t bitsize = int_vec->size();
  size_t bytesize = (bitsize / 8) + ((bitsize % 8 != 0) ? 1 : 0);
  *unpacked = vector<uint8_t>(bytesize, 0);
  for (size_t i = 0; i < bitsize; i++)
  {
    if (int_vec->at(i) == 1)
      (*unpacked)[i / 8] |= (1 << (i % 8));
  }
}

inline void pack_bitwise_single(CryptoContext<DCRTPoly> &bfv_ctx, PT *pt, vector<uint8_t> *to_pack)
{
  vector<int64_t> int_vec(to_pack->size() * 8);
  pack_bitwise_int_arr(&int_vec, to_pack, 0);
  *pt = bfv_ctx->MakePackedPlaintext(int_vec);
}

void unpack_bitwise_single(PT &pt, vector<uint8_t> *unpacked, size_t nbits)
{
  vector<int64_t> int_vec = pt->GetPackedValue();
  int_vec.resize(nbits);
  unpack_bitwise_int_arr(&int_vec, unpacked);
}

void pack_bitwise_multiple(CryptoContext<DCRTPoly> &bfv_ctx, PT *pt, vector<vector<uint8_t>> *to_pack, size_t start_idx, size_t count, size_t nbits, bool fill_random)
{
  size_t ring_dim = bfv_ctx->GetRingDimension();
  vector<int64_t> int_vec(ring_dim);
  for (size_t i = 0; i < count; i++)
  {
    pack_bitwise_int_arr(&int_vec, &to_pack->at(start_idx + i), i * nbits);
  }
  if (fill_random)
  {
    for (size_t i = nbits * count; i < ring_dim; i++)
      int_vec[i] = random_int(2);
  }
  *pt = bfv_ctx->MakePackedPlaintext(int_vec);
}

void unpack_bitwise_multiple(PT &pt, vector<vector<uint8_t>> *unpacked, size_t count, size_t nbits)
{
  vector<int64_t> int_vec = pt->GetPackedValue();
  vector<uint8_t> full;
  unpack_bitwise_int_arr(&int_vec, &full);
  unpacked->resize(count);
  size_t nbytes = bits_to_bytes(nbits);
  for (size_t i = 0; i < count; i++)
  {
    (*unpacked)[i] = vector<uint8_t>(full.begin() + (i * nbytes), full.begin() + ((i + 1) * nbytes));
  }
}

// Hardcoded 2 bytes i.e. mod 65537
inline void pack_compact_int_arr(vector<int64_t> *int_vec, vector<uint8_t> *to_pack, size_t start_idx)
{
  for (size_t i = 0; i < to_pack->size() / 2; i++)
    memcpy(&(int_vec->data()[start_idx + i]), &(to_pack->data()[2 * i]), 2);
}

// inline void pack_compact_int

// Hardcoded 2 bytes i.e. mod 65537
// inline void mask_compact_int_arr(vector<int64_t> *int_vec, vector<uint8_t> *to_pack, size_t start_idx)
// {
//   for (size_t i = 0; i < to_pack->size() / 2; i++)
//     memcpy(&(int_vec->data()[start_idx + i]), &(to_pack->data()[2 * i]), 2);
// }

// start_idx in to_pack
void pack_multiple_compact(CryptoContext<DCRTPoly> &bfv_ctx, PT *pt, vector<vector<uint8_t>> *to_pack, size_t start_idx, size_t count, size_t num_cf_per_hash, bool fill_random)
{
  size_t ring_dim = bfv_ctx->GetRingDimension();
  vector<int64_t> int_vec(ring_dim);
  for (size_t i = 0; i < count; i++)
    pack_compact_int_arr(&int_vec, &to_pack->at(start_idx + i), num_cf_per_hash * i);
  for (size_t i = count * num_cf_per_hash; i < ring_dim; i++)
    int_vec[i] = random_int(65537);
  *pt = bfv_ctx->MakePackedPlaintext(int_vec);
}

// void mask_multiple_compact(CryptoContext<DCRTPoly> &bfv_ctx, PT *pt, vector<vector<uint8_t>> *to_pack, size_t start_idx, size_t count, bool fill_random)
// {
//   size_t ring_dim = bfv_ctx->GetRingDimension();
//   vector<int64_t> int_vec(ring_dim);
//   size_t num_cf_per_hash = ring_dim / count;
//   for (size_t i = 0; i < count; i++)
//     pack_compact_int_arr(&int_vec, &to_pack->at(start_idx + i), num_cf_per_hash * i);
//   *pt = bfv_ctx->MakePackedPlaintext(int_vec);
// }

void unpack_multiple_compact(PT &pt, vector<vector<uint8_t>> *unpacked, size_t num_bytes_per_hash)
{
  vector<int64_t> int_vec = pt->GetPackedValue();
  size_t num_cf_per_hash = (num_bytes_per_hash / 2);
  size_t hash_count = (int_vec.size() / num_cf_per_hash);
  unpacked->resize(hash_count);
  for (size_t i = 0; i < hash_count; i++)
  {
    (*unpacked)[i].resize(num_bytes_per_hash);
    // for (size_t j = 0; j < num_cf_per_hash; j++)
    //   memcpy(&((*unpacked)[i].data()[j * 2]), &(int_vec.data()[num_cf_per_hash * i + j]), 2);
    memcpy((*unpacked)[i].data(), &(int_vec.data()[num_cf_per_hash * i]), num_bytes_per_hash);
  }
}

void pack_base_int_arr(vector<int64_t> &int_vec, const size_t a, const size_t b)
{
  size_t rem = a;
  while (rem > 0)
  {
    int_vec.push_back(rem % b);
    rem /= b;
  }
}