#pragma once

#include "party.hpp"

using namespace std;
using namespace lbcrypto;

inline size_t decrypt_check_one(const CryptoContext<DCRTPoly> &bfv_ctx, const SK &sk, const CT *ct, size_t nbits, PackingType pack_type)
{
  PT pt;
  bfv_ctx->Decrypt(sk, *ct, &pt);

  if (pack_type == SINGLE)
  {
    vector<uint8_t> unpacked;
    unpack_bitwise_single(pt, &unpacked, nbits);
    return (size_t)is_zero(&unpacked);
  }

  vector<vector<uint8_t>> unpacked;
  size_t plain_mod_bits = get_bitsize(bfv_ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
  size_t num_hashes_per_pt = n_hashes_in_pt(pack_type, bfv_ctx->GetRingDimension(), plain_mod_bits, nbits);
  // cout << "num_hashes_per_pt = " << num_hashes_per_pt << endl;

  if (pack_type == MULTIPLE)
    unpack_bitwise_multiple(pt, &unpacked, num_hashes_per_pt, nbits);
  else if (pack_type == MULTIPLE_COMPACT)
    unpack_multiple_compact(pt, &unpacked, bits_to_bytes(nbits));

  size_t n_zeros = 0;
  for (size_t i = 0; i < num_hashes_per_pt; i++)
    n_zeros += (size_t)is_zero(&unpacked[i]);
  return n_zeros;
}

struct Delegate
{
  SK sk;
  Party party;

  Delegate(shared_ptr<CCParams<CryptoContextBFVRNS>> &enc_parms, ProtocolParameters &pro_parms)
  {
    party = Party(enc_parms, pro_parms);
  }

  /* -------------------------------------- */

  size_t decrypt_check_all(const vector<CT> &B)
  {
    cout << "Decrypting " << B.size() << " ciphertexts." << endl;
    // BS::thread_pool pool(32);
    // BS::multi_future<size_t> res_fut(B.size());
    //   size_t poly_modulus_degree = party.enc_parms.poly_modulus_degree();
    size_t nbits = party.pro_parms.hash_sz * 8;
    //   // size_t nhashes = (poly_modulus_degree / nbits) - 1;
    size_t count = 0;
    for (size_t i = 0; i < B.size(); i++)
      count += decrypt_check_one(party.bfv_ctx, sk, &B[i], nbits, party.pro_parms.pack_type);

    //   // res_fut[i] = pool.submit(decrypt_check_one, decryptor, &B[i], poly_modulus_degree, nbits);
    //   // return res_fut.get();
    return count;
    // return 0;
  }

  /* -------------------------------------- */

  vector<CT> start(vector<string> &X)
  {
    Stopwatch sw;

    print_line();
    cout << "DelegateStart" << endl;
    print_line();

    sw.start();

    cout << "Generating keys... ";
    KeyPair<DCRTPoly> kp = party.bfv_ctx->KeyGen();
    sk = kp.secretKey;
    party.pro_parms.pk = kp.publicKey;
    cout << "generated." << endl;

    cout << "Packing plaintexts... ";
    HashMap hm(party.pro_parms);
    hm.insert(X);
    vector<PT> pt;
    hm.serialize(party.bfv_ctx, pt, true);
    cout << "packed." << endl;

    cout << "Encrypting plaintexts... ";
    vector<CT> M;
    party.encrypt_all(M, pt);

    cout << "\nElapsed: " << sw.elapsed() << "s" << endl;
    return M;
  }

  size_t finish(vector<CT> &B)
  {
    print_line();
    cout << "DelegateFinish" << endl;
    print_line();

    return decrypt_check_all(B);
    // return 0;
  }
};