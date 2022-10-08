#pragma once

#include <vector>
// #include <seal/seal.h>
#include <cassert>

#include <cryptopp/osrng.h>

using namespace std;
// using namespace seal;

/* Helpers */

// inline size_t IndexFn(const string &x, size_t n)
// {
//   return *((size_t *)Blake2b(x, sizeof(size_t)).data()) % n;
// }

/* Main API */

struct HashMap
{
  size_t n, sz, n_bits, num_pt, plain_mod_bits, poly_mod_deg, plain_mod;
  vector<vector<uint8_t>> data;
  PackingType pack_type;

  HashMap(ProtocolParameters &pro_parms)
  {
    n = pro_parms.map_sz;
    sz = pro_parms.hash_sz;
    pack_type = pro_parms.pack_type;
    n_bits = get_bitsize(n);
    // plain_mod_bits = enc_parms.plain_modulus().bit_count() - 1;
    // plain_mod = enc_parms.plain_modulus().value();
    // poly_mod_deg = enc_parms.poly_modulus_degree();
    data = vector<vector<uint8_t>>(n);
  }

  /* -------------------------------------- */

  // Returns the index of x in the hashmap
  inline size_t get_map_index(const string &x)
  {
    return *((size_t *)blake2b(x + "||~~MAP~~||", sizeof(size_t)).data()) % n;
  }

  // Returns the number of plaintexts needed to pack the hash map
  // inline size_t get_num_pt(PackingType pack_type, size_t poly_mod_deg)
  // {
  //   size_t nhpt = n_hashes_in_pt(pack_type, poly_mod_deg, sz * 8);
  //   return (n / nhpt) + ((n % nhpt == 0) ? 0 : 1);
  // }

  // Returns the (starting) plaintext index associated with a hashmap index
  // inline size_t get_pt_index(size_t map_idx)
  // {
  //   size_t nbits_pt = plain_mod_bits * poly_mod_deg;
  //   size_t nbits_before = map_idx * sz * 8;
  //   return nbits_before / nbits_pt;
  // }

  // inline size_t get_start_in_pt(size_t i)
  // {
  // }

  // Returns a coefficient in [0, 2^plain_mod_bits] with index cf_idx associated with the string at map_idx.
  // inline size_t get_cf(size_t map_idx, size_t cf_idx, size_t offset)
  // {
  //   assert(cf_idx * plain_mod_bits < sz * 8);

  // data[map_idx]
  // size_t nbits_before = cf_idx * plain_mod_bits;
  //   return nbits_before;
  // }

  /* -------------------------------------- */

  void
  insert(const vector<string> &X)
  {
    for (auto x : X)
    {
      data[get_map_index(x)] = blake2b(x + "||**VALUE**||", sz);
    }
  }

  size_t n_empty_slots()
  {
    size_t n_empty = 0;
    for (auto v : data)
    {
      if (v.size() == 0)
        n_empty++;
    }
    return n_empty;
  }

  void fill_empty_random()
  {
    Stopwatch sw;

    sw.start();
    size_t n_empty = n_empty_slots();
    vector<uint8_t> buf(n_empty * sz);
    random_bytes(buf.data(), n_empty * sz);
    size_t idx = 0;
    for (size_t i = 0; i < n; i++)
    {
      if (data[i].size() == 0)
      {
        data[i] = vector<uint8_t>(sz);
        memcpy(data[i].data(), buf.data() + (idx * sz), sz);
        idx++;
      }
    }
    // cout << "# Empty slots: " << n_empty << endl;
    // cout << "Generated " << n_empty * sz << " random bytes" << endl;
    cout << "filled empty slots with randomness... ";
  }

  void fill_empty_zeros()
  {
    for (size_t i = 0; i < n; i++)
    {
      if (data[i].size() < sz)
        data[i] = vector<uint8_t>(sz, 0);
      assert(data[i].size() == sz);
    }
    cout << "filled empty slots with zeros... ";
  }

  void serialize(CryptoContext<DCRTPoly> &bfv_ctx, vector<PT> &pt, bool fill_random)
  {
    cout << "# Empty slots = " << n_empty_slots() << endl;
    if (fill_random)
      fill_empty_random();
    else
      fill_empty_zeros();

    size_t plain_mod_bits = get_bitsize(bfv_ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
    size_t nbits = sz * 8;
    size_t num_hashes_per_pt = n_hashes_in_pt(pack_type, bfv_ctx->GetRingDimension(), plain_mod_bits, nbits);
    size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
    pt.resize(num_pt);

    cout << "# Plaintexts = " << num_pt << endl;
    cout << "# Hashes / Plaintext = " << num_hashes_per_pt << endl;
    size_t num_hashes = num_hashes_per_pt;
    if (pack_type == SINGLE)
    {
      for (size_t i = 0; i < num_pt; i++)
        pack_bitwise_single(bfv_ctx, &pt[i], &data[i]);
    }
    else if (pack_type == MULTIPLE)
    {
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt > 0))
          num_hashes = n % num_hashes_per_pt;
        pack_bitwise_multiple(bfv_ctx, &pt[i], &data, i * num_hashes_per_pt, num_hashes, nbits, fill_random);
      }
    }
    else if (pack_type == MULTIPLE_COMPACT)
    {
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt > 0))
          num_hashes = n % num_hashes_per_pt;
        pack_multiple_compact(bfv_ctx, &pt[i], &data, i * num_hashes_per_pt, num_hashes, fill_random);
      }
    }
  }
};

// void serialize_one(Plaintext &pt, vector<vector<uint8_t>> &to_pack, size_t start_idx, size_t count)
// {
// }
