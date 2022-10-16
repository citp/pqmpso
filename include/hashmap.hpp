#pragma once

#include <vector>
#include <cassert>
#include <set>

#include <cryptopp/osrng.h>

using namespace std;

/* -------------------------------------- */

struct HashMap
{
  size_t n, sz, n_bits, num_pt, plain_mod_bits, poly_mod_deg, plain_mod;
  vector<vector<uint8_t>> data;
  PackingType pack_type;
  vector<uint32_t> ad_data;

  HashMap(ProtocolParameters &pro_parms)
  {
    n = pro_parms.map_sz;
    sz = pro_parms.hash_sz;
    pack_type = pro_parms.pack_type;
    n_bits = get_bitsize(n);
    data = vector<vector<uint8_t>>(n);
  }

  /* -------------------------------------- */

  // Returns the index of x in the hashmap
  inline size_t get_map_index(const string &x)
  {
    vector<uint8_t> h = sha384(x + "||~~MAP~~||");
    h.resize(sizeof(size_t));
    return *((size_t *)h.data()) % n;
  }

  /* -------------------------------------- */

  void insert(const vector<string> &X)
  {
    for (auto x : X)
      data[get_map_index(x)] = sha384(x + "||**VALUE**||");
  }

  void insert(const vector<string> &X, const vector<int64_t> &ad)
  {
    assert(X.size() == ad.size());
    ad_data.resize(n);
    for (size_t i = 0; i < X.size(); i++)
    {
      vector<int64_t> int_vec;
      size_t idx = get_map_index(X[i]);
      data[idx] = sha384(X[i] + "||**VALUE**||");
      ad_data[idx] = (uint32_t)ad[i];
      // ad_data[idx] = vector<uint8_t>(sizeof(int64_t));
      // memcpy(ad_data[idx].data(), &ad[i], sizeof(int64_t));
      // pack_base_int_arr(int_vec, ad[idx], 2);
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

  set<size_t> filled_slots()
  {
    set<size_t> ret;
    for (size_t i = 0; i < data.size(); i++)
    {
      if (data[i].size() > 0)
        ret.insert(i);
    }
    return ret;
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
    if (ad_data.size() == n)
    {

      // buf = vector<uint8_t>(n_empty * sizeof(int64_t));
      // random_bytes(buf.data(), n_empty * sizeof(int64_t));
      // idx = 0;
      for (size_t i = 0; i < n; i++)
      {
        if (ad_data[i] == 0)
          ad_data[i] = random_int(1000);
        //   if (ad_data[i].size() == 0)
        //   {
        //     ad_data[i] = vector<uint8_t>(sizeof(int64_t));
        //     memcpy(ad_data[i].data(), buf.data() + (idx * sizeof(int64_t)), sizeof(int64_t));
        //   }
      }
    }
    // cout << "# Empty slots: " << n_empty << endl;
    // cout << "Generated " << n_empty * sz << " random bytes" << endl;
    // cout << "filled empty slots with randomness... ";
  }

  void fill_empty_zeros()
  {
    for (size_t i = 0; i < n; i++)
    {
      if (data[i].size() == 0)
        data[i] = vector<uint8_t>(sz, 0);
    }
    // if (ad_data.size() == n)
    // {
    //   for (size_t i = 0; i < n; i++)
    //   {
    //     if (ad_data[i].size() == 0)
    //       ad_data[i] = vector<uint8_t>(sizeof(int64_t), 0);
    //   }
    // }
    // cout << "filled empty slots with zeros... ";
  }

  void fill_int_arr(vector<int64_t> *int_vec, size_t val, size_t start_idx, size_t num_vals)
  {
    for (size_t i = start_idx; i < start_idx + num_vals; i++)
      (*int_vec)[i] = val;
  }

  void hot_encoding_mask(CryptoContext<DCRTPoly> &bfv_ctx, vector<PT> &pt, bool zero_hot)
  {
    set<size_t> filled = filled_slots();
    size_t plain_mod_bits = get_bitsize(bfv_ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
    size_t nbits = sz * 8;
    size_t ring_dim = bfv_ctx->GetRingDimension();
    size_t num_hashes_per_pt = n_hashes_in_pt(pack_type, ring_dim, plain_mod_bits, nbits);
    size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
    pt.resize(num_pt);
    size_t mark = zero_hot ? 0 : 1;

    size_t n_cf_per_hash = nbits;
    if (pack_type == MULTIPLE_COMPACT)
      n_cf_per_hash = ring_dim / num_hashes_per_pt;
    for (size_t i = 0; i < num_pt; i++)
    {
      vector<int64_t> int_vec(n_cf_per_hash * num_hashes_per_pt);
      for (size_t j = 0; j < num_hashes_per_pt; j++)
      {
        if (filled.find(i * num_hashes_per_pt + j) != filled.end())
          fill_int_arr(&int_vec, mark, n_cf_per_hash * j, n_cf_per_hash);
        else
          fill_int_arr(&int_vec, 1 - mark, n_cf_per_hash * j, n_cf_per_hash);
      }
      pt[i] = bfv_ctx->MakePackedPlaintext(int_vec);
    }
  }

  void serialize_data(CryptoContext<DCRTPoly> &ctx, vector<PT> &pt, bool ad)
  {
    size_t ring_dim = ctx->GetRingDimension();
    size_t num_hashes_per_pt = ring_dim / 2;
    if (ad)
    {
      size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
      cout << "# Plaintexts = " << num_pt << endl;
      cout << "# Hashes / Plaintext = " << num_hashes_per_pt << endl;
      pt.resize(num_pt);
      for (size_t i = 0; i < num_pt; i++)
      {
        size_t start = i * num_hashes_per_pt;
        size_t count = num_hashes_per_pt;
        if ((i == num_pt - 1) && (n % num_hashes_per_pt != 0))
          count = (n % num_hashes_per_pt);
        vector<double> vec(count);
        for (size_t j = 0; j < count; j++)
          vec[j] = (double)ad_data[j + start];
        pt[i] = ctx->MakeCKKSPackedPlaintext(vec);
      }
      return;
    }
    // buf = &ad_data;
    vector<vector<uint8_t>> *buf = &data;
    size_t plain_mod_bits = get_bitsize(ctx->GetEncodingParams()->GetPlaintextModulus()) - 1;
    size_t nbits = (*buf)[0].size() * 8;
    num_hashes_per_pt = n_hashes_in_pt(pack_type, ring_dim, plain_mod_bits, nbits);
    size_t num_cf_per_hash = ring_dim / num_hashes_per_pt;
    size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
    pt.resize(num_pt);

    cout << "# Plaintexts = " << num_pt << endl;
    cout << "# Hashes / Plaintext = " << num_hashes_per_pt << endl;
    size_t num_hashes = num_hashes_per_pt;

    if (pack_type == SINGLE)
    {
      for (size_t i = 0; i < num_pt; i++)
        pack_bitwise_single(ctx, &pt[i], &(*buf)[i]);
    }
    else if (pack_type == MULTIPLE)
    {
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt > 0))
          num_hashes = n % num_hashes_per_pt;
        pack_bitwise_multiple(ctx, &pt[i], buf, i * num_hashes_per_pt, num_hashes, nbits, (i == num_pt - 1));
      }
    }
    else if (pack_type == MULTIPLE_COMPACT)
    {
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt > 0))
          num_hashes = n % num_hashes_per_pt;
        pack_multiple_compact(ctx, &pt[i], buf, i * num_hashes_per_pt, num_hashes, num_cf_per_hash, (i == num_pt - 1));
      }
    }
  }

  void serialize(CryptoContext<DCRTPoly> &bfv_ctx, CryptoContext<DCRTPoly> &ckks_ctx, vector<PT> &pt, vector<PT> &ad_pt, bool fill_random)
  {
    cout << "# Empty slots = " << n_empty_slots() << endl;
    if (fill_random)
      fill_empty_random();
    else
      fill_empty_zeros();

    serialize_data(bfv_ctx, pt, false);
    if (ad_data.size() > 0)
      serialize_data(ckks_ctx, ad_pt, true);
  }
};
