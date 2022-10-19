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
      size_t idx = get_map_index(X[i]);
      data[idx] = sha384(X[i] + "||**VALUE**||");
      ad_data[idx] = (uint32_t)ad[i];
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

  vector<bool> filled_slots()
  {
    vector<bool> ret(n, false);
    for (size_t i = 0; i < n; i++)
    {
      if (data[i].size() > 0)
        ret[i] = true;
    }
    return ret;
  }

  void fill_empty_random()
  {
    Stopwatch sw;

    sw.start();
    size_t n_empty = n_empty_slots();
    cout << "# Empty slots = " << n_empty_slots() << endl;
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
      for (size_t i = 0; i < n; i++)
      {
        if (ad_data[i] == 0)
          ad_data[i] = random_int(65537);
      }
    }
  }

  void fill_empty_zeros()
  {
    for (size_t i = 0; i < n; i++)
    {
      if (data[i].size() == 0)
        data[i] = vector<uint8_t>(sz, 0);
    }
  }

  inline void fill_int_arr(vector<int64_t> *int_vec, size_t val, size_t start_idx, size_t num_vals)
  {
    for (size_t i = start_idx; i < start_idx + num_vals; i++)
      (*int_vec)[i] = val;
  }

  void hot_encoding_mask(CryptoContext<DCRTPoly> &bfv_ctx, vector<PT> &one_hot, vector<PT> &zero_hot, size_t batch_size)
  {
    vector<bool> filled = filled_slots();
    size_t ring_dim = bfv_ctx->GetRingDimension();
    size_t num_pt = (n / batch_size) + ((n % batch_size == 0) ? 0 : 1);

    one_hot.resize(num_pt);
    zero_hot.resize(num_pt);

    size_t n_cf_per_hash = sz * 8;
    if (pack_type == MULTIPLE_COMPACT)
      n_cf_per_hash = ring_dim / batch_size;
    for (size_t i = 0; i < num_pt; i++)
    {
      vector<int64_t> hot_vec(n_cf_per_hash * batch_size);
      for (size_t j = 0; j < batch_size; j++)
      {
        size_t start_idx = n_cf_per_hash * j;
        if (filled[i * batch_size + j])
          fill_int_arr(&hot_vec, 1, start_idx, n_cf_per_hash);
        else
          fill_int_arr(&hot_vec, 0, start_idx, n_cf_per_hash);
      }
      one_hot[i] = bfv_ctx->MakePackedPlaintext(hot_vec);
      for (size_t j = 0; j < n_cf_per_hash * batch_size; j++)
        hot_vec[j] = 1 - hot_vec[j];
      zero_hot[i] = bfv_ctx->MakePackedPlaintext(hot_vec);
    }
  }

  void serialize_data(CryptoContext<DCRTPoly> &ctx, vector<PT> &pt, bool ad, size_t batch_size, size_t num_threads)
  {
    size_t ring_dim = ctx->GetRingDimension();
    size_t num_hashes_per_pt = batch_size;
    if (ad)
    {
      size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
      cout << "# Plaintexts = " << num_pt << endl;
      cout << "# Hashes / Plaintext = " << num_hashes_per_pt << endl;
      pt.resize(num_pt);
      size_t count = num_hashes_per_pt;
      vector<double> vec(count);
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt != 0))
        {
          count = (n % num_hashes_per_pt);
          vec.resize(count);
        }
        for (size_t j = 0; j < count; j++)
          vec[j] = (double)ad_data[j + (i * num_hashes_per_pt)];
        pt[i] = ctx->MakeCKKSPackedPlaintext(vec);
      }
      return;
    }
    vector<vector<uint8_t>> *buf = &data;
    size_t num_cf_per_hash = ring_dim / num_hashes_per_pt;
    size_t num_pt = (n / num_hashes_per_pt) + ((n % num_hashes_per_pt == 0) ? 0 : 1);
    pt.resize(num_pt);

    cout << "# Plaintexts = " << num_pt << endl;
    cout << "# Hashes / Plaintext = " << num_hashes_per_pt << endl;
    size_t num_hashes = num_hashes_per_pt;

    BS::thread_pool pool(1);

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
        pack_bitwise_multiple(ctx, &pt[i], buf, i * num_hashes_per_pt, num_hashes, sz * 8, (i == num_pt - 1));
      }
    }
    else if (pack_type == MULTIPLE_COMPACT)
    {
      for (size_t i = 0; i < num_pt; i++)
      {
        if ((i == num_pt - 1) && (n % num_hashes_per_pt > 0))
          num_hashes = n % num_hashes_per_pt;
        pool.push_task(pack_multiple_compact, ctx, &pt[i], buf, i * num_hashes_per_pt, num_hashes, num_cf_per_hash, ring_dim, (i == num_pt - 1));
      }
    }

    pool.wait_for_tasks();
  }

  void serialize(CryptoContext<DCRTPoly> &bfv_ctx, CryptoContext<DCRTPoly> &ckks_ctx, vector<PT> &pt, vector<PT> &ad_pt, bool fill_random, size_t batch_size, size_t num_threads)
  {
    if (fill_random)
      fill_empty_random();
    else
      fill_empty_zeros();

    serialize_data(bfv_ctx, pt, false, batch_size, num_threads);
    if (ad_data.size() > 0)
      serialize_data(ckks_ctx, ad_pt, true, batch_size, num_threads);
  }
};
