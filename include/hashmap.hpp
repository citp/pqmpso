#pragma once

#include <vector>
#include <cryptopp/blake2.h>
#include <cryptopp/cryptlib.h>
#include <seal/seal.h>
#include <cassert>

#include "BS_thread_pool.hpp"

using namespace std;

/* Helpers */

size_t Blake2b(const string x)
{
  CryptoPP::byte digest[sizeof(size_t)];
  CryptoPP::BLAKE2b hash;
  hash.Update((const CryptoPP::byte *)x.data(), x.size());
  hash.TruncatedFinal(digest, sizeof(size_t));
  return *((size_t *)digest);
}

inline size_t IndexFn(const string &x, size_t n)
{
  return Blake2b(x) % n;
}

/* Main API */

template <typename T>
struct HashMap
{
  size_t n;
  vector<T> data;

  HashMap<T>(size_t n_)
  {
    n = n_;
    data = vector<T>(n);
  }

  void insert(const string &key, const T &value)
  {
    data[IndexFn(key, n)] = value;
  }

  void insert_all(const vector<string> &keys, const vector<T> &values)
  {
    assert(keys.size() == values.size());
    BS::thread_pool pool;
    cout << "#Threads: " << pool.get_thread_count() << endl;

    for (size_t i = 0; i < keys.size(); i++)
    {
      pool.push_task([this, keys, values, i]
                     { this->insert(keys[i], values[i]); });
    }
    pool.wait_for_tasks();
  }
};

// template <typename T>
// HashMap<T> New(size_t n, size_t sz)
// {
//   HashMap<T> hm;
//   hm.n = n;
//   hm.sz = sz;
//   hm.data = vector<T>(n);
//   return hm;
// }

// seal::Ciphertext

// template <typename T>
// void Insert(HashMap<T> &hm, const string &key, T &value)
// {
//   hm.data[IndexFn(key, hm.n)] = value;
// }
