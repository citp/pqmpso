#pragma once

#include <vector>
#include <cryptopp/blake2.h>
#include <cryptopp/cryptlib.h>
#include <seal/seal.h>

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
  size_t n, sz;
  vector<T> data;
};

template <typename T>
HashMap<T> New(size_t n, size_t sz)
{
  HashMap<T> hm;
  hm.n = n;
  hm.sz = sz;
  hm.data = vector<T>(n);
  return hm;
}

// seal::Ciphertext

template <typename T>
void Insert(HashMap<T> &hm, const string &key, T &value)
{
  hm.data[IndexFn(key, hm.n)] = value;
}
