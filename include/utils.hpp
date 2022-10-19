#pragma once

#include <vector>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <map>
#include <string>
#include <cmath>
#include <set>
#include <cassert>
#include <chrono>
#include <random>

using namespace std;
using namespace std::chrono;

/* -------------------------------------- */

struct Stopwatch
{
  time_point<high_resolution_clock> t0;

  Stopwatch() {}

  inline void start()
  {
    t0 = high_resolution_clock::now();
  }

  inline double elapsed()
  {
    auto t1 = high_resolution_clock::now();
    return std::chrono::duration_cast<milliseconds>(t1 - t0).count() / 1e3;
  }
};

/* -------------------------------------- */

void print_vec(const vector<complex<double>> &vec, size_t sz)
{
  if (sz == 0)
    sz = vec.size();
  cout << "size: " << sz << endl;
  for (size_t i = 0; i < sz; i++)
  {
    cout << vec[i] << " ";
  }
  cout << endl;
}

inline size_t
get_bitsize(size_t x)
{
  return (size_t)log2(x) + 1;
}

inline bool is_bit_set(uint8_t x, uint8_t bit)
{
  return 1 == ((x >> bit) & 1);
}

inline bool is_bit_set(size_t x, size_t bit)
{
  return 1 == ((x >> bit) & 1);
}

inline size_t bits_to_bytes(size_t nbits)
{
  return nbits / 8 + ((nbits % 8 != 0) ? 1 : 0);
}

inline bool is_zero(vector<uint8_t> *buf)
{
  for (size_t i = 0; i < buf->size(); i++)
  {
    if ((*buf)[i] != 0)
      return false;
  }
  return true;
}

/* -------------------------------------- */

inline void print_sep()
{
  cout << "===================================" << endl;
}

inline void print_line()
{
  cout << "-----------------------------------" << endl;
}

inline void print_title(string title)
{
  print_line();
  cout << title << endl;
  print_line();
}
/* -------------------------------------- */

inline void random_bytes(uint8_t *buf, size_t sz)
{
  // if (sz > INT32_MAX)
  // {
  int64_t remain = sz;
  while (remain > 0)
  {
    int err = RAND_bytes(buf, (remain > INT32_MAX) ? INT32_MAX : remain);
    assert(err == 1);
    remain -= INT32_MAX;
  }
  return;
  // }
  // int err = RAND_bytes(buf, sz);
  // assert(err == 1);
}

vector<string> random_strings(size_t num)
{
  size_t str_bytes = 6;
  size_t t_bytes = str_bytes * num;
  vector<uint8_t> buf(t_bytes);
  random_bytes(buf.data(), t_bytes);
  vector<string> ret(num);
  for (size_t i = 0; i < num; i++)
  {
    char arr[str_bytes * 2 + 1];
    size_t offset = (i * str_bytes);
    for (size_t j = 0; j < str_bytes; j++)
      sprintf(arr + (2 * j), "%02X", buf[offset + j]);
    ret[i] = string(arr);
  }
  return ret;
}

int64_t random_int(size_t mod)
{
  int64_t r;
  random_bytes((uint8_t *)&r, sizeof(r));
  return r % mod;
}

// vector<int64_t> random_ints(size_t num)
// {
//   vector<int64_t> r;
// }

/* -------------------------------------- */

void write(vector<int64_t> &vec, string fpath)
{
  ofstream out_file(fpath);
  for (const auto &e : vec)
    out_file << e << "\n";
}

void write(vector<string> &vec, string fpath)
{
  ofstream out_file(fpath);
  for (const auto &e : vec)
    out_file << e << "\n";
}

void read(vector<int64_t> &vec, string fpath)
{
  ifstream in_file(fpath);
  for (size_t i = 0; i < vec.size(); i++)
  {
    in_file >> vec[i];
  }
}

void read(vector<string> &vec, string fpath)
{
  ifstream in_file(fpath);
  for (size_t i = 0; i < vec.size(); i++)
  {
    in_file >> vec[i];
  }
}

void write_data(vector<vector<string>> &data, vector<int64_t> &ad, string dirpath)
{
  cout << "Writing data..." << endl;
  for (size_t i = 0; i < data.size(); i++)
  {
    string path = dirpath + "/" + to_string(i) + ".dat";
    write(data[i], path);
    cout << "\tWrote to " << path << "." << endl;
  }
  if (ad.size() > 0)
    write(ad, dirpath + "/0-AD.dat");
}

void read_data(vector<vector<string>> &data, vector<int64_t> &ad, size_t x0, size_t xi, string dirpath, bool with_ad)
{
  cout << "Reading data..." << endl;
  for (size_t i = 0; i < data.size(); i++)
  {
    data[i].resize(((i == 0) ? x0 : xi));
    string path = dirpath + "/" + to_string(i) + ".dat";
    read(data[i], path);
    cout << "\tRead from " << path << "." << endl;
  }
  if (with_ad)
  {
    ad.resize(x0);
    read(ad, dirpath + "/0-AD.dat");
  }
}

/* -------------------------------------- */

size_t get_intersection_size(vector<vector<string>> &data, bool iu)
{
  size_t max_size = 0;
  for (size_t i = 1; i < data.size(); i++)
    max_size += data[i].size();

  vector<string> U(max_size), Uprime(max_size), I(max_size);
  vector<string>::iterator it;
  if (iu)
  {
    it = set_union(data[1].begin(), data[1].end(), data[2].begin(), data[2].end(), U.begin());
    U.resize(it - U.begin());
    for (size_t i = 3; i < data.size(); i++)
    {
      it = set_union(U.begin(), U.end(), data[i].begin(), data[i].end(), Uprime.begin());
      Uprime.resize(it - Uprime.begin());
      U = Uprime;
    }
  }
  else
  {
    it = set_intersection(data[1].begin(), data[1].end(), data[2].begin(), data[2].end(), U.begin());
    U.resize(it - U.begin());
    for (size_t i = 3; i < data.size(); i++)
    {
      it = set_intersection(U.begin(), U.end(), data[i].begin(), data[i].end(), Uprime.begin());
      Uprime.resize(it - Uprime.begin());
      U = Uprime;
    }
  }

  it = set_intersection(U.begin(), U.end(), data[0].begin(), data[0].end(), I.begin());
  I.resize(it - I.begin());

  return I.size();
}

void gen_random_data(vector<vector<string>> &ret, vector<int64_t> &ad, size_t n_parties, size_t x0, size_t xi, size_t int_sz, bool iu, bool run_sum)
{
  cout << "Generating random data...";
  vector<string> int_strs = random_strings(int_sz);
  if (iu)
  {
    // Intersection-With-Union
    ret[0] = vector<string>(int_strs);
    for (size_t i = 1; i < n_parties; i++)
      ret[i] = vector<string>();
    for (size_t i = 0; i < int_sz; i++)
    {
      // Generate random non-empty subset of non-delegates
      size_t rand_sub = 0;
      while (rand_sub == 0)
        rand_sub = random_int(static_cast<size_t>(pow(2, n_parties - 1)));

      for (size_t j = 1; j < n_parties; j++)
      {
        if (is_bit_set(rand_sub, j - 1))
          ret[j].push_back(int_strs[i]);
      }
    }
    // Fill with random elements up to x0 or xi
    size_t total = 0;
    for (size_t i = 0; i < n_parties; i++)
      total += ((i == 0) ? x0 : xi) - ret[i].size();
    vector<string> rand_strs = random_strings(total);
    size_t offset = 0;
    for (size_t i = 0; i < n_parties; i++)
    {
      size_t len = ((i == 0) ? x0 : xi) - ret[i].size();
      ret[i].insert(end(ret[i]), rand_strs.data() + offset, rand_strs.data() + offset + len);
      offset += len;
      assert(ret[i].size() == ((i == 0) ? x0 : xi));
    }
  }
  else
  {
    // Intersection
    for (size_t i = 0; i < n_parties; i++)
    {
      ret[i] = vector<string>(int_strs);
      vector<string> r = random_strings(((i == 0) ? x0 : xi) - int_sz);
      ret[i].insert(end(ret[i]), begin(r), end(r));
    }
  }

  for (size_t i = 0; i < ret.size(); i++)
  {
    sort(ret[i].begin(), ret[i].end());
  }

  if (run_sum)
  {
    ad.resize(ret[0].size());
    for (size_t i = 0; i < ad.size(); i++)
      ad[i] = random_int(65537);
  }

  cout << " generated." << endl;
}
