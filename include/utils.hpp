#pragma once

#include <vector>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <map>
#include <string>
#include <coro/coro.hpp>

using namespace std;

string random_string()
{
  random_device rd;
  mt19937 generator(rd());
  return to_string(generator() % UINT64_MAX);
}

vector<string> random_strings(size_t num)
{
  vector<string> ret(num);
  for (size_t i = 0; i < num; i++)
    ret[i] = random_string(len);
  return ret;
}

// {
//   using namespace coro;
//   thread_pool tp;

//   auto offload_task = [&]() -> task<string>
//   {
//     co_return random_string();
//   };

//   auto main_task = [&]() -> task<vector<string>>
//   {
//     vector<task<string>> child_tasks{};
//     child_tasks.reserve(num);
//     for (size_t i = 0; i < num; ++i)
//       child_tasks.emplace_back(offload_task());
//     auto res = co_await when_all(move(child_tasks));

//     vector<string> ret;
//     ret.reserve(num);
//     for (const auto &task : res)
//     {
//       ret.emplace_back(task.return_value());
//     }
//     co_return ret;
//   };

//   auto res = sync_wait(main_task());
//   return res;
// }

void write(vector<string> &vec, string fpath)
{
  ofstream out_file(fpath);
  for (const auto &e : vec)
    out_file << e << "\n";
}

void read(vector<string> &vec, string fpath)
{
  ifstream in_file(fpath);
  for (size_t i = 0; i < vec.size(); i++)
  {
    in_file >> vec[i];
  }
}

// size_t compute_intersection(vector<vector<string>> &data, bool iu)
// {
//   map<string,int> all;
//   for (size_t i = 1; i < data.size(); i++)
//   {

//   }

// }

void gen_random_data(vector<vector<string>> &ret, size_t n_parties, size_t x0, size_t xi, size_t int_sz, bool iu)
{
  cout << "Generating random data...";
  ret[0] = random_strings(x0);

  // Set the intersection
  vector<string> int_strs(&ret[0][0], &ret[0][int_sz]);

  if (iu)
  {
    // Intersection-With-Union
    random_device rd;
    mt19937 generator(rd());
    // Keep track of each element in the intersection
    vector<int> added(int_sz);
    for (size_t i = 0; i < int_sz; i++)
      added[i] = 0;
    for (size_t i = 1; i < n_parties; i++)
      ret[i] = vector<string>();
    for (size_t i = 0; i < int_sz; i++)
    {
      // Randomly choose a number tau in [1, n_parties]
      size_t tau = 1 + (generator() % n_parties);
      // Add element to tau parties
      for (size_t j = 1; j < tau; j++)
        ret[j].push_back(int_strs[i]);
    }
    // Fill with random elements up to xi
    for (size_t i = 1; i < n_parties; i++)
    {
      vector<string> r = random_strings(xi - ret[i].size());
      ret[i].insert(end(ret[i]), begin(r), end(r));
    }
  }
  else
  {
    // Intersection
    for (size_t i = 1; i < n_parties; i++)
    {
      ret[i] = vector<string>(int_strs);
      vector<string> r = random_strings(xi - int_sz);
      ret[i].insert(end(ret[i]), begin(r), end(r));
    }
  }

  cout << " generated." << endl;
}

void write_data(vector<vector<string>> &data, string dirpath)
{
  cout << "Writing data..." << endl;
  for (size_t i = 0; i < data.size(); i++)
  {
    string path = dirpath + "/" + to_string(i) + ".dat";
    write(data[i], path);
    cout << "\tWrote to " << path << "." << endl;
  }
}

void read_data(vector<vector<string>> &data, size_t x0, size_t xi, string dirpath)
{
  cout << "Reading data..." << endl;
  for (size_t i = 0; i < data.size(); i++)
  {
    data[i].resize(((i == 0) ? x0 : xi));
    string path = dirpath + "/" + to_string(i) + ".dat";
    read(data[i], path);
  }
}