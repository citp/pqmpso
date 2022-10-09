#include <iostream>
#include "crypto.hpp"
#include "utils.hpp"
#include "hashmap.hpp"
#include "argparse.hpp"
#include "delegate.hpp"

using namespace std;
// using namespace lbcrypto;

void print_parameters(bool iu, bool run_sum, int n, int x0, int xi, int int_sz, int map_sz, string dir, bool v, int nthreads)
{
  print_sep();
  string protocol = string(iu ? "MPSIU" : "MPSI") + string(run_sum ? "-Sum" : "");
  cout
      << "Protocol\t" << protocol << endl;
  cout << "#Parties\t" << n << endl;
  cout << "|X_0|\t\t" << x0 << endl;
  cout << "|X_i|\t\t" << xi << endl;
  cout << "|I|\t\t" << int_sz << endl;
  cout << "|M|\t\t" << map_sz << endl;
  cout << "Threads\t\t" << nthreads << endl;
  cout << "Location\t" << dir << endl;
  cout << "Verbose?\t" << (v ? "True" : "False") << endl;
  print_sep();
}

int main(int argc, char *argv[])
{
  argparse::ArgumentParser program("Post-Quantum Secure MPSIU");

  program.add_argument("--read")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--iu")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--sum")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--n")
      .default_value(4)
      .help("number of parties (including delegate)")
      .scan<'i', int>();

  program.add_argument("--x0")
      .default_value(1048576)
      .help("size of delegate's input set")
      .scan<'i', int>();

  program.add_argument("--xi")
      .default_value(1048576)
      .help("size of non-delegate's input set")
      .scan<'i', int>();

  program.add_argument("--int")
      .default_value(65536)
      .help("size of the intersection (with union)")
      .scan<'i', int>();

  program.add_argument("--map")
      .default_value(16777216)
      .help("size of the hashmap")
      .scan<'i', int>();

  program.add_argument("--dir")
      .help("data directory")
      .default_value(string("./data"));

  program.add_argument("--pack")
      .help("packing type")
      .default_value(string("compact"));

  program.add_argument("--v")
      .help("increase output verbosity")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--t")
      .default_value(64)
      .help("number of threads to use")
      .scan<'i', int>();

  program.add_argument("--gen")
      .help("generate random data and exit, do NOT run the protocol")
      .default_value(false)
      .implicit_value(true);

  try
  {
    program.parse_args(argc, argv);
  }
  catch (const runtime_error &err)
  {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  auto read = program.get<bool>("--read");
  auto iu = program.get<bool>("--iu");
  auto run_sum = program.get<bool>("--sum");
  auto n = program.get<int>("--n");
  auto x0 = program.get<int>("--x0");
  auto xi = program.get<int>("--xi");
  auto int_sz = program.get<int>("--int");
  auto map_sz = program.get<int>("--map");
  auto dir = program.get<string>("--dir");
  auto v = program.get<bool>("--v");
  auto gen_only = program.get<bool>("--gen");
  auto pack_type_str = program.get<string>("--pack");
  auto nthreads = program.get<int>("--t");

  PackingType pack_type = MULTIPLE_COMPACT;
  if (pack_type_str == "multiple")
    pack_type = MULTIPLE;
  else if (pack_type_str == "single")
    pack_type = SINGLE;

  print_parameters(iu, run_sum, n, x0, xi, int_sz, map_sz, dir, v, nthreads);

  vector<vector<string>> data(n);
  if (read)
    read_data(data, x0, xi, dir);
  else
    gen_random_data(data, n, x0, xi, int_sz, iu, run_sum);

  assert((size_t)int_sz == get_intersection_size(data, iu));

  if (!read)
    write_data(data, dir);

  print_sep();

  if (gen_only)
    exit(0);

  ProtocolParameters pro_parms = {0, (size_t)n, (size_t)map_sz, 32, (size_t)nthreads, pack_type, NULL};

  shared_ptr<CCParams<CryptoContextBFVRNS>> enc_parms = gen_enc_params();
  Delegate del(enc_parms, pro_parms);
  vector<Party> providers(n - 1);

  vector<CT> M = del.start(data[0]);
  vector<CT> R(M.size());
  pro_parms.pk = del.party.pro_parms.pk;
  for (int i = 0; i < n - 1; i++)
  {
    pro_parms.party_id = i + 1;
    providers[i] = Party(enc_parms, pro_parms);
    providers[i].compute_on_r(&M, &R, data[i + 1], iu, run_sum);
  }
  del.finish(&R);
}