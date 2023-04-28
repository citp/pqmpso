#include <iostream>
#include <iomanip>
#include "crypto.hpp"
#include "utils.hpp"
#include "hashmap.hpp"
#include "argparse.hpp"
#include "ic.hpp"
#include "oversight.hpp"

using namespace std;

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

size_t run_joint_decryption(IC &del, vector<ServiceProvider> &providers, vector<CT> &agg_res)
{
  Stopwatch sw;
  print_title("Joint Decryption");
  sw.start();

  vector<CT> agg_res_parts(providers.size() + 1);
  agg_res_parts[0] = del.party.joint_decrypt(agg_res)[0];
  for (size_t i = 1; i <= providers.size(); i++)
    agg_res_parts[i] = providers[i - 1].joint_decrypt(agg_res)[0];
  PT agg_pt = del.joint_decrypt_final(agg_res_parts);
  agg_pt->SetLength(1);

  printf("\nTime: %5.2fs\n", sw.elapsed());
  return (size_t)agg_pt->GetCKKSPackedValue()[0].real();
}

void run_dkg(IC &ic, vector<ServiceProvider> &providers, Oversight &pclob, PK &apk, shared_ptr<EvalKeys> &ask)
{
  Stopwatch sw;
  print_title("Key Aggregation");
  sw.start();

  // Compute keys
  ic.party.dkg(apk, ask);
  for (size_t i = 0; i < providers.size(); i++)
    providers[i].dkg(apk, ask);

  // Set keys
  ic.party.pro_parms.apk = apk;
  for (size_t i = 0; i < providers.size(); i++)
    providers[i].pro_parms.apk = apk;
  ic.party.pro_parms.ask = ask;
  pclob.pro_parms.ask = ask;

  printf("\nTime: %5.2fs\n", sw.elapsed());
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

  program.add_argument("--in-bits")
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
  auto in_bits = program.get<bool>("--in-bits");

  if (in_bits)
  {
    n = (1 << n);
    x0 = (1 << x0);
    xi = (1 << xi);
    int_sz = (1 << int_sz);
    map_sz = (1 << map_sz);
  }

  PackingType pack_type = MULTIPLE_COMPACT;
  if (pack_type_str == "multiple")
    pack_type = MULTIPLE;
  else if (pack_type_str == "single")
    pack_type = SINGLE;

  print_parameters(iu, run_sum, n, x0, xi, int_sz, map_sz, dir, v, nthreads);

  vector<vector<string>> data(n);
  vector<int64_t> ad;

  if (read)
    read_data(data, ad, x0, xi, dir, run_sum);
  else
    gen_random_data(data, ad, n, x0, xi, int_sz, iu, run_sum);

  cout << int_sz << " " << get_intersection_size(data, iu) << endl;
  assert((size_t)int_sz == get_intersection_size(data, iu));

  if (!read)
    write_data(data, ad, dir);

  print_sep();

  if (gen_only)
    exit(0);

  /* Parameter Generation */
  size_t ring_dim = 32768;
  shared_ptr<CCParams<CryptoContextBFVRNS>> bfv_parms = gen_bfv_params(ring_dim);
  shared_ptr<CCParams<CryptoContextCKKSRNS>> ckks_parms = gen_ckks_params(ring_dim);
  ProtocolParameters pro_parms = {0, (size_t)n, (size_t)map_sz, 48, (size_t)nthreads, n_hashes_in_pt(pack_type, ring_dim, 16, 384), run_sum, pack_type, nullptr, nullptr};

  /* Setup */
  IC ic(pro_parms, bfv_parms, ckks_parms);
  vector<ServiceProvider> providers(n - 1);
  pro_parms.pk = ic.party.pro_parms.pk;
  pro_parms.ek = ic.party.pro_parms.ek;
  for (int i = 0; i < n - 1; i++)
  {
    pro_parms.party_id = i + 1;
    providers[i] = ServiceProvider(pro_parms, bfv_parms, ckks_parms);
  }
  Oversight pclob(pro_parms, bfv_parms, ckks_parms);

  /* Key Aggregation */
  PK apk;
  shared_ptr<EvalKeys> ask = make_shared<EvalKeys>();
  EvalKey<DCRTPoly> aak;
  if (run_sum)
    run_dkg(ic, providers, pclob, apk, ask);

  /* IC: Round 1 */
  Tuple<vector<CT>> M = ic.round1(data[0], ad);

  /* Service Providers */
  Tuple<vector<CT>> R;
  R.e0 = vector<CT>(M.e0.size());
  R.e1 = vector<CT>(M.e1.size());
  vector<PT> Rand;
  for (int i = 0; i < n - 1; i++)
    providers[i].compute_on_r(&M, &R, &Rand, data[i + 1], iu, run_sum);
  
  /* IC: Round 2 */
  vector<PT> R_pt;
  ic.round2_fix(&R, &R_pt);

  vector<CT> agg_res(1);
  size_t int_size = pclob.compute_result(&R, R_pt, Rand, agg_res);

  cout << "Computed intersection size: " << int_size << endl;
  if (run_sum)
  {
    /* Joint Decryption */
    size_t int_sum = run_joint_decryption(ic, providers, agg_res);
    cout << "Computed intersection sum: " << setprecision(9) << int_sum << endl;
  }
  return 0;
}