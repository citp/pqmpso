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

void run_key_aggregation(Delegate &del, vector<Party> &providers, PK &apk, shared_ptr<EvalKeys> &ask, EvalKey<DCRTPoly> &aak)
{
  // Compute keys
  del.party.key_agg(apk, ask, aak);
  for (size_t i = 0; i < providers.size(); i++)
    providers[i].key_agg(apk, ask, aak);

  // Set keys
  del.party.pro_parms.apk = apk;
  for (size_t i = 0; i < providers.size(); i++)
    providers[i].pro_parms.apk = apk;
  del.party.pro_parms.ask = ask;

  // Verify apk
  vector<double> a = {1 << 10, 1 << 9, 1 << 8, 1 << 7};
  PT pt1 = del.party.ckks_ctx->MakeCKKSPackedPlaintext(a), pt2;
  cout << pt1 << endl;
  vector<CT> ct = {del.party.ckks_ctx->Encrypt(apk, pt1)};
  vector<CT> ct_parts(providers.size() + 1);
  ct_parts[0] = del.party.joint_decrypt(ct)[0];
  for (size_t i = 1; i <= providers.size(); i++)
    ct_parts[i] = providers[i - 1].joint_decrypt(ct)[0];
  del.party.ckks_ctx->MultipartyDecryptFusion(ct_parts, &pt2);
  pt2->SetLength(4);
  cout << pt2 << endl;

  // Verify ask
  del.party.ckks_ctx->InsertEvalSumKey(ask);
  CT ct2 = del.party.ckks_ctx->EvalSum(ct[0], 4);
  vector<CT> ct_sum = {ct2};
  ct_parts[0] = del.party.joint_decrypt(ct_sum)[0];
  for (size_t i = 1; i <= providers.size(); i++)
    ct_parts[i] = providers[i - 1].joint_decrypt(ct_sum)[0];
  del.party.ckks_ctx->MultipartyDecryptFusion(ct_parts, &pt2);
  pt2->SetLength(1);
  cout << pt2 << endl;
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

  assert((size_t)int_sz == get_intersection_size(data, iu));

  if (!read)
    write_data(data, ad, dir);

  print_sep();

  if (gen_only)
    exit(0);

  /* Parameter Generation */
  ProtocolParameters pro_parms = {0, (size_t)n, (size_t)map_sz, 48, (size_t)nthreads, run_sum, pack_type, nullptr, nullptr};

  shared_ptr<CCParams<CryptoContextBFVRNS>> bfv_parms = gen_bfv_params();
  shared_ptr<CCParams<CryptoContextCKKSRNS>> ckks_parms = gen_ckks_params();

  /* Setup */
  Delegate del(pro_parms, bfv_parms, ckks_parms);
  vector<Party> providers(n - 1);

  pro_parms.pk = del.party.pro_parms.pk;
  pro_parms.ek = del.party.pro_parms.ek;
  for (int i = 0; i < n - 1; i++)
  {
    pro_parms.party_id = i + 1;
    providers[i] = Party(pro_parms, bfv_parms, ckks_parms);
  }

  /* Key Aggregation */
  // AggKeys agg_keys;
  PK apk;
  shared_ptr<EvalKeys> ask = make_shared<EvalKeys>();
  EvalKey<DCRTPoly> aak;
  if (run_sum)
    run_key_aggregation(del, providers, apk, ask, aak);

  /* Main Protocol */
  Tuple<vector<CT>> M = del.start(data[0], ad);
  Tuple<vector<CT>> R;
  R.e0 = vector<CT>(M.e0.size());
  R.e1 = vector<CT>(M.e1.size());
  for (int i = 0; i < n - 1; i++)
  {
    // if (run_sum)
    // {
    //   providers[i].pro_parms.apk = apk;
    //   providers[i].pro_parms.ask = ask;
    // }
    providers[i].compute_on_r(&M, &R, data[i + 1], iu, run_sum);
  }
  // del.finish(&R);
  vector<CT> agg_res = del.finish(&R);
  vector<CT> agg_res_parts(n);
  agg_res_parts[0] = del.party.joint_decrypt(agg_res)[0];
  for (int i = 1; i < n; i++)
    agg_res_parts[i] = providers[i - 1].joint_decrypt(agg_res)[0];
  PT agg_pt = del.joint_decrypt(agg_res_parts);
  agg_pt->SetLength(1);
  cout << agg_pt << endl;

  // vector<complex<double>> int_sum_vec = agg_pt->GetCKKSPackedValue();
  // cout << "Computed intersection-sum: " << int_sum_vec[0].real << endl;
}