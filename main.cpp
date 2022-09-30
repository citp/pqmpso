#include <iostream>
#include "crypto.hpp"
#include "hashmap.hpp"
#include "argparse.hpp"
#include "utils.hpp"

using namespace std;
using namespace seal;

void print_parameters(bool iu, int n, int x0, int xi, int int_sz, string dir, bool v)
{
  cout << "===================================" << endl;
  cout << "Protocol\t" << (iu ? "MPSIU" : "MPSI") << endl;
  cout << "#Parties\t" << n << endl;
  cout << "|X_0|\t\t" << x0 << endl;
  cout << "|X_i|\t\t" << xi << endl;
  cout << "|I|\t\t" << int_sz << endl;
  cout << "Location\t" << dir << endl;
  cout << "Verbose?\t" << (v ? "True" : "False") << endl;
  cout << "===================================" << endl;
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

  program.add_argument("--n")
      .default_value(4)
      .help("number of parties (including delegate)")
      .scan<'i', int>();

  program.add_argument("--x0")
      .default_value(1024)
      .help("size of delegate's input set")
      .scan<'i', int>();

  program.add_argument("--xi")
      .default_value(1048576)
      .help("size of non-delegate's input set")
      .scan<'i', int>();

  program.add_argument("--int")
      .default_value(128)
      .help("size of the intersection (with union)")
      .scan<'i', int>();

  program.add_argument("--dir")
      .help("data directory")
      .default_value(string("./data"));

  program.add_argument("--v")
      .help("increase output verbosity")
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
  auto n = program.get<int>("--n");
  auto x0 = program.get<int>("--x0");
  auto xi = program.get<int>("--xi");
  auto int_sz = program.get<int>("--int");
  auto dir = program.get<string>("--dir");
  auto v = program.get<bool>("--v");

  print_parameters(iu, n, x0, xi, int_sz, dir, v);

  vector<vector<string>> data(n);
  if (read)
  {
    read_data(data, x0, xi, dir);
  }
  else
  {
    gen_random_data(data, n, x0, xi, int_sz, iu);
    write_data(data, dir);
  }

  // cout << "Set encryption parameters and print" << endl;
  // EncryptionParameters parms = gen_enc_params();
  // SEALContext context(parms);
  // cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  // HashMap<seal::Ciphertext> hm = New<seal::Ciphertext>(10, 50);
  // Ciphertext x_encrypted;
  // string x = "hello";
  // Insert<seal::Ciphertext>(hm, x, x_encrypted);
}