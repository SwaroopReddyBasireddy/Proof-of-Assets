#include <stdlib.h>
#include <iostream>
#include <fstream>

#include "ecgadget.hpp"
#include "pedersen.hpp"

using namespace libsnark;
using namespace std;

int main()
{
  typedef libff::alt_bn128_pp ppT;
  typedef libff::Fr<ppT> FieldT;

  // Initialize the curve parameters
  ppT::init_public_params();
  init_curveparams();
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;

  protoboard<FieldT> pb;
  pb_variable<FieldT> outx, outy;
  pb_variable<FieldT> a, b;

  // Allocate variables

  outx.allocate(pb, "outx");
  outy.allocate(pb, "outy");
  a.allocate(pb, "a");
  b.allocate(pb, "b");

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(2);

  // Initialize the gadget
  ec_pedersen_gadget<FieldT> ped(pb, outx, outy, a, b, 51, 256);
  ped.generate_r1cs_constraints();
  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

  // Add witness values

  cout << "Prover" << endl;
  
  pb.val(a) = FieldT::random_element();
  pb.val(b) = FieldT::random_element();
  cout << "Computing " << pb.val(a) << "*G + " << pb.val(b) << "*H" << endl;

  ped.generate_r1cs_witness();

  const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
//  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  ofstream pkfile("pk_pedersen");
  pkfile << keypair.pk;
  pkfile.close();
  ofstream vkfile("vk_pedersen");
  vkfile << keypair.vk;
  vkfile.close();
  ofstream pffile("proof_pedersen");
  pffile << proof;
  pffile.close();

  cout << pb.val(a) << "*G" << " + " << pb.val(b) << "*H = (" << pb.val(outx) << ", " << pb.val(outy) << ")" << endl;

  return 0;
}
