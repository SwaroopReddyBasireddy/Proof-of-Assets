#include <stdlib.h>
#include <fstream>

#include "ecc_gadget.hpp"
#include "scalarmul.hpp"
//#include "equality_gadget.hpp"
//#include <iostream>
//#include <vector>
//#include <cmath>
//#include <ctime>


using namespace libsnark;
using namespace std;

int main()
{
 // typedef libff::alt_bn128_pp ppT;
 // typedef libff::Fr<ppT> FieldT;

  // Initialize the curve parameters
  ppT::init_public_params();
  init_curveparams();
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;

  protoboard<FieldT> pb;
  pb_variable<FieldT> s, PKx, PKy, Yx, Yy, cmx, cmy;
  pb_variable<FieldT> b, bal, t;
  pb_variable<FieldT> x;

  // The constant base point P
  //const FieldT Px = curveParams<FieldT>::Gx;
  //const FieldT Py = curveParams<FieldT>::Gy;

  // Allocate variables

  cmx.allocate(pb, "cmx");
  cmy.allocate(pb, "cmy");
  s.allocate(pb, "s");
  PKx.allocate(pb, "PKx");
  PKy.allocate(pb, "PKy");
  Yx.allocate(pb, "Yx");
  Yy.allocate(pb, "Yy");
  x.allocate(pb, "x");
  bal.allocate(pb, "bal");
  t.allocate(pb, "t");
  b.allocate(pb, "b");

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(5);

  // Initialize the multiplication gadget
  scalarmul_gadget<FieldT> sm(pb, PKx, PKy, x, 256);
  
  // Equality gadget
  equality_if_gadget<FieldT> eq(pb, PKx, PKy, Yx, Yy, s);
  
  // pedersen commitment
  ec_pedersen_gadget<FieldT> ped(pb, cmx, cmy, b, t, 51, 256);
  
  sm.generate_r1cs_constraints();
  eq.generate_r1cs_constraints();
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(s, bal, b));
  ped.generate_r1cs_constraints();

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  // Add witness values

  cout << "Prover" << endl;
  
  pb.val(x) = FieldT::random_element();
  cout << "Computing " << pb.val(x) << "*G" << endl;

  sm.generate_r1cs_witness();
  
  pb.val(Yx) = pb.val(PKx);
  pb.val(Yy) = pb.val(PKy);
  eq.generate_r1cs_witness();
  
  pb.val(bal) = rand() % int(pow(2,51));
  pb.val(t) = FieldT::random_element();
  pb.val(b) = pb.val(s) * pb.val(bal);
  ped.generate_r1cs_witness();

  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
	
  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
//  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  ofstream pkfile("pk_scalarmul");
  pkfile << keypair.pk;
  pkfile.close();
  ofstream vkfile("vk_scalarmul");
  vkfile << keypair.vk;
  vkfile.close();
  ofstream pffile("proof_scalarmul");
  pffile << proof;
  pffile.close();

  cout << pb.val(x) << "*G" << " = (" << pb.val(PKx) << ", " << pb.val(PKy) << ")" << endl;
  //cout << "G" << " = (" << Px << ", " << Py << ")" << endl;

  return 0;
}
