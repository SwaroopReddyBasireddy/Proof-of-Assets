#include <stdlib.h>
#include <iostream>
#include <fstream>

#include "equality_gadget.hpp"
//#include "ecgadget.hpp"
#include "test_equality.hpp"

using namespace libsnark;
using namespace std;

int main()
{
  // Initialize the curve parameters

  default_r1cs_gg_ppzksnark_pp::init_public_params();
  //init_curveparams();

  typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;

  protoboard<FieldT> pb;
  //pb_linear_combination<FieldT> s, s1, s2;
  //pb_linear_combination<FieldT> s;
  pb_variable<FieldT> Ax, Ay, Bx, By, sx, sy, s;
  
  s.allocate(pb, "s");
  sx.allocate(pb, "sx");
  sy.allocate(pb, "sy");
  Ax.allocate(pb, "Ax");
  Ay.allocate(pb, "Ay");
  Bx.allocate(pb, "Bx");
  By.allocate(pb, "By");
  

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(1);

  // Initialize the gadget
  equality_if_gadget<FieldT> eq(pb, Ax, Ay, Bx, By, s);
  
  eq.generate_r1cs_constraints();
  
  
  // Add witness values

  cout << "Prover" << endl;
  
  //pb.val(A) = FieldT::random_element();
  //pb.val(B) = pb.val(A);
  
  pb.val(Ax) = FieldT::random_element();
  pb.val(Bx) = pb.val(Ax);

  pb.val(Ay) = FieldT::random_element();
  pb.val(By) = pb.val(Ay);
  
  eq.generate_r1cs_witness();
  //pb.val(s) = FieldT(1);
  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
//cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
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

  cout << "A = (" << pb.val(Ax) << "," << pb.val(Ay) << ")" << endl;
  cout << "B = (" << pb.val(Bx) << "," << pb.val(By) << ")" << endl;

  cout << "s" << " = " << pb.lc_val(s) <<  endl;
 // cout << "sx" << " = " << pb.val(sx) <<  endl;
 // cout << "sy" << " = " << pb.val(sy) <<  endl;
    
  return 0;
  
}


