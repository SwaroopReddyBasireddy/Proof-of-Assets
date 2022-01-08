#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>

#include "equality_gadget.hpp"
#include "scalarmul_gadget.hpp"
#include "Proof_of_Assets.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono;

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
  pb_variable<FieldT> s, cmx, cmy;
  pb_variable<FieldT> x, Yx, Yy, PKx, PKy;
  pb_variable<FieldT> b, bal, t;
  pb_variable<FieldT> Ax, Ay, Bx, By;
  
  
  // The constant generator point G
  const FieldT Gx = FieldT("55066263022277343669578718895168534326250603453777594175500187360389116729240");
  const FieldT Gy = FieldT("32670510020758816978083085130507043184471273380659243275938904335757337482424");
  
  // The constant generator point H
 // const FieldT Hx = FieldT(0);
 // const FieldT Hy = FieldT("11977228949870389393715360594190192321220966033310912010610740966317727761886");

  const FieldT Hx = FieldT("110263267274902958436328867164224792406782446797825613715583521163553034287998");
  const FieldT Hy = FieldT("97481362542956814441892532371059707785205253773827785916951659669046127408432");
  
  cmx.allocate(pb, "cmx");
  cmy.allocate(pb, "cmy");
  s.allocate(pb, "s");
  PKx.allocate(pb, "PKx");
  PKy.allocate(pb, "PKy");
  x.allocate(pb, "x");
  Yx.allocate(pb, "Yx");
  Yy.allocate(pb, "Yy");
  //s1.allocate(pb, "s1");
  //s2.allocate(pb, "s2");
  b.allocate(pb, "b");
  bal.allocate(pb, "bal");
  t.allocate(pb, "t");
  Ax.allocate(pb, "Ax");
  Ay.allocate(pb, "Ay");
  Bx.allocate(pb, "Bx");
  By.allocate(pb, "By");
  
  
  pb.set_input_sizes(3);
  
  // Initialize the gadget for calculating public key from private key
  ec_constant_scalarmul_gadget<FieldT> sm(pb, PKx, PKy, x, 256, Gx, Gy);
  
  // Equality gadget
  equality_if_gadget<FieldT> eq(pb, PKx, PKy, Yx, Yy, s);
  //equality_gadget<FieldT> eq2(pb, PKy, Yy, s2);
  
  // Pedersen commitment
  ec_constant_scalarmul_gadget<FieldT> sm1(pb, Ax, Ay, b, 51, Gx, Gy);
  ec_constant_scalarmul_gadget<FieldT> sm2(pb, Bx, By, t, 256, Hx, Hy);
  ec_add_gadget<FieldT> adder(pb, cmx, cmy, Ax, Ay, Bx, By);

  
  sm.generate_r1cs_constraints();
  eq.generate_r1cs_constraints();
  //eq2.generate_r1cs_constraints();
  //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1-s1, 1-s2, s));
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(s, bal, b));
  sm1.generate_r1cs_constraints();
  sm2.generate_r1cs_constraints();
  adder.generate_r1cs_constraints();
  
  // Add witness values
  cout << "Prover" << endl;
  
  pb.val(x) = FieldT::random_element();
 // cout << "Computing " << pb.val(x) << "*G" << endl;
  
  sm.generate_r1cs_witness();
  
  pb.val(Yx) = pb.val(PKx);
  pb.val(Yy) = pb.val(PKy);

  eq.generate_r1cs_witness();
  //eq2.generate_r1cs_witness();
  //pb.val(s) = pb.val(s) = (FieldT(1) - pb.val(s1)) * (FieldT(1) - pb.val(s2));
  
  pb.val(bal) = FieldT::random_element();
  pb.val(t) = FieldT::random_element();
  
  pb.val(b) = pb.val(s) * pb.val(bal);
  sm1.generate_r1cs_witness();
  sm2.generate_r1cs_witness();
  adder.generate_r1cs_witness();
  
  //cout << pb.val(x) << "*G" << " = (" << pb.val(PKx) << ", " << pb.val(PKy) << ")" << endl;

  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  auto start = high_resolution_clock::now();
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  auto stop = high_resolution_clock::now();

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

  cout << pb.val(x) << "*G" << " = (" << pb.val(PKx) << ", " << pb.val(PKy) << ")" << endl;
 // cout << "s1" << " = " << pb.val(s1) <<  endl;
 // cout << "s2" << " = " << pb.val(s2) <<  endl;
  cout << "s" << " = " << pb.val(s) <<  endl;
  cout << "cm = (" << pb.val(cmx) << "," << pb.val(cmy) << ")" << endl;
  
  auto duration = duration_cast<microseconds>(stop - start);
  
  cout << "Time taken for proof construction: "
         << duration.count() << " microseconds" << endl;


  return 0;
}

