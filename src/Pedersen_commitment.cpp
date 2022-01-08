#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cmath>

#include "scalarmul_gadget.hpp"
//#include "pedersen.hpp"
//#include "POA.hpp"

using namespace libsnark;
using namespace std;
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

FieldT sum_a = FieldT::zero(), sum_b = FieldT::zero();
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
  pb_variable<FieldT> outx, outy, out_ax, out_ay, out_bx, out_by;
  pb_variable<FieldT> a, b;
  
  // The constant generator point G
  const FieldT Gx = FieldT("5815917273889497730302496188807371373931401217344778703222070189309225559577");
  const FieldT Gy = FieldT("8189405264277610384947948517788098541413756263235745909034225530367784524500");
  
  // The constant generator point G
 // const FieldT Gx = FieldT(0);
 // const FieldT Gy = FieldT("11977228949870389393715360594190192321220966033310912010610740966317727761886");

  //const FieldT Hx = FieldT("110263267274902958436328867164224792406782446797825613715583521163553034287998");
  //const FieldT Hy = FieldT("97481362542956814441892532371059707785205253773827785916951659669046127408432");
  
  // The constant generator point H
  const FieldT Hx = FieldT(1);
  const FieldT Hy = FieldT("21803877843449984883423225223478944275188924769286999517937427649571474907279");

  // Allocate variables

  outx.allocate(pb, "outx");
  outy.allocate(pb, "outy");
  out_ax.allocate(pb, "out_ax");
  out_ay.allocate(pb, "out_ay");
  out_bx.allocate(pb, "out_bx");
  out_by.allocate(pb, "out_by");
  a.allocate(pb, "a");
  b.allocate(pb, "b");

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(2);

  // Initialize the gadget
 ec_constant_scalarmul_gadget<FieldT> sm1(pb, out_ax, out_ay, a, 100, Gx, Gy);
 ec_constant_scalarmul_gadget<FieldT> sm2(pb, out_bx, out_by, b, 300, Hx, Hy);
 ec_add_gadget<FieldT> adder(pb, outx, outy, out_ax, out_ay, out_bx, out_by);
 
 sm1.generate_r1cs_constraints();
 sm2.generate_r1cs_constraints();
 adder.generate_r1cs_constraints();
 
 //ec_pedersen_gadget<FieldT> ped(pb, outx, outy, a, b, Gx, Gy, Hx, Hy);
 //ped.generate_r1cs_constraints();
  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  // Add witness values

  cout << "Prover" << endl;
  
  for(int i = 0; i < 10; i++){
	  sum_a += rand() % int(pow(2,51));
	  sum_b += FieldT::random_element();
  }
	  
  pb.val(a) = sum_a;
  pb.val(b) = sum_b;
  cout << "Computing " << pb.val(a) << "*G + " << pb.val(b) << "*H" << endl;

  //ped.generate_r1cs_witness();
  sm1.generate_r1cs_witness();
  sm2.generate_r1cs_witness();
  adder.generate_r1cs_witness();
  
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

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
