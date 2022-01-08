#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>


#include "POA.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono;




int main()
{
  // Initialize the curve parameters

  const uint32_t n = 10;
  default_r1cs_gg_ppzksnark_pp::init_public_params();
  //init_curveparams();

  typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;
  
  // The constant generator point G
  const FieldT Gx = FieldT("55066263022277343669578718895168534326250603453777594175500187360389116729240");
  const FieldT Gy = FieldT("32670510020758816978083085130507043184471273380659243275938904335757337482424");
  
  const FieldT Hx = FieldT("110263267274902958436328867164224792406782446797825613715583521163553034287998");
  const FieldT Hy = FieldT("97481362542956814441892532371059707785205253773827785916951659669046127408432");

  vector<double_t> constr_time;
  vector<double_t> ver_time;
  vector<size_t> proof_size;
  double temp_constr_time = 0.0;
  double temp_ver_time = 0.0;
  size_t temp_proof_size = 0;
  
  for(size_t i = 0; i < n; i++){

  protoboard<FieldT> pb;	
  pb_variable<FieldT> x, s, cmx, cmy;
  
  s.allocate(pb, "s");
  cmx.allocate(pb, "cmx");
  cmy.allocate(pb, "cmy");
  x.allocate(pb, "x");
  
  pb.set_input_sizes(3);
  
  // Initialize the gadget for calculating public key from private key
  POA_gadget<FieldT> POA(pb, Gx, Gy, Hx, Hy, x, s, cmx, cmy);
  
  POA.generate_r1cs_constraints();
  
  
  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  pb.val(x) = FieldT::random_element();
 // cout << "Computing " << pb.val(x) << "*G" << endl;
 POA.generate_r1cs_witness();
  

  auto start = high_resolution_clock::now();
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  constr_time.emplace_back(temp_constr_time + duration.count());

  proof_size.emplace_back(temp_proof_size + proof.size_in_bits());
  cout << "Verifier" << endl;

  auto start1 = high_resolution_clock::now();
  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
  auto stop1 = high_resolution_clock::now();
  auto duration1 = duration_cast<microseconds>(stop1 - start1);
  ver_time.emplace_back(temp_ver_time + duration1.count());

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
//cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  //ofstream pkfile("pk_scalarmul");
  //pkfile << keypair.pk;
  //pkfile.close();
  //ofstream vkfile("vk_scalarmul");
  //vkfile << keypair.vk;
  //vkfile.close();
  //ofstream pffile("proof_scalarmul");
  //pffile << proof;
  //pffile.close();

  cout << pb.val(x) << "*" << Gx <<  endl;
  //cout << "s1" << " = " << pb.val(s1) <<  endl;
  //cout << "s2" << " = " << pb.val(s2) <<  endl;
  cout << "s" << " = " << pb.val(s) <<  endl;
  cout << "cm = (" << pb.val(cmx) << "," << pb.val(cmy) << ")" << endl;
  
  
  cout << sizeof(proof) << endl;
  proof.print_size();
  cout << proof.size_in_bits() << endl;
  
  cout << "Time taken for proof construction: "
         << duration.count() << " microseconds" << endl;
         
  temp_constr_time = constr_time[i];
  temp_ver_time = ver_time[i];
  temp_proof_size = proof_size[i];     
 }

  for(size_t i = 0; i < n; i++){
		cout << constr_time[i]/1e6 << "," << proof_size[i]/1e6 << " , " << ver_time[i]/1e6 << "\n" << endl;
	}
  return 0;
}

