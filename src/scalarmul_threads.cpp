#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cmath>
#include <ctime>
#include <chrono>
#include <vector>
#include <thread>
#include <stdio.h>



#include "scalarmul_gadget.hpp"
//#include "ecgadget.hpp"
#include "scalarmul.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono;

typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

//template<typename FieldT>
static void proof_threading(r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> &proof, r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> &keypair, protoboard<FieldT> &pb) {
		proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
	}
	
int main()
{
  // Initialize the curve parameters

  default_r1cs_gg_ppzksnark_pp::init_public_params();
  //init_curveparams();

  
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;
  
  // The constant base point P
  const FieldT Px = FieldT("55066263022277343669578718895168534326250603453777594175500187360389116729240");
  const FieldT Py = FieldT("32670510020758816978083085130507043184471273380659243275938904335757337482424"); 
  
  //ofstream keyfile;
  //keyfile.open("inputfile.csv");
  //keyfile << "SK" << " " << "PKx" << " " << "PKy" << " " << "balance" << " " << "b_i" << "\n";
  
  double temp_constr_time = 0;
  vector<double> constr_time;

  int n = 10, m = 4;
  protoboard<FieldT> pb[n];
  pb_variable<FieldT> outx[n], outy[n];
  pb_variable<FieldT> s[n], b[n];
  vector<ec_constant_scalarmul_gadget<FieldT>> sm;
  
  vector<r1cs_constraint_system<FieldT> > constraint_system;
  vector<r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> > keypair;
  
  r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof[n];

  // Allocate variables

  for(size_t i = 0; i < n ; i++){ 
	outx[i].allocate(pb[i], " outx");
	outy[i].allocate(pb[i], " outy");
	s[i].allocate(pb[i], " s");
	b[i].allocate(pb[i], " b");

  //// This sets up the protoboard variables so that the first n of them
  //// represent the public input and the rest is private input

  pb[i].set_input_sizes(3);

  // Initialize the gadget
  sm.emplace_back(pb[i], outx[i], outy[i], s[i], 256, Px, Py);
  sm[i].generate_r1cs_constraints();

  //const r1cs_constraint_system<FieldT> constraint_system = pb[i].get_constraint_system();
  constraint_system.emplace_back(pb[i].get_constraint_system());

  //const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
  keypair.emplace_back(r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system[i]));

  // Add witness values

  cout << "keypair address " << &(keypair[i]) << endl;
  cout << "keypair size " << sizeof(keypair[i]) << endl;
  cout << "constraint system address " << &(constraint_system[i]) << endl;
  
  cout << "pb address " << &(pb[i]) << endl;
  cout << "Prover" << endl;
  
  cout << "sm address " << &(sm[i]) << endl;
  
  
  pb[i].val(s[i]) = FieldT::random_element();
  cout << "Computing " << &(pb[i].val(s[i])) << "*G" << endl;

  sm[i].generate_r1cs_witness();
  }

  thread t[n];
  //const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  //proof[i] = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair[i].pk, pb[i].primary_input(), pb[i].auxiliary_input());
  
  auto start = high_resolution_clock::now();
  int i = 0;
  //while(i < n) {
	//for(int j = i; j < i+4; j++)
	  //t[j] = thread(proof_threading, ref(proof[j]), ref(keypair[j]), ref(pb[j]));
	//for(int j=i; j < i+4; j++)
	  //t[j].join();
	//i = i+4;
	//}
 
  for(i = 0; i < n; i++)
		t[i] = thread(proof_threading, ref(proof[i]), ref(keypair[i]), ref(pb[i]));
  for(i = 0; i < n; i++){
		t[i].join();
		cout << "Thread number " << i << "\n";
	}
		//delete pb[i].auxiliary_input();
		
  //proof_threading(proof[i], keypair[i], pb[i]);
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  //constr_time.emplace_back(temp_constr_time + duration.count());
  cout << "Construction time for 5 scalar multiplications:" << duration.count() << "\n";
  //cout << "Verifier" << endl;

  //bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  //cout << "Number of R1CS constraints: " << constraint_system[n].num_constraints() << endl;
  //cout << "Primary (public) input: " << pb[n].primary_input() << endl;
  //cout << "Auxiliary (private) input length: " << pb[n].auxiliary_input().size() << endl;
 //cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  //cout << "Verification status: " << verified << endl;

  //ofstream pkfile("pk_scalarmul");
  //pkfile << keypair.pk;
  //pkfile.close();
  //ofstream vkfile("vk_scalarmul");
  //vkfile << keypair.vk;
  //vkfile.close();
  //ofstream pffile("proof_scalarmul");
  //pffile << proof;
  //pffile.close();

  //srand(time(0));
  //uint64_t bal = rand() % int(pow(2,51));
  //pb.val(b) = FieldT::random_element();
  //cout << pb.val(s) << "*G" << " = (" << pb.val(outx) << ", " << pb.val(outy) << ")" << endl;
  //keyfile << pb.val(s) << " " << pb.val(outx) << " " << pb.val(outy) << " " << bal << " " << pb.val(b) << "\n";
  
  //temp_constr_time = constr_time[i];
  
  //}	
  //for(size_t i = 0; i < n; i++)
		//cout << constr_time[i] << "\n";
  return 0;
}
