#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cmath>
#include <ctime>
#include <chrono>
//#include <random>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
//#include <gmp.h>
#include <boost/multiprecision/gmp.hpp>
//#include <boost/multiprecision/random.hpp>

using namespace boost::multiprecision;
using namespace boost::random;
using namespace std;

#include "ecgadget.hpp"
#include "scalarmul.hpp"

//using namespace libsnark;
using namespace std;

//namespace mp = boost::multiprecision;
//using namespace boost::random;

//uint256_t rand_gen(){
	//typedef std::independent_bits_engine<mt19937, 256, std::uint64_t> generator_type;
    //unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    ////srand(time(0));
    //generator_type gen;
    //return gen();
    
    //mt19937 mt;
    //uniform_int_distribution<cpp_int> ui(0, cpp_int(1) << 256);
//}


int main()
{    
  //typedef std::independent_bits_engine<std::mt19937,64, uint64_t> generator_type;

  //unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
  //generator_type g1(seed), g2, g3, g4;
  
  
  //typedef independent_bits_engine<mt19937, 256, uint256_t> generator_type;
  //generator_type g;
  
  //int256 x = randomNumberGenerator();
  //cout << x;
  
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
  pb_variable<FieldT> s;

  // The constant base point P
  //const FieldT Px = curveParams<FieldT>::Gx;
  //const FieldT Py = curveParams<FieldT>::Gy;

  // Allocate variables

  outx.allocate(pb, "outx");
  outy.allocate(pb, "outy");
  s.allocate(pb, "s");

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(2);

  // Initialize the gadget
  scalarmul_gadget<FieldT> sm(pb, outx, outy, s, 256);
  sm.generate_r1cs_constraints();

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  // Add witness values

  cout << "Prover" << endl;
  
  //srand(time(0));
  //pb.val(s) = 0;
  //for(int i = 0; i < 10; i++){
      //pb.val(s) += FieldT::random_element();
      //cout << pb.val(s) << " " << sizeof(pb.val(s)) << "\n" ;
  //}
  pb.val(s) = FieldT::random_element();
 
  sm.generate_r1cs_witness();

  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
	
  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
//  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;
  cout << "Computing " << pb.val(s) << "*G" << endl;

  //pb.val(s) += FieldT::random_element();
  
  ofstream pkfile("pk_scalarmul");
  pkfile << keypair.pk;
  pkfile.close();
  ofstream vkfile("vk_scalarmul");
  vkfile << keypair.vk;
  vkfile.close();
  ofstream pffile("proof_scalarmul");
  pffile << proof;
  pffile.close();

  cout << pb.val(s) << "*G" << " = (" << pb.val(outx) << ", " << pb.val(outy) << ")" << endl;
  //cout << "G" << " = (" << Px << ", " << Py << ")" << endl;
  //cout << FieldT::numbits;
  return 0;
}
