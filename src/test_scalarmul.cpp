#include <stdlib.h>
#include <iostream>

#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp"
#include "libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp"
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

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
  pb_variable<FieldT> outx, outy;
  pb_variable<FieldT> s;
  
  s.allocate(pb, " s");
  
  pb.set_input_sizes(1);
  
  pb.val(s) = FieldT::random_element();
  cout << "Computing " << pb.val(s) << "*G" << endl;
  
  size_t numbits = FieldT::num_bits;
  cout << "number of bits:" << numbits << endl;
  return 0;
  
}
