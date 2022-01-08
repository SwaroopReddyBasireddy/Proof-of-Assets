#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/ripemd160/ripemd160_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <util.hpp>

using namespace libsnark;
using namespace std;

int main()
{
  default_r1cs_ppzksnark_pp::init_public_params();
  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
  protoboard<FieldT> pb;
  vector<pb_linear_combination_array<FieldT> > a;
  vector<pb_linear_combination_array<FieldT> > b;
  vector<pb_linear_combination_array<FieldT> > c;
  vector<pb_linear_combination_array<FieldT> > d;
  vector<pb_linear_combination_array<FieldT> > e;
  pb_variable<FieldT> W, new_b, new_d;
  long KK;
  int s;
  
  new_b.allocate(pb, "new_b");
  new_d.allocate(pb, "new_d");
  W.allocate(pb, "W");
  pb_variable_array<FieldT> hash_packed;
 // hash_packed.allocate(pb, 2, "hash packed");
  
  pb_linear_combination_array<FieldT> x, y, prev_output;
  prev_output.reserve(RIPEMD160_digest_size);
 // y.reserve(SHA256_digest_size);
  prev_output = RIPEMD160_default_IV<FieldT>(pb);
 // y = SHA256_default_IV<FieldT>(pb);
 // cout << sizeof(x) << endl;
 // cout << sizeof(y) << endl;
    
  a.push_back(pb_linear_combination_array<FieldT>(prev_output.rbegin() + 4*32, prev_output.rbegin() + 5*32));
  b.push_back(pb_linear_combination_array<FieldT>(prev_output.rbegin() + 3*32, prev_output.rbegin() + 4*32));
  c.push_back(pb_linear_combination_array<FieldT>(prev_output.rbegin() + 2*32, prev_output.rbegin() + 3*32));
  d.push_back(pb_linear_combination_array<FieldT>(prev_output.rbegin() + 1*32, prev_output.rbegin() + 2*32));
  e.push_back(pb_linear_combination_array<FieldT>(prev_output.rbegin() + 0*32, prev_output.rbegin() + 1*32));
  
  cout << sizeof(prev_output) << endl;
  cout << sizeof(a) << endl;
 // for(int i=0; i < sizeof(a); i++){
 //   cout << pb.lc_val(a[i]) << endl;
   // cout << pb.lc_val(y[i]) << endl;
 // }

  //FF_gadget<FieldT> FF;
 //(pb, a, b, c, d, e, W, KK, s, new_b, new_d);
  //FF_gadget<FieldT> FF(pb, a, b, c, d, e, W, KK, s, new_b, new_d, "FF"));

  //FF.generate_r1cs_constraints();
  //pb.val(W) = 0x11111111;
  //KK = 0x00000000;
  //s = 10;
  //FF.generate_r1cs_witness();
  
  cout << pb.val(new_b) << endl;
  cout << pb.val(new_d) << endl;
  return 0;
}
