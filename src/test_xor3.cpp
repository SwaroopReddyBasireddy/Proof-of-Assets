#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/ripemd160/ripemd160_aux.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_aux.hpp>

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
    
    pb_variable<FieldT> out;
    pb_linear_combination_array<FieldT> A;
    pb_linear_combination_array<FieldT> B;
    pb_linear_combination_array<FieldT> C;
    
    pb.set_input_sizes(1);


    //XOR3_gadget<FieldT> X(pb, A, B, C, false, out, "X");
    
    f2_gadget<FieldT> X(pb, A, B, C, out, "X");
    //choice_gadget<FieldT> X(pb, A, B, C, out, "X");
    
    X.generate_r1cs_constraints();
    
    printf("Number of constraints for xor3_gadget: %zu\n", pb.num_constraints());
    
    X.generate_r1cs_witness();
    return 0;
}
