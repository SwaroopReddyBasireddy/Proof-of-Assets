#include <stdlib.h>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libff/algebra/fields/field_utils.hpp>
//#include <libff/common/default_types/ec_pp.hpp>
//#include <libff/common/profiling.hpp>
//#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <util.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

using namespace libsnark;

template<typename FieldT>
void test_two_to_one()
{
    protoboard<FieldT> pb;

	
	digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    
	pb.set_input_sizes(1);
	
    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();
    //printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());
	//printf("Primary (public) input: %zu\n",pb.primary_input());
    const libff::bit_vector left_bv  = libff::int_list_to_bits({0x8414d7c5, 0xf49bcff8, 0x90476fb7, 0x4b803047, 0xa925329e, 0xdeb533f1, 0xe2f468a1, 0x2f071f85}, 32);
  const libff::bit_vector right_bv = libff::int_list_to_bits({0xaafc00cc, 0x6120a67c, 0xe5487a71, 0xfaa3292e, 0x3f959a37, 0xe39368aa, 0x7ba2c52e, 0x5f605e94}, 32);
  const libff::bit_vector hash_bv  = libff::int_list_to_bits({0x0f8db247, 0x19d5912c, 0x50f1c605, 0x968df3a4, 0xd65b9a94, 0xe8bdb5c2, 0xecab9a32, 0x273a2cfc}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);

    //assert(pb.is_satisfied());
    
    //if (hash_bv.get_digest() != hash_bv) {
    //cout << "Hash does not match expected value." << endl;
    //return 1;
 // }
    
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Verification status: " << verified << endl;
    //cout << hash_bv << endl;
}

int main(void)
{
    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
    test_two_to_one<libff::Fr<libff::default_ec_pp> >();
}
