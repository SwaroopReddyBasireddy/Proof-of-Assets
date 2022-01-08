#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
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

  pb_variable_array<FieldT> hash_packed;
  hash_packed.allocate(pb, 2, "hash packed");

  

  digest_variable<FieldT> hash_bits(pb, SHA256_digest_size, "hash_bits");
  digest_variable<FieldT> left_bits(pb, SHA256_digest_size, "left_bits");
  digest_variable<FieldT> right_bits(pb, SHA256_digest_size, "right_bits");
  pb.set_input_sizes(3);

  multipacking_gadget<FieldT> packer(pb, hash_bits.bits, hash_packed, 128, "packer");
  packer.generate_r1cs_constraints(true);

  sha256_two_to_one_hash_gadget<FieldT> hasher(pb, left_bits, right_bits, hash_bits, "hash_gadget");
  hasher.generate_r1cs_constraints(true);

  const libff::bit_vector left_bv  = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
  const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);

  //const libff::bit_vector left_bv  = libff::int_list_to_bits({0x8414d7c5, 0xf49bcff8, 0x90476fb7, 0x4b803047, 0xa925329e, 0xdeb533f1, 0xe2f468a1, 0x2f071f85}, 32);
  //const libff::bit_vector right_bv = libff::int_list_to_bits({0xaafc00cc, 0x6120a67c, 0xe5487a71, 0xfaa3292e, 0x3f959a37, 0xe39368aa, 0x7ba2c52e, 0x5f605e94}, 32);
  const libff::bit_vector hash_bv  = libff::int_list_to_bits({0x0f8db247, 0x19d5912c, 0x50f1c605, 0x968df3a4, 0xd65b9a94, 0xe8bdb5c2, 0xecab9a32, 0x273a2cfc}, 32);

  left_bits.generate_r1cs_witness(left_bv);
  right_bits.generate_r1cs_witness(right_bv);
 
  hasher.generate_r1cs_witness();
 // hash_bits.generate_r1cs_witness(hash_bv);
  
  packer.generate_r1cs_witness_from_bits();

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
  const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
  const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  if (hash_bits.get_digest() == hash_bv) {
    cout << "Hash does matches expected value." << endl;
   // return 1;
  }

 // cout << hash_bits.get_digest() << endl;
  cout << "\n" << sizeof(proof) << endl;
  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  //cout << "Auxilary (private) input" << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;
  //cout << hash_bv << endl;
  //cout << sizeof(left_bits.bits) << endl;

  const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
  print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

  return 0;
}
