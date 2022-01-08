//#include <stdlib.h>
//#include <iostream>
//#include <fstream>


#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp"
#include "libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp"
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"



using namespace libsnark;
using namespace std;
template<typename FieldT>

class lastbits_gadget : public gadget<FieldT> {
public:
    pb_variable<FieldT> X;
    size_t X_bits;
    pb_variable<FieldT> result;
    pb_linear_combination_array<FieldT> result_bits;

    pb_linear_combination_array<FieldT> full_bits;
    std::shared_ptr<packing_gadget<FieldT> > unpack_bits;
    std::shared_ptr<packing_gadget<FieldT> > pack_result;

    lastbits_gadget(protoboard<FieldT> &pb,
                    const pb_variable<FieldT> &X,
                    const size_t X_bits,
                    const pb_variable<FieldT> &result,
                    const pb_linear_combination_array<FieldT> &result_bits,
                    const std::string &annotation_prefix):
            gadget<FieldT>(pb, annotation_prefix),
			X(X),
			X_bits(X_bits),
			result(result),
			result_bits(result_bits)
		{
			full_bits = result_bits;
			for (size_t i = result_bits.size(); i < X_bits; ++i)
				{
					pb_variable<FieldT> full_bits_overflow;
					full_bits_overflow.allocate(pb, FMT(this->annotation_prefix, " full_bits_%zu", i));
					full_bits.emplace_back(full_bits_overflow);
				}

			unpack_bits.reset(new packing_gadget<FieldT>(pb, full_bits, X, FMT(this->annotation_prefix, " unpack_bits")));
			pack_result.reset(new packing_gadget<FieldT>(pb, result_bits, result, FMT(this->annotation_prefix, " pack_result")));
		}


    void generate_r1cs_constraints()
    {
		unpack_bits->generate_r1cs_constraints(true);
		pack_result->generate_r1cs_constraints(false);
	}
    void generate_r1cs_witness()
    {
		unpack_bits->generate_r1cs_witness_from_packed();
		pack_result->generate_r1cs_witness_from_bits();
	}
};


template<typename FieldT>
class XOR3_gadget : public gadget<FieldT> {
private:
    pb_variable<FieldT> tmp;
public:
    pb_linear_combination<FieldT> A;
    pb_linear_combination<FieldT> B;
    pb_linear_combination<FieldT> C;
    bool assume_C_is_zero;
    pb_linear_combination<FieldT> out;

    XOR3_gadget(protoboard<FieldT> &pb,
                const pb_linear_combination<FieldT> &A,
                const pb_linear_combination<FieldT> &B,
                const pb_linear_combination<FieldT> &out):
          gadget<FieldT>(pb, "XOR3_gadget"),
          A(A), B(B), out(out)
          { }

    void generate_r1cs_constraints()
    {
		
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2*A, B, A + B - out), FMT(this->annotation_prefix, " out"));
	}
	
    void generate_r1cs_witness()
    {
		this->pb.lc_val(out) = this->pb.lc_val(A) + this->pb.lc_val(B) - FieldT(2) * this->pb.lc_val(A) * this->pb.lc_val(B);
	}
};

template<typename FieldT>
class equality_gadget : public gadget<FieldT>  {
private:
	pb_variable<FieldT> unreduced_new_A;
    std::shared_ptr<lastbits_gadget<FieldT> > mod_reduce_new_A;
    pb_variable<FieldT> packed_new_A;
    
    pb_variable<FieldT> unreduced_new_B;
    std::shared_ptr<lastbits_gadget<FieldT> > mod_reduce_new_B;
    pb_variable<FieldT> packed_new_B;
    
   // pb_linear_combination_array<FieldT> C_bits;


public:
	pb_variable<FieldT> A, B;
	pb_variable_array<FieldT> new_A, new_B;
	
	pb_variable<FieldT> C;
    pb_variable_array<FieldT> C_bits;
    std::vector<std::shared_ptr<XOR3_gadget<FieldT> > > compute_bits;
    std::shared_ptr<packing_gadget<FieldT> > pack_C;
    	
	equality_gadget(protoboard<FieldT> &pb,
					const pb_variable<FieldT> &A,
					const pb_variable<FieldT> &B,
					//const pb_linear_combination_array<FieldT> &new_A,
					//const pb_linear_combination_array<FieldT> &new_B,
					const pb_variable<FieldT> &C):
			gadget<FieldT>(pb, "equality_gadget"),
			A(A), B(B), C(C)
			{
				unreduced_new_A.allocate(pb, FMT(this->annotation_prefix, " unreduced_new_A"));
				unreduced_new_B.allocate(pb, FMT(this->annotation_prefix, " unreduced_new_B"));
				
				new_A.allocate(pb, 256, FMT(this->annotation_prefix, " new_A"));
				packed_new_A.allocate(pb, FMT(this->annotation_prefix, " packed_new_A"));
				
				new_B.allocate(pb, 256, FMT(this->annotation_prefix, " new_B"));
				packed_new_B.allocate(pb, FMT(this->annotation_prefix, " packed_new_B"));
			
				mod_reduce_new_A.reset(new lastbits_gadget<FieldT>(pb, unreduced_new_A, 256+3, packed_new_A, new_A, FMT(this->annotation_prefix, " mod_reduce_new_A")));
				mod_reduce_new_B.reset(new lastbits_gadget<FieldT>(pb, unreduced_new_B, 256+3, packed_new_B, new_B, FMT(this->annotation_prefix, " mod_reduce_new_B")));
			
			
				C_bits.allocate(pb, 256, FMT(this->annotation_prefix, " C_bits"));
				
				compute_bits.resize(256);
				for (size_t i = 0; i < 256; ++i)
					{
						compute_bits[i].reset(new XOR3_gadget<FieldT>(pb, new_A[i], new_B[i], C_bits[i]));
					}

				pack_C.reset(new packing_gadget<FieldT>(pb, C_bits, C, FMT(this->annotation_prefix, " pack_C")));
			}
			
		void generate_r1cs_constraints()
		{
			this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, A, unreduced_new_A), FMT(this->annotation_prefix, " unreduced_new_A"));
			this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, unreduced_new_B), FMT(this->annotation_prefix, " unreduced_new_B"));
			mod_reduce_new_A->generate_r1cs_constraints();
			mod_reduce_new_B->generate_r1cs_constraints();
			
			for (size_t i = 0; i < 256; ++i)
				{
					compute_bits[i]->generate_r1cs_constraints();
				  }

				pack_C->generate_r1cs_constraints(false);
		}
		
		void generate_r1cs_witness()
		{
			this->pb.val(unreduced_new_A) = this->pb.lc_val(A);
			this->pb.val(unreduced_new_B) = this->pb.lc_val(B);
			mod_reduce_new_A->generate_r1cs_witness();
			mod_reduce_new_B->generate_r1cs_witness();
			
			for (size_t i = 0; i < 256; ++i)
				{
					compute_bits[i]->generate_r1cs_witness();
				}

				pack_C->generate_r1cs_witness_from_bits();
		}
};


#define equality(A, B) (A == B ? 1 : 0)

template<typename FieldT>
class equality_if_gadget : public gadget<FieldT>  {
private:
	pb_variable<FieldT> sx, sy;
	
public:
	pb_variable<FieldT> Ax, Ay, Bx, By;
	pb_variable<FieldT> s;
		
	equality_if_gadget(protoboard<FieldT> &pb,
					const pb_variable<FieldT> &Ax,
					const pb_variable<FieldT> &Ay,
					const pb_variable<FieldT> &Bx,
					const pb_variable<FieldT> &By,
					//const pb_variable<FieldT> &sx,
					//const pb_variable<FieldT> &sy,
					const pb_variable<FieldT> &s):
			gadget<FieldT>(pb, "equality_gadget"),
			Ax(Ax), Ay(Ay), Bx(Bx), By(By), s(s)
			{
				//if (Ax == Bx)
					//sx.assign(pb, FieldT(1));
				//else
					//sx.assign(pb, 0);
				//if(Ay == By)
					//sy.assign(pb, 1);
				//else
					//sy.assign(pb,0);
				sx.allocate(pb, FMT(this->annotation_prefix, " sx"));
				sy.allocate(pb, FMT(this->annotation_prefix, " sy"));
			}

	void generate_r1cs_constraints()
		{
			
			//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, equality(Ax, Bx) , sx), FMT(this->annotation_prefix, " sx"));
			//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, equality(Ay, By) , sy), FMT(this->annotation_prefix, " sy"));
			this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sx, sy , s), FMT(this->annotation_prefix, " s"));
		}
		
	void generate_r1cs_witness()
		{
			//if(Ax == Bx)
				//this->pb.lc_val(sx) = FieldT::one();
				////sx.evaluate(this->pb);
			//else
				//this->pb.lc_val(sx) = 0;
				////sx.evaluate(this->pb);
					
			//if(Ay == By)
				//this->pb.lc_val(sy) = FieldT::one();
				////sy.evaluate(this->pb);
			//else
				//this->pb.lc_val(sy) = 0;
				////sy.evaluate(this->pb);
				
			this->pb.val(sx) = (this->pb.val(Ax) == this->pb.val(Bx) ? FieldT::one() : FieldT::zero());
			this->pb.val(sy) = (this->pb.val(Ay) == this->pb.val(By) ? FieldT::one() : FieldT::zero());
				
			this->pb.val(s) = this->pb.val(sx) * this->pb.val(sy); 
			
			//cout << this->sx << "," << this->sy << endl;
		}
};


