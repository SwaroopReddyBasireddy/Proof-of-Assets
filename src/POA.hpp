#include "equality_gadget.hpp"
#include "scalarmul_gadget.hpp"
#include "Proof_of_Assets.hpp"
#include <iostream>
#include <vector>
#include <cmath>
#include <ctime>


using namespace libsnark;

typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

vector<vector<string>> keys;
FieldT sum_t = FieldT::zero(), sum_b = FieldT::zero(), sum_a = FieldT::zero();


template<typename FieldT>
class POA_gadget : public gadget<FieldT> {
public:
  pb_variable<FieldT>  PKx, PKy;     // Public key calculated from private key x
  pb_variable<FieldT> b;             // b = s * bal
  pb_variable<FieldT> Ax, Ay, Bx, By;  
  
public:
  pb_variable<FieldT> s, cmx, cmy;   // output s and pedersen commitment
  pb_variable<FieldT> x, Yx, Yy;     // Private and public keys
  pb_variable<FieldT> bal, t;        // balance and blinding factor
  const FieldT Gx, Gy, Hx, Hy;
  
  std::vector<ec_constant_scalarmul_gadget<FieldT> > compute_PK;
  std::vector<equality_if_gadget<FieldT> > compute_s;
  std::vector<ec_constant_scalarmul_gadget<FieldT> > sm1;
  std::vector<ec_constant_scalarmul_gadget<FieldT> > sm2;
  std::vector<ec_add_gadget<FieldT> > compute_cm;  
  //std::shared_ptr<ec_constant_scalarmul_gadget<FieldT> > compute_PK;  // Compute public key corresponding to private key x
  //std::shared_ptr<equality_if_gadget<FieldT> > compute_s;  // Compute public key corresponding to private key x
  
  //std::shared_ptr<ec_constant_scalarmul_gadget<FieldT> > sm1;
  //std::shared_ptr<ec_constant_scalarmul_gadget<FieldT> > sm2;
  
  //std::shared_ptr<ec_add_gadget<FieldT> > compute_cm;
  
  POA_gadget(protoboard<FieldT> &pb,
			 const FieldT Gx, const FieldT Gy,
			 const FieldT Hx, const FieldT Hy,
			 const pb_variable<FieldT> x,
			 const pb_variable<FieldT> s,
			 const pb_variable<FieldT> cmx,
			 const pb_variable<FieldT> cmy):
		gadget<FieldT>(pb, "POA_gadget"), Gx(Gx), Gy(Gy), Hx(Hx), Hy(Hy), x(x), s(s), cmx(cmx), cmy(cmy)
		{
			// Initialize the gadget for calculating public key from private key
			PKx.allocate(pb, "PKx");
			PKy.allocate(pb, "PKy");
			compute_PK.emplace_back(this->pb, PKx, PKy, x, 256, Gx, Gy);
			
			// Equality gadget
			Yx.allocate(pb, "Yx");
			Yy.allocate(pb, "Yy");
			compute_s.emplace_back(this->pb, PKx, PKy, Yx, Yy, s);
			
			// Pedersen commitment gadget
			bal.allocate(pb, "bal");
			t.allocate(pb, "t");
			b.allocate(pb, "b");
			Ax.allocate(pb, "Ax");
			Ay.allocate(pb, "Ay");
			Bx.allocate(pb, "Bx");
			By.allocate(pb, "By");
			sm1.emplace_back(this->pb, Ax, Ay, b, 51, Gx, Gy);
			sm2.emplace_back(this->pb, Bx, By, t, 256, Hx, Hy);	
			compute_cm.emplace_back(this->pb, cmx, cmy, Ax, Ay, Bx, By);
		}
		
  void generate_r1cs_constraints()
	{
		compute_PK[0].generate_r1cs_constraints();
		
		//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, PKx, Yx));
		//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, PKy, Yy));
		compute_s[0].generate_r1cs_constraints();
		
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(s, bal, b));
		sm1[0].generate_r1cs_constraints();
		sm2[0].generate_r1cs_constraints();
		compute_cm[0].generate_r1cs_constraints();
		
	}
  void generate_r1cs_witness()
	{
		//pb.val(x) = FieldT::random_element();
		compute_PK[0].generate_r1cs_witness();
		
		this->pb.val(Yx) = this->pb.val(PKx);
		this->pb.val(Yy) = this->pb.val(PKy);
		compute_s[0].generate_r1cs_witness();
		
		//this->pb.val(bal) = FieldT::random_element();
		this->pb.val(bal) = rand() % int(pow(2,51));
		//this->pb.val(t) = FieldT::random_element();
		this->pb.val(t) = rand() % int(pow(2,51));
		this->pb.val(b) = this->pb.val(s) * this->pb.val(bal);
		sum_b += this->pb.val(b);
		sum_t += this->pb.val(t);
		sm1[0].generate_r1cs_witness();
		sm2[0].generate_r1cs_witness();
		compute_cm[0].generate_r1cs_witness();
	}
};
			 
template<typename FieldT>
class Pedersen_gadget : public gadget<FieldT> {
public:
  pb_variable<FieldT> Ax, Ay, Bx, By;  
  
public:
  pb_variable<FieldT> Cx, Cy, t, b;   // output s and pedersen commitment
  const FieldT Gx, Gy, Hx, Hy;
  
  std::vector<ec_constant_scalarmul_gadget<FieldT> > sm1;
  std::vector<ec_constant_scalarmul_gadget<FieldT> > sm2;
  std::vector<ec_add_gadget<FieldT> > compute_C;
  
  Pedersen_gadget(protoboard<FieldT> &pb,
			 const FieldT Gx, const FieldT Gy,
			 const FieldT Hx, const FieldT Hy,
			 const pb_variable<FieldT> b,
			 const pb_variable<FieldT> t,
			 const pb_variable<FieldT> Cx,
			 const pb_variable<FieldT> Cy):
		gadget<FieldT>(pb, "POA_gadget"), Gx(Gx), Gy(Gy), Hx(Hx), Hy(Hy), b(b), t(t), Cx(Cx), Cy(Cy)
		{
			Ax.allocate(pb, "Ax");
			Ax.allocate(pb, "Ay");
			Ax.allocate(pb, "Bx");
			Ax.allocate(pb, "By");
			sm1.emplace_back(this->pb, Ax, Ay, b, 128, Gx, Gy);
			sm2.emplace_back(this->pb, Bx, By, t, 512, Hx, Hy);	
			compute_C.emplace_back(this->pb, Cx, Cy, Ax, Ay, Bx, By);
		}
		
	void generate_r1cs_constraints(){
		sm1[0].generate_r1cs_constraints();
		sm2[0].generate_r1cs_constraints();
		compute_C[0].generate_r1cs_constraints();
	}
	
	void generate_r1cs_witness() {
		this->pb.val(b) = FieldT(sum_b);
		this->pb.val(t) = FieldT(sum_t);
		sm1[0].generate_r1cs_witness();
		sm2[0].generate_r1cs_witness();
		compute_C[0].generate_r1cs_witness();
	}
};
		
		

