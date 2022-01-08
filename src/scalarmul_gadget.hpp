#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
//#include "libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp"
//#include "libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp"
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using namespace libsnark;

// There are two types of values:
//   _constants_ are values known at circuit generation time; they
//       are global constants known to everyone
//   _variables_ are values that change in each use of the circuit;
//       they have two subtypes:
//
//   _public variables_ are values known to both the prover
//       and verifier but change in each use of the circuit
//   _private variables_ are values known only to the prover
//       and change in each use of the circuit

// The elliptic curve we're operating on must have a _modulus_ that is
// the same as the _order_ of the underlying SNARK curve (BN128, MNT4,
// etc.).  So we need to be able to specify a suitable curve and
// generators for each such underlying SNARK curve.
//template<typename FieldT>
//struct curveParams {
    //// Some generators
    //static FieldT Gx, Gy, Hx, Hy, Cx = 0, Cy = 0, Ax = 0, Ay = 0;
//};

// Double a constant EC point (inx,iny) to yield (outx,outy).  The input
// point must not be the point at infinity.
template<typename FieldT>
static void ec_double_point(FieldT &outx, FieldT &outy,
    const FieldT &inx, const FieldT &iny)
{
    FieldT xsq = inx.squared();
    FieldT lambda = (xsq * 3) * (iny * 2).inverse();
    outx = lambda.squared() - inx * 2;
    outy = lambda * (inx - outx) - iny;
}

// Add constant EC points (inx, iny) and (addx, addy) to yield (outx, outy).
// inx and addx must not be equal.
template<typename FieldT>
static void ec_add_points(FieldT &outx, FieldT &outy,
    const FieldT &inx, const FieldT &iny,
    const FieldT &addx, const FieldT &addy)
{
    FieldT lambda = (addy - iny) * (addx - inx).inverse();
    outx = lambda.squared() - (addx + inx);
    outy = lambda * (inx - outx) - iny;
}

// Double the variable EC point (inx,iny) to yield (outx,outy).  The
// input point must not be the point at infinity.
template<typename FieldT>
class ec_double_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> lambda, inxsq;
public:
  const pb_variable<FieldT> outx, outy, inx, iny;

  ec_double_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny) :
    gadget<FieldT>(pb, "ec_double_gadget"), outx(outx), outy(outy),
        inx(inx), iny(iny)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    lambda.allocate(this->pb, "lambda");
    inxsq.allocate(this->pb, "inxsq");
  }

  void generate_r1cs_constraints()
  {
    // inxsq = inx * inx
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(inx, inx, inxsq));

    // 2 * iny * lambda = 3 * inxsq - 3  (a = -3 on our curve)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * iny, lambda, 3 * inxsq));

    // outx = lambda^2 - 2 * inx
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, lambda, outx + 2 * inx));

    // outy = lambda * (inx - outx) - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, inx - outx, outy + iny));

  }

  void generate_r1cs_witness()
  {
    this->pb.val(inxsq) = this->pb.lc_val(inx) * this->pb.lc_val(inx);
    this->pb.val(lambda) = (this->pb.val(inxsq) * 3) * (this->pb.lc_val(iny) * 2).inverse();
    this->pb.val(outx) = this->pb.val(lambda).squared() - this->pb.lc_val(inx) * 2;
    this->pb.val(outy) = this->pb.val(lambda) * (this->pb.lc_val(inx) - this->pb.val(outx)) - this->pb.lc_val(iny);
  }
};

// Add the variable EC point (addx,addy) to the variable EC point
// (inx,iny) to yield (outx,outy).  The input point must not be the
// point at infinity.
template<typename FieldT>
class ec_add_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> lambda;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny, addx, addy;

  ec_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const pb_linear_combination<FieldT> &addx,
              const pb_linear_combination<FieldT> &addy) :
    gadget<FieldT>(pb, "ec_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), addx(addx), addy(addy)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    lambda.allocate(this->pb, "lambda");
  }

  void generate_r1cs_constraints()
  {
    // (addx - inx) * lambda = addy - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(addx - inx, lambda, addy - iny));

    // outx = lambda^2 - (addx + inx)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, lambda, outx + addx + inx));

    // outy = lambda * (inx - outx) - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, inx - outx, outy + iny));

  }

  void generate_r1cs_witness()
  {
    this->pb.val(lambda) = (this->pb.lc_val(addy) - this->pb.lc_val(iny)) * (this->pb.lc_val(addx) - this->pb.lc_val(inx)).inverse();
    this->pb.val(outx) = this->pb.val(lambda).squared() - (this->pb.lc_val(addx) + this->pb.lc_val(inx));
    this->pb.val(outy) = this->pb.val(lambda) * (this->pb.lc_val(inx) - this->pb.val(outx)) - this->pb.lc_val(iny);
  }
};


// Add the variable EC point (addx,addy) to the variable EC point
// (inx,iny) to yield (outx,outy).  The input point must not be the
// point at infinity.
template<typename FieldT>
class ec_add_variable_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> lambda;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> inx, iny, addx, addy;

  ec_add_variable_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &inx,
              const pb_variable<FieldT> &iny,
              const pb_variable<FieldT> &addx,
              const pb_variable<FieldT> &addy) :
    gadget<FieldT>(pb, "ec_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), addx(addx), addy(addy)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    lambda.allocate(this->pb, "lambda");
  }

  void generate_r1cs_constraints()
  {
    // (addx - inx) * lambda = addy - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(addx - inx, lambda, addy - iny));

    // outx = lambda^2 - (addx + inx)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, lambda, outx + addx + inx));

    // outy = lambda * (inx - outx) - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, inx - outx, outy + iny));

  }

  void generate_r1cs_witness()
  {
    this->pb.val(lambda) = (this->pb.lc_val(addy) - this->pb.lc_val(iny)) * (this->pb.lc_val(addx) - this->pb.lc_val(inx)).inverse();
    this->pb.val(outx) = this->pb.val(lambda).squared() - (this->pb.lc_val(addx) + this->pb.lc_val(inx));
    this->pb.val(outy) = this->pb.val(lambda) * (this->pb.lc_val(inx) - this->pb.val(outx)) - this->pb.lc_val(iny);
  }
};

// Add the variable EC point P to the constant EC point (inx,iny) to
// yield (outx,outy).  The input point must not be the point at
// infinity.
template<typename FieldT>
class ec_constant_add_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> lambda;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny;
  const FieldT Px, Py;

  ec_constant_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const FieldT &Px, const FieldT &Py) :
    gadget<FieldT>(pb, "ec_constant_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), Px(Px), Py(Py)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    lambda.allocate(this->pb, "lambda");
  }

  void generate_r1cs_constraints()
  {
    // (Px - inx) * lambda = Py - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(Px - inx, lambda, Py - iny));

    // outx = lambda^2 - (Px + inx)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, lambda, outx + Px + inx));

    // outy = lambda * (inx - outx) - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, inx - outx, outy + iny));

  }

  void generate_r1cs_witness()
  {
    this->pb.val(lambda) = (Py - this->pb.lc_val(iny)) * (Px - this->pb.lc_val(inx)).inverse();
    this->pb.val(outx) = this->pb.val(lambda).squared() - (Px + this->pb.lc_val(inx));
    this->pb.val(outy) = this->pb.val(lambda) * (this->pb.lc_val(inx) - this->pb.val(outx)) - this->pb.lc_val(iny);
  }
};

// Add the constant EC point P0 or the constant EC point P1 to the
// variable EC point (inx,iny) to yield (outx,outy).  The input point
// must not be the point at infinity.  The input bit choice controls
// which addition is done.
template<typename FieldT>
class ec_2_constant_add_gadget : public gadget<FieldT> {
private:
  pb_linear_combination<FieldT> addx, addy;
  std::vector<ec_add_gadget<FieldT> > adder;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny;
  const pb_variable<FieldT> choice;
  const FieldT P0x, P0y, P1x, P1y;

  ec_2_constant_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const pb_variable<FieldT> &choice,
              const FieldT &P0x, const FieldT &P0y,
              const FieldT &P1x, const FieldT &P1y) :
    gadget<FieldT>(pb, "ec_2_constant_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), choice(choice),
    P0x(P0x), P0y(P0y), P1x(P1x), P1y(P1y)
  {
    // Allocate variables to protoboard

    addx.assign(pb, choice * (P1x-P0x) + P0x);
    addy.assign(pb, choice * (P1y-P0y) + P0y);
    adder.emplace_back(this->pb, outx, outy, inx, iny, addx, addy);
  }

  void generate_r1cs_constraints()
  {
    adder[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    addx.evaluate(this->pb);
    addy.evaluate(this->pb);
    adder[0].generate_r1cs_witness();
  }
};

// Add the constant EC point P0 or the variable EC point P1 to the
// variable EC point (inx,iny) to yield (outx,outy).  The input point
// must not be the point at infinity.  The input bit choice controls
// which addition is done.
template<typename FieldT>
class ec_2_1constant_add_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> addx, addy;
  std::vector<ec_add_gadget<FieldT> > adder;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny;
  const pb_variable<FieldT> choice;
  const FieldT P0x, P0y;
  const pb_variable<FieldT> P1x, P1y;

  ec_2_1constant_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const pb_variable<FieldT> &choice,
              const FieldT &P0x,
              const FieldT &P0y,
              const pb_variable<FieldT> &P1x,
              const pb_variable<FieldT> &P1y) :
    gadget<FieldT>(pb, "ec_2_1constant_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), choice(choice),
    P0x(P0x), P0y(P0y), P1x(P1x), P1y(P1y)
  {
    // Allocate variables to protoboard

    addx.allocate(this->pb, "addx");
    addy.allocate(this->pb, "addy");
    adder.emplace_back(this->pb, outx, outy, inx, iny, addx, addy);
  }

  void generate_r1cs_constraints()
  {
    // Set (addx,addy) = choice ? (P0x, P0y) : (P1x, P1y)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(P1x - P0x, choice, addx - P0x));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(P1y - P0y, choice, addy - P0y));
    adder[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    bool choiceb = this->pb.val(choice) != FieldT(0);
    this->pb.val(addx) = choiceb ? this->pb.val(P1x) : P0x;
    this->pb.val(addy) = choiceb ? this->pb.val(P1y) : P0y;
    adder[0].generate_r1cs_witness();
  }
};

// Add the variable EC point P0 or the variable EC point P1 to the
// variable EC point (inx,iny) to yield (outx,outy).  The input point
// must not be the point at infinity.  The input bit choice controls
// which addition is done.
template<typename FieldT>
class ec_2_add_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> addx, addy;
  std::vector<ec_add_gadget<FieldT> > adder;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny;
  const pb_variable<FieldT> choice;
  const pb_variable<FieldT> P0x, P0y, P1x, P1y;

  ec_2_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const pb_variable<FieldT> &choice,
              const pb_variable<FieldT> &P0x,
              const pb_variable<FieldT> &P0y,
              const pb_variable<FieldT> &P1x,
              const pb_variable<FieldT> &P1y) :
    gadget<FieldT>(pb, "ec_2_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny), choice(choice),
    P0x(P0x), P0y(P0y), P1x(P1x), P1y(P1y)
  {
    // Allocate variables to protoboard

    addx.allocate(this->pb, "addx");
    addy.allocate(this->pb, "addy");
    adder.emplace_back(this->pb, outx, outy, inx, iny, addx, addy);
  }

  void generate_r1cs_constraints()
  {
    // Set (addx,addy) = choice ? (P0x, P0y) : (P1x, P1y)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(P1x - P0x, choice, addx - P0x));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(P1y - P0y, choice, addy - P0y));
    adder[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    bool choiceb = this->pb.val(choice) != FieldT(0);
    this->pb.val(addx) = choiceb ? this->pb.val(P1x) : this->pb.val(P0x);
    this->pb.val(addy) = choiceb ? this->pb.val(P1y) : this->pb.val(P0y);
    adder[0].generate_r1cs_witness();
  }
};

// Add one of the four constant EC points to the variable EC point
// (inx,iny) to yield (outx,outy).  The input point must not be the
// point at infinity.  The input bits choice0 and choice1 control which
// addition is done (P{2*choice1+choice0} is added).
template<typename FieldT>
class ec_4_constant_add_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> both;
  pb_linear_combination<FieldT> addx, addy;
  std::vector<ec_add_gadget<FieldT> > adder;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_linear_combination<FieldT> inx, iny;
  const pb_variable<FieldT> choice0, choice1;
  const FieldT P0x, P0y, P1x, P1y, P2x, P2y, P3x, P3y;

  ec_4_constant_add_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_linear_combination<FieldT> &inx,
              const pb_linear_combination<FieldT> &iny,
              const pb_variable<FieldT> &choice0,
              const pb_variable<FieldT> &choice1,
              const FieldT &P0x, const FieldT &P0y,
              const FieldT &P1x, const FieldT &P1y,
              const FieldT &P2x, const FieldT &P2y,
              const FieldT &P3x, const FieldT &P3y) :
    gadget<FieldT>(pb, "ec_4_constant_add_gadget"),
    outx(outx), outy(outy), inx(inx), iny(iny),
    choice0(choice0), choice1(choice1),
    P0x(P0x), P0y(P0y), P1x(P1x), P1y(P1y),
    P2x(P2x), P2y(P2y), P3x(P3x), P3y(P3y)
  {
    // Allocate variables to protoboard

    both.allocate(this->pb, "both");
    addx.assign(this->pb, both * (P3x - P2x - P1x + P0x) + choice1 * (P2x - P0x) + choice0 * (P1x - P0x) + P0x);
    addy.assign(this->pb, both * (P3y - P2y - P1y + P0y) + choice1 * (P2y - P0y) + choice0 * (P1y - P0y) + P0y);
    adder.emplace_back(this->pb, outx, outy, inx, iny, addx, addy);
  }

  void generate_r1cs_constraints()
  {
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(choice0, choice1, both));
    adder[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    bool c0 = this->pb.val(choice0) != FieldT(0);
    bool c1 = this->pb.val(choice1) != FieldT(0);
    this->pb.val(both) = c0 && c1;
    addx.evaluate(this->pb);
    addy.evaluate(this->pb);
    adder[0].generate_r1cs_witness();
  }
};


// Compute s*P as (outx, outy) for an accumulator A, a given
// constant point P, and s given as a bit vector.  The _caller_ is
// responsible for proving that the elements of svec are bits.  The
// (constant) accumulator excess (AXS) will be updated; when all the
// computations are complete, AXS should be subtracted from the
// accumulator A.
template<typename FieldT>
class ec_constant_scalarmul_vec_accum_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> accumx, accumy;
 // std::vector<ec_4_constant_add_gadget<FieldT> > fouradders;
  std::vector<ec_2_constant_add_gadget<FieldT> > twoadders;
 // std::vector<ec_constant_add_gadget<FieldT> > adders;
public:
  const pb_variable<FieldT> outx, outy;
 // const pb_variable<FieldT> Ax, Ay;
  const pb_variable_array<FieldT> svec;
  const FieldT Px, Py;
  
  // Strategy: We compute (as compile-time constants) (powers of 2)
  // times P.  Based on each bit of s, we add one of the constant points
  // 0 or (2^i * P) to the accumulator, and regardless of s, add C
  // to the excess.

  ec_constant_scalarmul_vec_accum_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
            //  const pb_variable<FieldT> &Ax,
            //  const pb_variable<FieldT> &Ay,
              const pb_variable_array<FieldT> &svec,
              const FieldT &Px, const FieldT &Py) :
    gadget<FieldT>(pb, "ec_constant_scalarmul_vec_accum_gadget"),
    outx(outx), outy(outy), svec(svec), Px(Px), Py(Py)
  {
    size_t numbits = svec.size();
    
    accumx.allocate(this->pb, numbits-1, "accumx");
    accumy.allocate(this->pb, numbits-1, "accumy");
    
    FieldT twoiPx = Px, twoiPy = Py;
    FieldT twoi2Px, twoi2Py;
    
    // Create the adders to fill the Ptable with the correct values.
        // Ptable[2*i] and Ptable[2*i+1] are the (x,y) coordinates of
        // 2^i * P.
        
        //twoiPx.allocate(this->pb, numbits, "twoiPx");
        //twoiPy.allocate(this->pb, numbits, "twoiPy");
        
      //  if (numbits > 0) {
      //      adders.emplace_back(this->pb, twoiPx[0], twoiPy[0],
      //              Px, Py, FieldT(0), FieldT(0));
      //  }
    
      for (size_t i = 0; i < numbits; ++i) {
            // Invariant: twoiP[i] = 2^{i+1} * P
            
            twoi2Px = twoiPx;
            twoi2Py = twoiPy;
            
            twoadders.emplace_back(this->pb,
				     (i == numbits-1 ? outx : accumx[i]),
                     (i == numbits-1 ? outy : accumy[i]),
                     (i == 0 ? 0 : accumx[i-1]),
                     (i == 0 ? 0 : accumy[i-1]),
                     svec[i], 0, 0, twoi2Px, twoi2Py);
                     
            ec_double_point(twoiPx, twoiPy, twoi2Px, twoi2Py);
            
            }
             
		}
  
  void generate_r1cs_constraints()
  {
        for (auto&& gadget : twoadders) {
            gadget.generate_r1cs_constraints();
        }
  }
  
  void generate_r1cs_witness()
  {     
        for (auto&& gadget : twoadders) {
            gadget.generate_r1cs_witness();
        }//
  }
};



// Compute s*P as (outx, outy) for a given constant point P, and s given
// as a bit vector.  The _caller_ is responsible for proving that the
// elements of svec are bits.
//template<typename FieldT>
//class ec_constant_scalarmul_vec_gadget : public gadget<FieldT> {
//private:
  //FieldT AXSx, AXSy;
  //pb_variable<FieldT> accinx, acciny, accoutx, accouty;
  //std::vector<ec_constant_scalarmul_vec_accum_gadget<FieldT> > scalarmuls;
  //std::vector<ec_constant_add_gadget<FieldT> > adders;
//public:
  //const pb_variable<FieldT> outx, outy;
  //const pb_variable_array<FieldT> svec;
  //const FieldT Px, Py;

  //ec_constant_scalarmul_vec_gadget(protoboard<FieldT> &pb,
              //const pb_variable<FieldT> &outx,
              //const pb_variable<FieldT> &outy,
              //const pb_variable_array<FieldT> &svec,
              //const FieldT &Px, const FieldT &Py) :
    //gadget<FieldT>(pb, "ec_constant_scalarmul_vec_gadget"),
    //outx(outx), outy(outy), svec(svec), Px(Px), Py(Py)
  //{
    //AXSx = curveParams<FieldT>::Ax;
    //AXSy = curveParams<FieldT>::Ay;
    //accinx.allocate(this->pb, "accinx");
    //acciny.allocate(this->pb, "acciny");
    //accoutx.allocate(this->pb, "accoutx");
    //accouty.allocate(this->pb, "accouty");

    //scalarmuls.emplace_back(pb, accoutx, accouty, accinx, acciny, svec, Px, Py, AXSx, AXSy);
    //adders.emplace_back(pb, outx, outy, accoutx, accouty, AXSx, -AXSy);
  //}

  //void generate_r1cs_constraints()
  //{
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));
    //scalarmuls[0].generate_r1cs_constraints();
    //adders[0].generate_r1cs_constraints();
  //}

  //void generate_r1cs_witness()
  //{
    //this->pb.val(accinx) = curveParams<FieldT>::Ax;
    //this->pb.val(acciny) = curveParams<FieldT>::Ay;
    //scalarmuls[0].generate_r1cs_witness();
    //adders[0].generate_r1cs_witness();
  //}
//};


// Compute s*P as (outx, outy) for a given constant point P, and s given
// as a field element.
template<typename FieldT>
class ec_constant_scalarmul_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> svec;
  std::vector<packing_gadget<FieldT> > packers;
  std::vector<ec_constant_scalarmul_vec_accum_gadget<FieldT> > vecgadget;

public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> s;
  const FieldT Px, Py;
  const size_t numbits;

  ec_constant_scalarmul_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &s,
              const size_t &numbits,
              const FieldT &Px, const FieldT &Py) :
    gadget<FieldT>(pb, "ec_constant_scalarmul_gadget"),
    outx(outx), outy(outy), s(s), numbits(numbits), Px(Px), Py(Py)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    //size_t numbits = FieldT::num_bits;
    svec.allocate(this->pb, numbits, "svec");
    packers.emplace_back(this->pb, svec, s);
    vecgadget.emplace_back(this->pb, outx, outy, svec, Px, Py);
  }

  void generate_r1cs_constraints()
  {
    packers[0].generate_r1cs_constraints(true);
    vecgadget[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    packers[0].generate_r1cs_witness_from_packed();
    vecgadget[0].generate_r1cs_witness();
  }
};


//template<typename FieldT>
//class ec_scalarmul_gadget;

//// Compute A + s*P as (outx, outy) for an accumulator A, a precomputed
//// addition table Ptable for a variable point P, and s given as a bit
//// vector.  The _caller_ is responsible for proving that the elements of
//// svec are bits.  The (constant) accumulator excess (AXS) will be
//// updated; when all the computations are complete, AXS should be
//// subtracted from the accumulator A.  The addition table is a variable
//// array of length 2*numbits (where numbits is the length of svec) such
//// that Ptable[2*i] and Ptable[2*i+1] are the (x,y) coordinates of
//// 2^i * P + C.  Set Ptable_set_constraints to true (exactly once
//// in the event the same Ptable is reused in the same circuit) if
//// the Ptable is part of the private input.  Set Ptable_fill_values
//// to true exactly once per Ptable (again, in case it it reused in the
//// same circuit).
//template<typename FieldT>
//class ec_scalarmul_vec_accum_gadget : public gadget<FieldT> {
  //private:
  //pb_variable_array<FieldT> accumx, accumy;
  //pb_variable_array<FieldT> twoiPx, twoiPy;
  //std::vector<ec_constant_add_gadget<FieldT> > cadders;
 //// std::vector<ec_add_gadget<FieldT> > adders;
  //std::vector<ec_2_1constant_add_gadget<FieldT> > twoadders;
  //std::vector<ec_double_gadget<FieldT> > doublers;
  
  //public:
  //const pb_variable<FieldT> outx, outy;
  //const pb_variable<FieldT> Ax, Ay;
  //const pb_variable_array<FieldT> svec;
  //const pb_variable<FieldT> Px, Py;
  //const pb_variable_array<FieldT> Ptable;
  //bool Ptable_set_constraints, Ptable_fill_values;
  
  //ec_scalarmul_vec_accum_gadget(protoboard<FieldT> &pb,
              //const pb_variable<FieldT> &outx,
              //const pb_variable<FieldT> &outy,
           ////   const pb_variable<FieldT> &Ax,
           ////   const pb_variable<FieldT> &Ay,
              //const pb_variable_array<FieldT> &svec,
              //const pb_variable<FieldT> &Px,
              //const pb_variable<FieldT> &Py
              //) :
    //gadget<FieldT>(pb, "ec_scalarmul_vec_accum_gadget"),
    //outx(outx), outy(outy), svec(svec),
    //Px(Px), Py(Py)
    //// Ptable(Ptable),
    //// Ptable_set_constraints(Ptable_set_constraints),
    //// Ptable_fill_values(Ptable_fill_values)
  //{
    //size_t numbits = svec.size();
   //// assert(Ptable.size() == 2*numbits);
   //Ptable.allocate(this->pb, 2*numbits, "Ptable");
    
   //// if (Ptable_set_constraints) {
        //// Create the adders to fill the Ptable with the correct values.
        //// Ptable[2*i] and Ptable[2*i+1] are the (x,y) coordinates of
        //// 2^i * P.
        //if (numbits > 0) {
            //cadders.emplace_back(this->pb, Ptable[0], Ptable[1],
                    //Px, Py, FieldT(0), FieldT(0));
        //}
    
        //if (numbits > 1) {
            //twoiPx.allocate(this->pb, numbits-1, "twoiPx");
            //twoiPy.allocate(this->pb, numbits-1, "twoiPy");
        //}
        
        //for (size_t i = 1; i < numbits; ++i) {
            //// Invariant: twoiP[i] = 2^{i+1} * P
            //doublers.emplace_back(this->pb,
					 //Ptable[2*i], Ptable[2*i+1],
                     //Ptable[2*i-2], Ptable[2*i-1]);

              //}
  ////  }
    
    //accumx.allocate(this->pb, numbits-1, "accumx");
    //accumy.allocate(this->pb, numbits-1, "accumy");

    //for (size_t i = 0; i < numbits; ++i) {
        //twoadders.emplace_back(this->pb,
            //(i == numbits-1 ? outx : accumx[i]),
            //(i == numbits-1 ? outy : accumy[i]),
            //(i == 0 ? 0 : accumx[i-1]),
            //(i == 0 ? 0 : accumy[i-1]),
            //svec[i], 0, 0, Ptable[2*i], Ptable[2*i+1]);
            
		//}
  //}
  
  //void generate_r1cs_constraints()
  //{
    //if (Ptable_set_constraints) {
        //cadders[0].generate_r1cs_constraints();
        
        //for (auto&& gadget : doublers) {
            //gadget.generate_r1cs_constraints();
        //}
    //}
    //for (auto&& gadget : twoadders) {
        //gadget.generate_r1cs_constraints();
    //}
  //}
  
  //void generate_r1cs_witness()
  //{
    //if (Ptable_set_constraints) {
        //// We also have to satisfy the constraints we set
        //size_t numbits = Ptable.size() / 2;

        //if (numbits > 0) {
            //cadders[0].generate_r1cs_witness();
        //}
        
        //for (auto&& gadget : doublers) {
            //gadget.generate_r1cs_witness();
        //}
    //} else if (Ptable_fill_values) {
        //// We can just compute the Ptable values manually
       //compute_Ptable(this->pb, &Ptable, &Px, &Py);
    //}
    //for (auto&& gadget : twoadders) {
        //gadget.generate_r1cs_witness();
    //}
  //}
//};


//// Compute s*P as (outx, outy) for a precomputed addition table Ptable
//// for a variable point P, and s given as a bit vector.  The _caller_ is
//// responsible for proving that the elements of svec are bits.
//// The addition table is a variable array of length 2*numbits (where
//// numbits is the length of svec) such that Ptable[2*i] and
//// Ptable[2*i+1] are the (x,y) coordinates of 2^i * P + C.  Set
//// Ptable_set_constraints to true (exactly once in the event the same
//// Ptable is reused in the same circuit) if the Ptable is part of the
//// private input.  Set Ptable_fill_values to true exactly once per
//// Ptable (again, in case it it reused in the same circuit).
//template<typename FieldT>
//class ec_scalarmul_vec_gadget : public gadget<FieldT> {
//private:
  //FieldT AXSx, AXSy;
  //pb_variable<FieldT> accinx, acciny, accoutx, accouty;
  //std::vector<ec_scalarmul_vec_accum_gadget<FieldT> > scalarmuls;
  //std::vector<ec_constant_add_gadget<FieldT> > adders;
//public:
  //const pb_variable<FieldT> outx, outy;
  //const pb_variable_array<FieldT> svec;
  //const pb_variable<FieldT> Px, Py;
  //const pb_variable_array<FieldT> Ptable;
  //bool Ptable_set_constraints, Ptable_fill_values;

  //ec_scalarmul_vec_gadget(protoboard<FieldT> &pb,
              //const pb_variable<FieldT> &outx,
              //const pb_variable<FieldT> &outy,
              //const pb_variable_array<FieldT> &svec,
              //const pb_variable<FieldT> &Px,
              //const pb_variable<FieldT> &Py,
              //const pb_variable_array<FieldT> &Ptable,
              //bool Ptable_set_constraints,
              //bool Ptable_fill_values) :
    //gadget<FieldT>(pb, "ec_scalarmul_vec_gadget"),
    //outx(outx), outy(outy), svec(svec),
    //Px(Px), Py(Py), Ptable(Ptable),
    //Ptable_set_constraints(Ptable_set_constraints),
    //Ptable_fill_values(Ptable_fill_values)
  //{
    //AXSx = curveParams<FieldT>::Ax;
    //AXSy = curveParams<FieldT>::Ay;
    //accinx.allocate(this->pb, "accinx");
    //acciny.allocate(this->pb, "acciny");
    //accoutx.allocate(this->pb, "accoutx");
    //accouty.allocate(this->pb, "accouty");
    //scalarmuls.emplace_back(pb, accoutx, accouty, accinx, acciny, svec,
        //Px, Py, Ptable, Ptable_set_constraints, Ptable_fill_values,
        //AXSx, AXSy);
    //adders.emplace_back(pb, outx, outy, accoutx, accouty, AXSx, -AXSy);
  //}

  //void generate_r1cs_constraints()
  //{
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));
    //scalarmuls[0].generate_r1cs_constraints();
    //adders[0].generate_r1cs_constraints();
  //}

  //void generate_r1cs_witness()
  //{
    //this->pb.val(accinx) = curveParams<FieldT>::Ax;
    //this->pb.val(acciny) = curveParams<FieldT>::Ay;
    //scalarmuls[0].generate_r1cs_witness();
    //adders[0].generate_r1cs_witness();
  //}
//};



//// Compute s*P as (outx, outy) for a precomputed addition table Ptable
//// for a variable point P, and s given as a field element.  

////The addition table is a variable array of length 2*numbits (where numbits is the
//// length of the FieldT size) such that Ptable[2*i] and Ptable[2*i+1]
//// are the (x,y) coordinates of 2^i * P + C.  Set Ptable_set_constraints
//// to true (exactly once in the event the same Ptable is reused in the
//// same circuit) if the Ptable is part of the private input.  Set
//// Ptable_fill_values to true exactly once per Ptable (again, in case it
//// it reused in the same circuit).
//template<typename FieldT>
//class ec_scalarmul_gadget : public gadget<FieldT> {
//private:
  //pb_variable_array<FieldT> svec;
  //std::vector<packing_gadget<FieldT> > packers;
  //std::vector<ec_scalarmul_vec_accum_gadget<FieldT> > vecgadget;

//public:
  //const pb_variable<FieldT> outx, outy;
  //const pb_variable<FieldT> s;
  //const pb_variable<FieldT> Px, Py;
  
  //ec_scalarmul_gadget(protoboard<FieldT> &pb,
              //const pb_variable<FieldT> &outx,
              //const pb_variable<FieldT> &outy,
              //const pb_variable<FieldT> &s,
              //const pb_variable<FieldT> &Px,
              //const pb_variable<FieldT> &Py) :
    //gadget<FieldT>(pb, "ec_scalarmul_gadget"),
    //outx(outx), outy(outy), s(s), Px(Px), Py(Py)
    //{
    //size_t numbits = FieldT::num_bits;
    //svec.allocate(this->pb, numbits, "svec");
    //packers.emplace_back(this->pb, svec, s);
    //vecgadget.emplace_back(this->pb, outx, outy, svec,Px, Py);
   //}
	
  //void generate_r1cs_constraints()
	//{
    //packers[0].generate_r1cs_constraints(true);
    //vecgadget[0].generate_r1cs_constraints();
	//}

  //void generate_r1cs_witness()
	//{
    //packers[0].generate_r1cs_witness_from_packed();
    //vecgadget[0].generate_r1cs_witness();
	//}
//};

// Compute the addition table.  The addition table is a variable array
  // of length 2*numbits such that Ptable[2*i] and Ptable[2*i+1] are the
  // (x,y) coordinates of 2^i * P.
  template<typename FieldT>
  static void compute_Ptable(protoboard<FieldT> &pb,
                const pb_variable_array<FieldT> &Ptable,
                const pb_variable<FieldT> &Px,
                const pb_variable<FieldT> &Py)
  {
    assert(Ptable.size() % 2 == 0);
    size_t numbits = Ptable.size() / 2;

    FieldT twoiPx = pb.val(Px);
    FieldT twoiPy = pb.val(Py);

    for (size_t i = 0; i < numbits; ++i) {
        // Invariant: (twoiPx, twoiPy) = 2^i * P
		pb.val(Ptable[2*i]) = twoiPx;
        pb.val(Ptable[2*i+1]) = twoiPy;

        // Compute 2^{i+1} * P
        FieldT twoi1Px, twoi1Py;
        ec_double_point(twoi1Px, twoi1Py, twoiPx, twoiPy);
        twoiPx = twoi1Px;
        twoiPy = twoi1Py;
    }
  }
 
//Compute a*G + b*H as (outx, outy), given a and b as field elements.
template<typename FieldT>
class ec_pedersen_gadget : public gadget<FieldT> {
private:
  //pb_variable<FieldT> accinx, acciny, accmidx, accmidy, accoutx, accouty;
  std::vector<ec_constant_scalarmul_gadget<FieldT> > mulgadgets;
  std::vector<ec_add_gadget<FieldT> > addgadget;
  pb_variable<FieldT> out_ax, out_ay, out_bx, out_by;

public:
  const pb_variable<FieldT> outx, outy, a, b;
  
  const FieldT Gx, Gy, Hx, Hy;

  ec_pedersen_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &a,
              const pb_variable<FieldT> &b,
              const FieldT &Gx, const FieldT &Gy,
              const FieldT &Hx, const FieldT &Hy) :
    gadget<FieldT>(pb, "ec_pedersen_gadget"),
    outx(outx), outy(outy), a(a), b(b), Gx(Gx), Gy(Gy), Hx(Hx), Hy(Hy)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    //accinx.allocate(this->pb, "accinx");
    //acciny.allocate(this->pb, "acciny");
    //accmidx.allocate(this->pb, "accmidx");
    //accmidy.allocate(this->pb, "accmidy");
    //accoutx.allocate(this->pb, "accoutx");
    //accouty.allocate(this->pb, "accouty");

    // Initialize the accumulator
    //FieldT AXSx = curveParams<FieldT>::Ax;
    //FieldT AXSy = curveParams<FieldT>::Ay;
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));

    // Initialize the gadgets
    mulgadgets.emplace_back(this->pb, out_ax, out_ay, a, Gx, Gy);
    mulgadgets.emplace_back(this->pb, out_bx, out_by, b, Hx, Hy);
    
    
    addgadget.emplace_back(this->pb, outx, outy, out_ax, out_ay, out_bx, out_by);
  }

  void generate_r1cs_constraints()
  {
    mulgadgets[0].generate_r1cs_constraints();
    mulgadgets[1].generate_r1cs_constraints();
    addgadget[0].generate_r1cs_constraints();
  //  this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(out_ax + out_bx, 1, outx));
  //  this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(out_ay + out_by, 1, outy));
  }

  void generate_r1cs_witness()
  {
    mulgadgets[0].generate_r1cs_witness();
    mulgadgets[1].generate_r1cs_witness();
    addgadget[0].generate_r1cs_witness();
  // this->pb.val(outx) = this->pb.lc_val(out_ax) + this->pb.lc_val(out_bx);
  // this->pb.val(outy) = this->pb.lc_val(out_ay) + this->pb.lc_val(out_by);
  }
};

 
