#include "equality_gadget.hpp"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
//#include <gmp.h>
#include <boost/multiprecision/gmp.hpp>
//#include <boost/multiprecision/random.hpp>

using namespace boost::multiprecision;
using namespace boost::random;


//#include <iostream>
//#include <vector>
//#include <cmath>
//#include <ctime>

//#include <stdlib.h>
//#include <fstream>
//#include <chrono>
//#include <cstdint>
//#include <random>

typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;

FieldT sum_t = 0;
FieldT sum_b = FieldT::zero();

struct int256{
	uint64_t value[4];
};

int256 randomNumberGenerator(){
	int256 num;
	srand(time(NULL));
	for(int i=0;i<3;i++){
		num.value[i] = rand() % (uint64_t)(pow(2,64));
	}
	return num;
}


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
template<typename FieldT>
struct curveParams {
    // Some generators
    static FieldT Gx, Gy, Hx, Hy, Cx, Cy, Ax, Ay;
};

typedef libff::Fr<libff::alt_bn128_pp> BN128Fr;
typedef curveParams<BN128Fr> BN128Params;
typedef libff::Fr<libff::mnt4_pp> MNT4Fr;
typedef curveParams<MNT4Fr> MNT4Params;
typedef libff::Fr<libff::mnt6_pp> MNT6Fr;
typedef curveParams<MNT6Fr> MNT6Params;

void init_curveparams(void) {
    // BN128 has order 21888242871839275222246405745257275088548364400416034343698204186575808495617.
    // The curve we use has that number as a modulus, equation
    // y^2 = x^3 - 3*x + 7950939520449436327800262930799465135910802758673292356620796789196167463969,
    // order 21888242871839275222246405745257275088760161411100494528458776273921456643749,
    // and twist order 21888242871839275222246405745257275088336567389731574158937632099230160347487
    BN128Params::Gx = BN128Fr(0);
    BN128Params::Gy = BN128Fr("11977228949870389393715360594190192321220966033310912010610740966317727761886");
    BN128Params::Hx = BN128Fr(1);
    BN128Params::Hy = BN128Fr("21803877843449984883423225223478944275188924769286999517937427649571474907279");
    BN128Params::Cx = BN128Fr(2);
    BN128Params::Cy = BN128Fr("4950745124018817972378217179409499695353526031437053848725554590521829916331");
    BN128Params::Ax = BN128Fr(4);
    BN128Params::Ay = BN128Fr("1929778687269876629657252589535788315400602403700102541701561325064015752665");

    // MNT4 has order 475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137.
    // The curve we use has that number as a modulus, equation
    // y^2 = x^3 - 3*x + 231167148323223259519222248276530122498019837271767399092881541755570759528915690054257617,
    // order 475922286169261325753349249653048451545124877609388602970058907680650183700694415633043899,
    // and twist order 475922286169261325753349249653048451545124879496258428136476563797679110914122565486882377
    MNT4Params::Gx = MNT4Fr(0);
    MNT4Params::Gy = MNT4Fr("69340010096176642671075936244233205591761175107929619077175443746098492155210682688004000");
    MNT4Params::Hx = MNT4Fr(4);
    MNT4Params::Hy = MNT4Fr("89962085395108430328776481330922276788164520703635405311225917405228387147951802989614963");
    MNT4Params::Cx = MNT4Fr(5);
    MNT4Params::Cy = MNT4Fr("52902001285898935334481582927659505082867000922458881015269230130767369971501119682509581");
    MNT4Params::Ax = MNT4Fr(13);
    MNT4Params::Ay = MNT4Fr("121053423448209007180763047755032137130187089528003831161099799540651189694573076331882906");

    // MNT6 has order 475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081
    // The curve we use has that number as a modulus, equation
    // y^2 = x^3 - 3*x + 24546313041565681523715355676371506472020535518551005057500340479469011985449670363024622,
    // order 475922286169261325753349249653048451545124878803858277348714592806990498327174348276061263,
    // and twist order 475922286169261325753349249653048451545124879681531173442395664345430027308737252691454901
    MNT6Params::Gx = MNT6Fr(6);
    MNT6Params::Gy = MNT6Fr("24197108752891306593933912637919640614809244712814357996916386860820196450211056738894088");
    MNT6Params::Hx = MNT6Fr(7);
    MNT6Params::Hy = MNT6Fr("38986684752414230937697051240187730249331222579878762386361563720275249449300503095108315");
    MNT6Params::Cx = MNT6Fr(10);
    MNT6Params::Cy = MNT6Fr("16456076723096839034614236624058053946787958080849874304391400047777491942015349039526487");
    MNT6Params::Ax = MNT6Fr(15);
    MNT6Params::Ay = MNT6Fr("217167731603808417993030053532106278784760282438477394477321645018696010454906317296597425");
}

// These need to be here for the linker to work
template<> BN128Fr BN128Params::Gx = 0;
template<> BN128Fr BN128Params::Gy = 0;
template<> BN128Fr BN128Params::Hx = 0;
template<> BN128Fr BN128Params::Hy = 0;
template<> BN128Fr BN128Params::Cx = 0;
template<> BN128Fr BN128Params::Cy = 0;
template<> BN128Fr BN128Params::Ax = 0;
template<> BN128Fr BN128Params::Ay = 0;
template<> MNT4Fr MNT4Params::Gx = 0;
template<> MNT4Fr MNT4Params::Gy = 0;
template<> MNT4Fr MNT4Params::Hx = 0;
template<> MNT4Fr MNT4Params::Hy = 0;
template<> MNT4Fr MNT4Params::Cx = 0;
template<> MNT4Fr MNT4Params::Cy = 0;
template<> MNT4Fr MNT4Params::Ax = 0;
template<> MNT4Fr MNT4Params::Ay = 0;
template<> MNT6Fr MNT6Params::Gx = 0;
template<> MNT6Fr MNT6Params::Gy = 0;
template<> MNT6Fr MNT6Params::Hx = 0;
template<> MNT6Fr MNT6Params::Hy = 0;
template<> MNT6Fr MNT6Params::Cx = 0;
template<> MNT6Fr MNT6Params::Cy = 0;
template<> MNT6Fr MNT6Params::Ax = 0;
template<> MNT6Fr MNT6Params::Ay = 0;

// Double a constant EC point (inx,iny) to yield (outx,outy).  The input
// point must not be the point at infinity.
template<typename FieldT>
static void ec_double_point(FieldT &outx, FieldT &outy,
    const FieldT &inx, const FieldT &iny)
{
    FieldT xsq = inx.squared();
    FieldT lambda = (xsq * 3 - 3) * (iny * 2).inverse();
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
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * iny, lambda, 3 * inxsq - 3));

    // outx = lambda^2 - 2 * inx
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, lambda, outx + 2 * inx));

    // outy = lambda * (inx - outx) - iny
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lambda, inx - outx, outy + iny));

  }

  void generate_r1cs_witness()
  {
    this->pb.val(inxsq) = this->pb.lc_val(inx) * this->pb.lc_val(inx);
    this->pb.val(lambda) = (this->pb.val(inxsq) * 3 - 3) * (this->pb.lc_val(iny) * 2).inverse();
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

// Compute A + s*P as (outx, outy) for an accumulator A, a given
// constant point P, and s given as a bit vector.  The _caller_ is
// responsible for proving that the elements of svec are bits.  The
// (constant) accumulator excess (AXS) will be updated; when all the
// computations are complete, AXS should be subtracted from the
// accumulator A.
template<typename FieldT>
class ec_constant_scalarmul_vec_accum_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> accumx, accumy;
  std::vector<ec_4_constant_add_gadget<FieldT> > fouradders;
  std::vector<ec_2_constant_add_gadget<FieldT> > twoadders;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> Ax, Ay;
  const pb_variable_array<FieldT> svec;
  const FieldT Px, Py;

  // Strategy: We compute (as compile-time constants) (powers of 2)
  // times P.  Based on each bit of s, we add one of the constant points
  // C or (2^i * P) + C to the accumulator, and regardless of s, add C
  // to the excess.

  ec_constant_scalarmul_vec_accum_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &Ax,
              const pb_variable<FieldT> &Ay,
              const pb_variable_array<FieldT> &svec,
              const FieldT &Px, const FieldT &Py,
              FieldT &AXSx, FieldT &AXSy) :
    gadget<FieldT>(pb, "ec_constant_scalarmul_vec_accum_gadget"),
    outx(outx), outy(outy), Ax(Ax), Ay(Ay), svec(svec), Px(Px), Py(Py)
  {
    size_t numbits = svec.size();
    // See loop comments below: if numbits is odd, we need (numbits-1)/2
    // slots.  If numbits is even, we need (numbits-2)/2 slots.  So
    // with integer truncated division, (numbits-1)/2 will be correct
    // in both cases.  (Well, if numbits is 0 for some reason, we also want
    // to get 0.)
    size_t accumslots = 0;
    if (numbits > 0) {
        accumslots = (numbits-1)/2;
    }
    accumx.allocate(this->pb, accumslots, "accumx");
    accumy.allocate(this->pb, accumslots, "accumy");

    FieldT twoiPx = Px, twoiPy = Py;
    size_t i = 0, accnext = 0;

    while(i < numbits) {
        // Invariant: twoiP = 2^i * P
        // Invariant: i is even and accnext = i/2

        if (i == numbits-1) {
            FieldT twoiPCx, twoiPCy;
            ec_add_points(twoiPCx, twoiPCy, twoiPx, twoiPy,
                curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);

            twoadders.emplace_back(this->pb,
                outx, outy,
                (i == 0 ? Ax : accumx[accnext-1]),
                (i == 0 ? Ay : accumy[accnext-1]),
                svec[i],
                curveParams<FieldT>::Cx, curveParams<FieldT>::Cy,
                twoiPCx, twoiPCy);

            // This makes i odd, but also exits the loop with
            // i = numbits and accnext = (numbits-1)/2
            i += 1;
        } else {
            // Do two bits at a time

            // We need to compute 2^i * a * P + C for a = 1,2,3
            FieldT twoi2Px, twoi2Py;
            FieldT twoi1PCx, twoi1PCy, twoi2PCx, twoi2PCy, twoi3PCx, twoi3PCy;

            ec_add_points(twoi1PCx, twoi1PCy, twoiPx, twoiPy,
                    curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
            ec_double_point(twoi2Px, twoi2Py, twoiPx, twoiPy);
            ec_add_points(twoi2PCx, twoi2PCy, twoi2Px, twoi2Py,
                    curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
            ec_add_points(twoi3PCx, twoi3PCy, twoi2Px, twoi2Py,
                    twoi1PCx, twoi1PCy);

            fouradders.emplace_back(this->pb,
                (i == numbits-2 ? outx : accumx[accnext]),
                (i == numbits-2 ? outy : accumy[accnext]),
                (i == 0 ? Ax : accumx[accnext-1]),
                (i == 0 ? Ay : accumy[accnext-1]),
                svec[i], svec[i+1],
                curveParams<FieldT>::Cx, curveParams<FieldT>::Cy,
                twoi1PCx, twoi1PCy,
                twoi2PCx, twoi2PCy, twoi3PCx, twoi3PCy);

            // If i == numbits-2, we write directly to out and not accum above, and
            // exit the loop with i even and i == numbits and accnext = (numbits-2)/2
            if (i < numbits - 2) {
                accnext += 1;
            }
            i += 2;
            ec_double_point(twoiPx, twoiPy, twoi2Px, twoi2Py);
        }

        FieldT newAXSx, newAXSy;
        ec_add_points(newAXSx, newAXSy, AXSx, AXSy,
                curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
        AXSx = newAXSx;
        AXSy = newAXSy;
    }
  }

  void generate_r1cs_constraints()
  {
    for (auto&& gadget : fouradders) {
        gadget.generate_r1cs_constraints();
    }
    for (auto&& gadget : twoadders) {
        gadget.generate_r1cs_constraints();
    }
  }

  void generate_r1cs_witness()
  {
    for (auto&& gadget : fouradders) {
        gadget.generate_r1cs_witness();
    }
    for (auto&& gadget : twoadders) {
        gadget.generate_r1cs_witness();
    }
  }
};

// Compute A + s*P as (outx, outy) for an accumulator A, a given
// constant point P, and s given as a field element.  The (constant)
// accumulator excess (AXS) will be updated; when all the computations
// are complete, AXS should be subtracted from the accumulator A.
template<typename FieldT>
class ec_constant_scalarmul_accum_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> svec;
  std::vector<packing_gadget<FieldT> > packers;
  std::vector<ec_constant_scalarmul_vec_accum_gadget<FieldT> > vecgadget;

public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> Ax, Ay;
  const pb_variable<FieldT> s;
  const FieldT Px, Py;
  const int numbits;

  ec_constant_scalarmul_accum_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &Ax,
              const pb_variable<FieldT> &Ay,
              const pb_variable<FieldT> &s,
              const int &numbits,
              const FieldT &Px, const FieldT &Py,
              FieldT &AXSx, FieldT &AXSy) :
    gadget<FieldT>(pb, "ec_constant_scalarmul_accum_gadget"),
    outx(outx), outy(outy), Ax(Ax), Ay(Ay), s(s), numbits(numbits), Px(Px), Py(Py)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    //size_t numbits = FieldT::num_bits;
    svec.allocate(this->pb, numbits, "svec");
    packers.emplace_back(this->pb, svec, s);
    vecgadget.emplace_back(this->pb, outx, outy, Ax, Ay, svec, Px, Py, AXSx, AXSy);
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

// Compute s*P as (outx, outy) for a given constant point P, and s given
// as a bit vector.  The _caller_ is responsible for proving that the
// elements of svec are bits.
template<typename FieldT>
class ec_constant_scalarmul_vec_gadget : public gadget<FieldT> {
private:
  FieldT AXSx, AXSy;
  pb_variable<FieldT> accinx, acciny, accoutx, accouty;
  std::vector<ec_constant_scalarmul_vec_accum_gadget<FieldT> > scalarmuls;
  std::vector<ec_constant_add_gadget<FieldT> > adders;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable_array<FieldT> svec;
  const FieldT Px, Py;

  ec_constant_scalarmul_vec_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable_array<FieldT> &svec,
              const FieldT &Px, const FieldT &Py) :
    gadget<FieldT>(pb, "ec_constant_scalarmul_vec_gadget"),
    outx(outx), outy(outy), svec(svec), Px(Px), Py(Py)
  {
    AXSx = curveParams<FieldT>::Ax;
    AXSy = curveParams<FieldT>::Ay;
    accinx.allocate(this->pb, "accinx");
    acciny.allocate(this->pb, "acciny");
    accoutx.allocate(this->pb, "accoutx");
    accouty.allocate(this->pb, "accouty");

    scalarmuls.emplace_back(pb, accoutx, accouty, accinx, acciny, svec, Px, Py, AXSx, AXSy);
    adders.emplace_back(pb, outx, outy, accoutx, accouty, AXSx, -AXSy);
  }

  void generate_r1cs_constraints()
  {
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));
    scalarmuls[0].generate_r1cs_constraints();
    adders[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    this->pb.val(accinx) = curveParams<FieldT>::Ax;
    this->pb.val(acciny) = curveParams<FieldT>::Ay;
    scalarmuls[0].generate_r1cs_witness();
    adders[0].generate_r1cs_witness();
  }
};

// Compute s*P as (outx, outy) for a given constant point P, and s given
// as a field element.
template<typename FieldT>
class ec_constant_scalarmul_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> svec;
  std::vector<packing_gadget<FieldT> > packers;
  std::vector<ec_constant_scalarmul_vec_gadget<FieldT> > vecgadget;

public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> s;
  const FieldT Px, Py;
  const int numbits;

  ec_constant_scalarmul_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &s,
              const int &numbits,
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

template<typename FieldT>
class ec_scalarmul_gadget;

// Compute A + s*P as (outx, outy) for an accumulator A, a precomputed
// addition table Ptable for a variable point P, and s given as a bit
// vector.  The _caller_ is responsible for proving that the elements of
// svec are bits.  The (constant) accumulator excess (AXS) will be
// updated; when all the computations are complete, AXS should be
// subtracted from the accumulator A.  The addition table is a variable
// array of length 2*numbits (where numbits is the length of svec) such
// that Ptable[2*i] and Ptable[2*i+1] are the (x,y) coordinates of
// 2^i * P + C.  Set Ptable_set_constraints to true (exactly once
// in the event the same Ptable is reused in the same circuit) if
// the Ptable is part of the private input.  Set Ptable_fill_values
// to true exactly once per Ptable (again, in case it it reused in the
// same circuit).
template<typename FieldT>
class ec_scalarmul_vec_accum_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> accumx, accumy;
  pb_variable_array<FieldT> twoiPx, twoiPy;
  std::vector<ec_constant_add_gadget<FieldT> > cadders;
  std::vector<ec_add_gadget<FieldT> > adders;
  std::vector<ec_2_1constant_add_gadget<FieldT> > twoadders;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> Ax, Ay;
  const pb_variable_array<FieldT> svec;
  const pb_variable<FieldT> Px, Py;
  const pb_variable_array<FieldT> Ptable;
  bool Ptable_set_constraints, Ptable_fill_values;

  ec_scalarmul_vec_accum_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &Ax,
              const pb_variable<FieldT> &Ay,
              const pb_variable_array<FieldT> &svec,
              const pb_variable<FieldT> &Px,
              const pb_variable<FieldT> &Py,
              const pb_variable_array<FieldT> &Ptable,
              bool Ptable_set_constraints,
              bool Ptable_fill_values,
              FieldT &AXSx, FieldT &AXSy) :
    gadget<FieldT>(pb, "ec_scalarmul_vec_accum_gadget"),
    outx(outx), outy(outy), Ax(Ax), Ay(Ay), svec(svec),
    Px(Px), Py(Py), Ptable(Ptable),
    Ptable_set_constraints(Ptable_set_constraints),
    Ptable_fill_values(Ptable_fill_values)
  {
    size_t numbits = svec.size();
    assert(Ptable.size() == 2*numbits);

    if (Ptable_set_constraints) {
        // Create the adders to fill the Ptable with the correct values.
        // Ptable[2*i] and Ptable[2*i+1] are the (x,y) coordinates of
        // 2^i * P + C.
        if (numbits > 0) {
            // Add P and C to get Ptable[0,1] = P+C
            cadders.emplace_back(this->pb, Ptable[0], Ptable[1],
                    Px, Py, curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
        }
        if (numbits > 1) {
            // Add P and P+C to get Ptable[2,3] = 2*P+C
            adders.emplace_back(this->pb, Ptable[2], Ptable[3],
                    Px, Py, Ptable[0], Ptable[1]);
        }
        if (numbits > 2) {
            twoiPx.allocate(this->pb, numbits-2, "twoiPx");
            twoiPy.allocate(this->pb, numbits-2, "twoiPy");
        }
        for (size_t i = 2; i < numbits; ++i) {
            // Invariant: twoiP[i] = 2^{i+1} * P

            // Compute 2^{i-1}*P = (2^{i-1}*P + C) - C
            cadders.emplace_back(this->pb,
                    twoiPx[i-2], twoiPy[i-2],
                    Ptable[2*(i-1)], Ptable[2*(i-1)+1],
                    curveParams<FieldT>::Cx, -curveParams<FieldT>::Cy);

            // Compute 2^{i}*P + C = (2^{i-1}*P + C) + (2^{i-1}*P)
            adders.emplace_back(this->pb,
                    Ptable[2*i], Ptable[2*i+1],
                    Ptable[2*i-2], Ptable[2*i-1],
                    twoiPx[i-2], twoiPy[i-2]);
        }
    }

    accumx.allocate(this->pb, numbits-1, "accumx");
    accumy.allocate(this->pb, numbits-1, "accumy");

    for (size_t i = 0; i < numbits; ++i) {
        twoadders.emplace_back(this->pb,
            (i == numbits-1 ? outx : accumx[i]),
            (i == numbits-1 ? outy : accumy[i]),
            (i == 0 ? Ax : accumx[i-1]),
            (i == 0 ? Ay : accumy[i-1]),
            svec[i], curveParams<FieldT>::Cx, curveParams<FieldT>::Cy, Ptable[2*i], Ptable[2*i+1]);

        FieldT newAXSx, newAXSy;
        ec_add_points(newAXSx, newAXSy, AXSx, AXSy, curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
        AXSx = newAXSx;
        AXSy = newAXSy;
    }
  }

  void generate_r1cs_constraints()
  {
    if (Ptable_set_constraints) {
        for (auto&& gadget : cadders) {
            gadget.generate_r1cs_constraints();
        }
        for (auto&& gadget : adders) {
            gadget.generate_r1cs_constraints();
        }
    }
    for (auto&& gadget : twoadders) {
        gadget.generate_r1cs_constraints();
    }
  }

  void generate_r1cs_witness()
  {
    if (Ptable_set_constraints) {
        // We also have to satisfy the constraints we set
        size_t numbits = Ptable.size() / 2;

        if (numbits > 0) {
            cadders[0].generate_r1cs_witness();
        }
        if (numbits > 1) {
            adders[0].generate_r1cs_witness();
        }
        for (size_t i = 2; i < numbits; ++i) {
            cadders[i-1].generate_r1cs_witness();
            adders[i-1].generate_r1cs_witness();
        }
    } else if (Ptable_fill_values) {
        // We can just compute the Ptable values manually
        ec_scalarmul_gadget<FieldT>::compute_Ptable(this->pb, Ptable, Px, Py);
    }
    for (auto&& gadget : twoadders) {
        gadget.generate_r1cs_witness();
    }
  }
};

// Compute A + s*P as (outx, outy) for an accumulator A, a precomputed
// addition table Ptable for a variable point P, and s given as a field
// element.  The _caller_ is responsible for proving that the elements
// of svec are bits.  The (constant) accumulator excess (AXS) will be
// updated; when all the computations are complete, AXS should be
// subtracted from the accumulator A.  The addition table is a variable
// array of length 2*numbits (where numbits is the length of the FieldT
// size) such that Ptable[2*i] and Ptable[2*i+1] are the (x,y)
// coordinates of 2^i * P + C.  Set Ptable_set_constraints to true
// (exactly once in the event the same Ptable is reused in the same
// circuit) if the Ptable is part of the private input.  Set
// Ptable_fill_values to true exactly once per Ptable (again, in case it
// it reused in the same circuit).
template<typename FieldT>
class ec_scalarmul_accum_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> svec;
  std::vector<packing_gadget<FieldT> > packers;
  std::vector<ec_scalarmul_vec_accum_gadget<FieldT> > vecgadget;

public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> Ax, Ay;
  const pb_variable<FieldT> s;
  const pb_variable<FieldT> Px, Py;
  const pb_variable_array<FieldT> Ptable;
  bool Ptable_set_constraints, Ptable_fill_values;

  ec_scalarmul_accum_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &Ax,
              const pb_variable<FieldT> &Ay,
              const pb_variable<FieldT> &s,
              const pb_variable<FieldT> &Px,
              const pb_variable<FieldT> &Py,
              const pb_variable_array<FieldT> &Ptable,
              bool Ptable_set_constraints,
              bool Ptable_fill_values,
              FieldT &AXSx, FieldT &AXSy) :
    gadget<FieldT>(pb, "ec_scalarmul_accum_gadget"),
    outx(outx), outy(outy), Ax(Ax), Ay(Ay), s(s),
    Px(Px), Py(Py), Ptable(Ptable),
    Ptable_set_constraints(Ptable_set_constraints),
    Ptable_fill_values(Ptable_fill_values)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    size_t numbits = FieldT::num_bits;
    svec.allocate(this->pb, numbits, "svec");
    packers.emplace_back(this->pb, svec, s);
    vecgadget.emplace_back(this->pb, outx, outy, Ax, Ay, svec,
        Px, Py, Ptable, Ptable_set_constraints, Ptable_fill_values,
        AXSx, AXSy);
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

// Compute s*P as (outx, outy) for a precomputed addition table Ptable
// for a variable point P, and s given as a bit vector.  The _caller_ is
// responsible for proving that the elements of svec are bits.
// The addition table is a variable array of length 2*numbits (where
// numbits is the length of svec) such that Ptable[2*i] and
// Ptable[2*i+1] are the (x,y) coordinates of 2^i * P + C.  Set
// Ptable_set_constraints to true (exactly once in the event the same
// Ptable is reused in the same circuit) if the Ptable is part of the
// private input.  Set Ptable_fill_values to true exactly once per
// Ptable (again, in case it it reused in the same circuit).
template<typename FieldT>
class ec_scalarmul_vec_gadget : public gadget<FieldT> {
private:
  FieldT AXSx, AXSy;
  pb_variable<FieldT> accinx, acciny, accoutx, accouty;
  std::vector<ec_scalarmul_vec_accum_gadget<FieldT> > scalarmuls;
  std::vector<ec_constant_add_gadget<FieldT> > adders;
public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable_array<FieldT> svec;
  const pb_variable<FieldT> Px, Py;
  const pb_variable_array<FieldT> Ptable;
  bool Ptable_set_constraints, Ptable_fill_values;

  ec_scalarmul_vec_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable_array<FieldT> &svec,
              const pb_variable<FieldT> &Px,
              const pb_variable<FieldT> &Py,
              const pb_variable_array<FieldT> &Ptable,
              bool Ptable_set_constraints,
              bool Ptable_fill_values) :
    gadget<FieldT>(pb, "ec_scalarmul_vec_gadget"),
    outx(outx), outy(outy), svec(svec),
    Px(Px), Py(Py), Ptable(Ptable),
    Ptable_set_constraints(Ptable_set_constraints),
    Ptable_fill_values(Ptable_fill_values)
  {
    AXSx = curveParams<FieldT>::Ax;
    AXSy = curveParams<FieldT>::Ay;
    accinx.allocate(this->pb, "accinx");
    acciny.allocate(this->pb, "acciny");
    accoutx.allocate(this->pb, "accoutx");
    accouty.allocate(this->pb, "accouty");

    scalarmuls.emplace_back(pb, accoutx, accouty, accinx, acciny, svec,
        Px, Py, Ptable, Ptable_set_constraints, Ptable_fill_values,
        AXSx, AXSy);
    adders.emplace_back(pb, outx, outy, accoutx, accouty, AXSx, -AXSy);
  }

  void generate_r1cs_constraints()
  {
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));
    scalarmuls[0].generate_r1cs_constraints();
    adders[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    this->pb.val(accinx) = curveParams<FieldT>::Ax;
    this->pb.val(acciny) = curveParams<FieldT>::Ay;
    scalarmuls[0].generate_r1cs_witness();
    adders[0].generate_r1cs_witness();
  }
};

// Compute s*P as (outx, outy) for a precomputed addition table Ptable
// for a variable point P, and s given as a field element.  The addition
// table is a variable array of length 2*numbits (where numbits is the
// length of the FieldT size) such that Ptable[2*i] and Ptable[2*i+1]
// are the (x,y) coordinates of 2^i * P + C.  Set Ptable_set_constraints
// to true (exactly once in the event the same Ptable is reused in the
// same circuit) if the Ptable is part of the private input.  Set
// Ptable_fill_values to true exactly once per Ptable (again, in case it
// it reused in the same circuit).
template<typename FieldT>
class ec_scalarmul_gadget : public gadget<FieldT> {
private:
  pb_variable_array<FieldT> svec;
  std::vector<packing_gadget<FieldT> > packers;
  std::vector<ec_scalarmul_vec_gadget<FieldT> > vecgadget;

public:
  const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> s;
  const pb_variable<FieldT> Px, Py;
  const pb_variable_array<FieldT> Ptable;
  bool Ptable_set_constraints, Ptable_fill_values;

  ec_scalarmul_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &s,
              const pb_variable<FieldT> &Px,
              const pb_variable<FieldT> &Py,
              const pb_variable_array<FieldT> &Ptable,
              bool Ptable_set_constraints,
              bool Ptable_fill_values) :
    gadget<FieldT>(pb, "ec_scalarmul_gadget"),
    outx(outx), outy(outy), s(s),
    Px(Px), Py(Py), Ptable(Ptable),
    Ptable_set_constraints(Ptable_set_constraints),
    Ptable_fill_values(Ptable_fill_values)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    size_t numbits = FieldT::num_bits;
    svec.allocate(this->pb, numbits, "svec");
    packers.emplace_back(this->pb, svec, s);
    vecgadget.emplace_back(this->pb, outx, outy, svec,
        Px, Py, Ptable, Ptable_set_constraints, Ptable_fill_values);
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

  // Compute the addition table.  The addition table is a variable array
  // of length 2*numbits such that Ptable[2*i] and Ptable[2*i+1] are the
  // (x,y) coordinates of 2^i * P + C.
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

        // Compute 2^i * P + C
        FieldT twoiPCx, twoiPCy;
        ec_add_points(twoiPCx, twoiPCy, twoiPx, twoiPy,
                curveParams<FieldT>::Cx, curveParams<FieldT>::Cy);
        pb.val(Ptable[2*i]) = twoiPCx;
        pb.val(Ptable[2*i+1]) = twoiPCy;

        // Compute 2^{i+1} * P
        FieldT twoi1Px, twoi1Py;
        ec_double_point(twoi1Px, twoi1Py, twoiPx, twoiPy);
        twoiPx = twoi1Px;
        twoiPy = twoi1Py;
    }
  }
};

// Compute s*G as (outx, outy), given s as field elements.
template<typename FieldT>
class scalarmul_gadget : public gadget<FieldT> {
private:
  std::vector<ec_constant_scalarmul_gadget<FieldT> > compute_PK;

public:
  const pb_variable<FieldT> outx, outy, s;
  const int numbits;
  
  scalarmul_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &s,
              const int &numbits) :
    gadget<FieldT>(pb, "ec_pedersen_gadget"),
    outx(outx), outy(outy), s(s), numbits(numbits)
  {
	  compute_PK.emplace_back(this->pb, outx, outy, s, numbits,
            curveParams<FieldT>::Gx, curveParams<FieldT>::Gy);
  }
		
   void generate_r1cs_constraints()
    {
       compute_PK[0].generate_r1cs_constraints();
    }
   
   void generate_r1cs_witness()
    {
		//this->pb.val(s) = FieldT::random_element();
		compute_PK[0].generate_r1cs_witness();
	}
};
		


// Compute a*G + b*H as (outx, outy), given a and b as field elements.
template<typename FieldT>
class ec_pedersen_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> accinx, acciny, accmidx, accmidy, accoutx, accouty;
  std::vector<ec_constant_scalarmul_accum_gadget<FieldT> > mulgadgets;
  std::vector<ec_constant_add_gadget<FieldT> > addgadget;

public:
  const pb_variable<FieldT> outx, outy, a, b;
  const int n1, n2;

  ec_pedersen_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &outx,
              const pb_variable<FieldT> &outy,
              const pb_variable<FieldT> &a,
              const pb_variable<FieldT> &b,
              const int &n1, const int &n2) :
    gadget<FieldT>(pb, "ec_pedersen_gadget"),
    outx(outx), outy(outy), a(a), b(b), n1(n1), n2(n2)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    accinx.allocate(this->pb, "accinx");
    acciny.allocate(this->pb, "acciny");
    accmidx.allocate(this->pb, "accmidx");
    accmidy.allocate(this->pb, "accmidy");
    accoutx.allocate(this->pb, "accoutx");
    accouty.allocate(this->pb, "accouty");

    // Initialize the accumulator
    FieldT AXSx = curveParams<FieldT>::Ax;
    FieldT AXSy = curveParams<FieldT>::Ay;
    

    // Initialize the gadgets
    mulgadgets.emplace_back(this->pb, accmidx, accmidy, accinx, acciny, a, n1,
            curveParams<FieldT>::Gx, curveParams<FieldT>::Gy, AXSx, AXSy);
    mulgadgets.emplace_back(this->pb, accoutx, accouty, accmidx, accmidy, b, n2,
            curveParams<FieldT>::Hx, curveParams<FieldT>::Hy, AXSx, AXSy);
    // Subtract the accumulator excess to get the result
    addgadget.emplace_back(this->pb, outx, outy, accoutx, accouty, AXSx, -AXSy);
  }

  void generate_r1cs_constraints()
  {
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(accinx, 1, curveParams<FieldT>::Ax));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(acciny, 1, curveParams<FieldT>::Ay));
    mulgadgets[0].generate_r1cs_constraints();
    mulgadgets[1].generate_r1cs_constraints();
    addgadget[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    this->pb.val(accinx) = curveParams<FieldT>::Ax;
    this->pb.val(acciny) = curveParams<FieldT>::Ay;
    mulgadgets[0].generate_r1cs_witness();
    mulgadgets[1].generate_r1cs_witness();
    addgadget[0].generate_r1cs_witness();
  }
};

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
  //const FieldT Gx, Gy, Hx, Hy;
  const int numbits, n1, n2;
  
  std::vector<scalarmul_gadget<FieldT> > compute_PK;
  std::vector<equality_if_gadget<FieldT> > compute_s;
  std::vector<ec_pedersen_gadget<FieldT> > compute_cm;
  
  POA_gadget(protoboard<FieldT> &pb,
			 const pb_variable<FieldT> x,
			 const int numbits,
			 const int n1,
			 const int n2,
			 const pb_variable<FieldT> s,
			 const pb_variable<FieldT> cmx,
			 const pb_variable<FieldT> cmy):
		gadget<FieldT>(pb, "POA_gadget"), x(x), numbits(numbits), n1(n1), n2(n2), s(s), cmx(cmx), cmy(cmy)
		{
			// Initialize the gadget for calculating public key from private key
			PKx.allocate(pb, "PKx");
			PKy.allocate(pb, "PKy");
			compute_PK.emplace_back(this->pb, PKx, PKy, x, numbits);
			
			// Equality gadget
			Yx.allocate(pb, "Yx");
			Yy.allocate(pb, "Yy");
			compute_s.emplace_back(this->pb, PKx, PKy, Yx, Yy, s);
			
			// Pedersen commitment gadget
			bal.allocate(pb, "bal");
			t.allocate(pb, "t");
			b.allocate(pb, "b");
			compute_cm.emplace_back(this->pb, cmx, cmy, b, t, n1, n2);
		}
		
	void generate_r1cs_constraints(){
		compute_PK[0].generate_r1cs_constraints();
		
		compute_s[0].generate_r1cs_constraints();
		
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(s, bal, b));
		compute_cm[0].generate_r1cs_constraints();
	}
	
	void generate_r1cs_witness() {
		compute_PK[0].generate_r1cs_witness();
		
		this->pb.val(Yx) = this->pb.val(PKx);
		this->pb.val(Yy) = this->pb.val(PKy);
		compute_s[0].generate_r1cs_witness();
		
		//this->pb.val(bal) = FieldT::random_element();
		this->pb.val(bal) = rand() % uint64_t(pow(2,51));
		//this->pb.val(bal) = ui(mt);
		
		//uint256_t temp = rand() % uint256_t(pow(2,256));
		this->pb.val(t) = rand() % uint64_t(pow(2,256));
		//this->pb.val(t) = FieldT::random_element();
		//this-pb.val(t) = ui1(mt);
		this->pb.val(b) = this->pb.val(s) * this->pb.val(bal);
		sum_b += this->pb.val(b);
		//sum_b = long(sum_b) % 21888242871839275222246405745257275088760161411100494528458776273921456643749;
		sum_t += this->pb.val(t);
		//sum_t = sum_t % FieldT("21888242871839275222246405745257275088760161411100494528458776273921456643749");
		compute_cm[0].generate_r1cs_witness();
	}
};


template<typename FieldT>
class packing : public gadget<FieldT> {
private:
  
  std::vector<packing_gadget<FieldT> > packers;
  //std::vector<ec_constant_scalarmul_vec_gadget<FieldT> > vecgadget;

public:
 // const pb_variable<FieldT> outx, outy;
  const pb_variable<FieldT> s;
  pb_variable_array<FieldT> svec;
  //const FieldT Px, Py;
  const int numbits;

  packing(protoboard<FieldT> pb,
             // const pb_variable<FieldT> outx,
             // const pb_variable<FieldT> outy,
              const pb_variable<FieldT> s,
              const pb_variable_array<FieldT> svec,
              const int numbits):
             // const FieldT &Px, const FieldT &Py) :
    gadget<FieldT>(pb, "packing_gadget"),
    s(s), svec(svec), numbits(numbits)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    //size_t numbits = FieldT::num_bits;
   // svec.allocate(this->pb, numbits, "svec");
    packers.emplace_back(this->pb, svec, s);
   // vecgadget.emplace_back(this->pb, outx, outy, svec, Px, Py);
  }

  void generate_r1cs_constraints()
  {
    packers[0].generate_r1cs_constraints(true);
   // vecgadget[0].generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
    packers[0].generate_r1cs_witness_from_packed();
  //  vecgadget[0].generate_r1cs_witness();
  }
};


