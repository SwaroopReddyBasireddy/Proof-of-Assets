#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <string.h>
#include <string>
#include <math.h>

#include "POA.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono; 

int main()
{
  // Read the data file
  vector<string> row;
  string line, word, temp;
  ifstream fin("inputfile.csv");
  int n = 10;
  while(!fin.eof())
	{
		//cout << k << "\n";
		row.clear();
		//cout << temp << endl;
		getline(fin, line);
		
		stringstream s(line);
		//cout << s << "\n";
		while (s >> word) {
		
            // add all the column data
            // of a row to a vector
            row.push_back(word);
        }
        //cout << row << "\n";
       // size_t roll2 = stoi(row[0]);
  
        //cout << row << endl;
        keys.push_back(row);
	}
	
		cout << keys.size() << endl;
		cout << keys[0].size() << endl;
      //for(size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < keys[0].size(); j++)
			{
				cout << keys[0][j] << "\n";
			}
		//}
	
  // Initialize the curve parameters

  default_r1cs_gg_ppzksnark_pp::init_public_params();
  
  typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;
  
  libff::start_profiling();

  cout << "Keypair" << endl;
  
  // The constant generator point G
  const FieldT Gx = FieldT("55066263022277343669578718895168534326250603453777594175500187360389116729240");
  const FieldT Gy = FieldT("32670510020758816978083085130507043184471273380659243275938904335757337482424");
  
  // The constant generator point H
  const FieldT Hx = FieldT("110263267274902958436328867164224792406782446797825613715583521163553034287998");
  const FieldT Hy = FieldT("97481362542956814441892532371059707785205253773827785916951659669046127408432");
  
  // The constant generator point G
  //const FieldT Gx = FieldT("0");
  //const FieldT Gy = FieldT("11977228949870389393715360594190192321220966033310912010610740966317727761886");
  
  // The constant generator point H
  //const FieldT Hx = FieldT("1");
  //const FieldT Hy = FieldT("21803877843449984883423225223478944275188924769286999517937427649571474907279");
  
  vector<double_t> constr_time;
  vector<double_t> ver_time;
  vector<size_t> proof_size;
  double temp_constr_time = 0.0;
  double temp_ver_time = 0.0;
  size_t temp_proof_size = 0;
  
  protoboard<FieldT> pb[n+1];
  vector<FieldT> Cx_assets, Cy_assets;
  
  vector<r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> > keypair;
  vector<r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> > proof;
  int i;
  for( i = 0; i < n; i++){
	  // Create protoboard
	  //protoboard<FieldT> pb;
	  pb_variable<FieldT> x, s, cmx, cmy;
	  
	  s.allocate(pb[i], "s");
	  cmx.allocate(pb[i], "cmx");
	  cmy.allocate(pb[i], "cmy");
	  x.allocate(pb[i], "x");
	  
	  pb[i].set_input_sizes(3);
	  
	  // Initialize the gadget for calculating the pedersen commitment 
	  POA_gadget<FieldT> POA(pb[i], Gx, Gy, Hx, Hy, x, s, cmx, cmy);
	  
	  POA.generate_r1cs_constraints();
	  
	  const r1cs_constraint_system<FieldT> constraint_system = pb[i].get_constraint_system();
	  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> kp = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
	  keypair.emplace_back(kp);
	  
	  pb[i].val(x) = FieldT::random_element();
	  // cout << "Computing " << pb.val(x) << "*G" << endl;
	  POA.generate_r1cs_witness();
	  Cx_assets.emplace_back(pb[i].val(cmx));
	  Cy_assets.emplace_back(pb[i].val(cmy));
	  
	  auto start = high_resolution_clock::now();
	  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> pf = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(kp.pk, pb[i].primary_input(), pb[i].auxiliary_input());
	  proof.emplace_back(pf);
	  auto stop = high_resolution_clock::now();
	  auto duration = duration_cast<microseconds>(stop - start);
	  constr_time.emplace_back(temp_constr_time + duration.count());
	  
	  
	  proof_size.emplace_back(temp_proof_size + proof[i].size_in_bits() + int(512));
	  temp_constr_time = constr_time[i];
	  temp_proof_size = proof_size[i];
	  }
	  
	  cout << sum_b << " " << sizeof(sum_b) << "\n";
	  cout << sum_t << " " << sizeof(sum_t) << "\n";
	  
	  //protoboard<FieldT> pb;
	  pb_variable<FieldT> outx, outy, out_ax, out_ay, out_bx, out_by;
	  pb_variable<FieldT> a, b;
  
	  // Allocate variables

	  outx.allocate(pb[i], "outx");
	  outy.allocate(pb[i], "outy");
	  out_ax.allocate(pb[i], "out_ax");
	  out_ay.allocate(pb[i], "out_ay");
	  out_bx.allocate(pb[i], "out_bx");
	  out_by.allocate(pb[i], "out_by");
	  a.allocate(pb[i], "a");
	  b.allocate(pb[i], "b");

	 // This sets up the protoboard variables so that the first n of them
	 // represent the public input and the rest is private input

	 pb[i].set_input_sizes(2);

    // Initialize the gadget
     ec_constant_scalarmul_gadget<FieldT> sm1(pb[i], out_ax, out_ay, a, 256, Gx, Gy);
     ec_constant_scalarmul_gadget<FieldT> sm2(pb[i], out_bx, out_by, b, 256, Hx, Hy);
     ec_add_gadget<FieldT> adder(pb[i], outx, outy, out_ax, out_ay, out_bx, out_by);
 
	 sm1.generate_r1cs_constraints();
	 sm2.generate_r1cs_constraints();
	 adder.generate_r1cs_constraints();
 
 //ec_pedersen_gadget<FieldT> ped(pb, outx, outy, a, b, Gx, Gy, Hx, Hy);
 //ped.generate_r1cs_constraints();
  
  const r1cs_constraint_system<FieldT> constraint_system = pb[i].get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> kp = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
  keypair.emplace_back(kp);
  // Add witness values

  cout << "Prover" << endl;
  
  pb[i].val(a) = sum_b;
  pb[i].val(b) = sum_t;
  cout << "Computing " << pb[i].val(a) << "*G + " << pb[i].val(b) << "*H" << endl;

  //ped.generate_r1cs_witness();
  sm1.generate_r1cs_witness();
  sm2.generate_r1cs_witness();
  adder.generate_r1cs_witness();
  
  Cx_assets.emplace_back(pb[i].val(outx));
  Cy_assets.emplace_back(pb[i].val(outy));
  
  auto start = high_resolution_clock::now();
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> pf = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(kp.pk, pb[i].primary_input(), pb[i].auxiliary_input());
  proof.emplace_back(pf);
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  constr_time.emplace_back(temp_constr_time + duration.count());
  proof_size.emplace_back(temp_proof_size + proof[i].size_in_bits() + int(512));
  
  
  cout << "Verifier" << endl;
  vector<bool> v;
  for(int j = 0; j < n+1; j++){
	  auto start1 = high_resolution_clock::now();
	  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair[j].vk, pb[j].primary_input(), proof[j]);
	  v.emplace_back(verified);
	  auto stop1 = high_resolution_clock::now();
	  auto duration1 = duration_cast<microseconds>(stop1 - start1);
	  ver_time.emplace_back(temp_ver_time + duration1.count());
	  temp_ver_time = ver_time[j];
  }
  
  FieldT Cx_sum , Cy_sum, tempx = Cx_assets[0], tempy = Cy_assets[0];
  for(size_t k = 1; k < n; k++){
	 // Cx_sum = 0; Cy_sum = 0;
	  ec_add_points(Cx_sum, Cy_sum, tempx, tempy, Cx_assets[k], Cy_assets[k]);
	  tempx = Cx_sum;
	  tempy = Cy_sum;
	  //Cx_sum += Cx_assets[k];
	  //Cy_sum += Cy_assets[k];
  }
  
  cout << "Primary (public) input \n " << pb[i].primary_input() << "\n\n";
  cout << "Sum of the commitments \n" << Cx_sum << "\n" << Cy_sum << "\n\n";
  cout << "n th commitment \n" << Cx_assets[n] << "\n" << Cy_assets[n] << endl;
   
  if((Cx_sum == Cx_assets[n]) && (Cy_sum == Cy_assets[n]))
		cout << "Sum of the assets are proved" << "\n";
  else
		cout << "Commitment doesn't satisfy the sum of the commitments" << "\n";
	  
	  
   for(size_t j = 0; j < n+1; j++)
		cout << constr_time[j]/1e6 << ", " << proof_size[j]/1e6 << ", " << ver_time[j]/1e6 << ", " << v[j] << "\n" << endl;
  
  
  	  return 0;
}
