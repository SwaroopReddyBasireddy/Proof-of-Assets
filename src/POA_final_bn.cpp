#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>

#include "ecgadget.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono; 

int main()
{
 // typedef libff::alt_bn128_pp ppT;
 // typedef libff::Fr<ppT> FieldT;

  // Initialize the curve parameters
  ppT::init_public_params();
  init_curveparams();
  
  // Create protoboard

  libff::start_profiling();
  
  ofstream outfile;
  outfile.open("outfile_10.csv");
  
   
  int i, n = 10, m = 2;
  
 //for(int l = 0; l < m; l++){
	 
  vector<double> constr_time;
  vector<double> ver_time;
  vector<long> proof_size;
  double temp_constr_time = 0.0;
  double temp_ver_time = 0.0;
  long temp_proof_size = 0;

  vector<bool> v;

 // protoboard<FieldT> pb[n+1];
  vector<FieldT> Cx_assets, Cy_assets;
  
  vector<r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> > keypair;
  vector<r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> > proof;


  for(i=0; i < n; i++){
	  srand(time(0));
	  // Create protoboard
	  protoboard<FieldT> pb;
	  pb_variable<FieldT> x, s, cmx, cmy;
	  
	  s.allocate(pb, "s");
	  cmx.allocate(pb, "cmx");
	  cmy.allocate(pb, "cmy");
	  x.allocate(pb, "x");
	  
  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(3);

  // Initialize the gadget for calculating the pedersen commitment 
	  POA_gadget<FieldT> POA(pb, x, 256, 51, 256, s, cmx, cmy);
      POA.generate_r1cs_constraints();

      const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
      const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> kp = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
	  //keypair.emplace_back(kp);
	  
	  pb.val(x) = FieldT::random_element();
	  // cout << "Computing " << pb.val(x) << "*G" << endl;
	  POA.generate_r1cs_witness();
	  Cx_assets.emplace_back(pb.val(cmx));
	  Cy_assets.emplace_back(pb.val(cmy));
	  
	  auto start = high_resolution_clock::now();
	  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> pf = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(kp.pk, pb.primary_input(), pb.auxiliary_input());
	  //proof.emplace_back(pf);
	  auto stop = high_resolution_clock::now();
	  auto duration = duration_cast<microseconds>(stop - start);
	  constr_time.emplace_back(temp_constr_time + duration.count());
	  
	  auto start1 = high_resolution_clock::now();
	  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(kp.vk, pb.primary_input(), pf);
	  v.emplace_back(verified);
	  auto stop1 = high_resolution_clock::now();
	  auto duration1 = duration_cast<microseconds>(stop1 - start1);
	  ver_time.emplace_back(temp_ver_time + duration1.count());
	  
	  
	  proof_size.emplace_back(temp_proof_size + pf.size_in_bits() + int(512));
	  temp_constr_time = constr_time[i];
	  temp_proof_size = proof_size[i];
	  temp_ver_time = ver_time[i];

	}
	
   protoboard<FieldT> pb1;
   pb_variable<FieldT> outx, outy;
   pb_variable<FieldT> a, b;
   
   outx.allocate(pb1, "outx");
   outy.allocate(pb1, "outy");
   a.allocate(pb1, "a");
   b.allocate(pb1, "b");
   
   pb1.set_input_sizes(2);
   
   ec_pedersen_gadget<FieldT> ped(pb1, outx, outy, a, b, 80, 300);
   ped.generate_r1cs_constraints();
   
   const r1cs_constraint_system<FieldT> constraint_system = pb1.get_constraint_system();

   const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> kp = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
   //keypair.emplace_back(kp);
   //Add witness values

   cout << "Prover" << endl;
  
   pb1.val(a) = sum_b;
   pb1.val(b) = sum_t;
   cout << "Computing " << pb1.val(a) << "*G + " << pb1.val(b) << "*H" << endl;

   ped.generate_r1cs_witness();
   
   Cx_assets.emplace_back(pb1.val(outx));
   Cy_assets.emplace_back(pb1.val(outy));
  
   auto start = high_resolution_clock::now();
   const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> pf = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(kp.pk, pb1.primary_input(), pb1.auxiliary_input());
   //proof.emplace_back(pf);
   auto stop = high_resolution_clock::now();
   auto duration = duration_cast<microseconds>(stop - start);
   constr_time.emplace_back(temp_constr_time + duration.count());
   proof_size.emplace_back(temp_proof_size + pf.size_in_bits() + int(512));

   cout << "Verifier" << endl;
   auto start2 = high_resolution_clock::now();
   bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(kp.vk, pb1.primary_input(), pf);
   v.emplace_back(verified);
   auto stop2 = high_resolution_clock::now();
   auto duration2 = duration_cast<microseconds>(stop2 - start2);
   ver_time.emplace_back(temp_ver_time + duration2.count());
   temp_ver_time = ver_time[n];
   
   
   auto start3 = high_resolution_clock::now();
   FieldT Cx_sum = 0, Cy_sum = 0, tempx = Cx_assets[0], tempy = Cy_assets[0];
   for(size_t k = 1; k < n; k++){
	 // 
	  ec_add_points(Cx_sum, Cy_sum, tempx, tempy, Cx_assets[k], Cy_assets[k]);
	  //Cx_sum += Cx_assets[k];
	  //Cy_sum += Cy_assets[k];
	  tempx = Cx_sum;
	  tempy = Cy_sum;
	      }
	  Cx_sum = tempx;
	  Cy_sum = tempy;

  
  if((Cx_sum == Cx_assets[n]) && (Cy_sum == Cy_assets[n]))
		cout << "Sum of the assets are proved" << "\n";
  else
		cout << "Commitment doesn't satisfy the sum of the commitments" << "\n";
	
  auto stop3 = high_resolution_clock::now();
  auto duration3 = duration_cast<microseconds>(stop3 - start3);
  ver_time[n] += duration3.count();  
  
  //cout << "Primary (public) input \n " << pb[n].primary_input() << "\n\n";
  //cout << "Sum of the commitments \n" << Cx_sum << "\n" << Cy_sum << "\n\n";
  //cout << "n-th commitment \n" << Cx_assets[n] << "\n" << Cy_assets[n] << endl;
  
  cout << "\n" << sum_b << " " << sizeof(sum_b) << "\n";
  cout << sum_t << " " << sizeof(sum_t) << "\n";

   
  	  
   for(size_t p = 0; p < n+1; p++)
  		cout << constr_time[p]/1e6 << ", " << proof_size[p]/1e6 << ", " << ver_time[p]/1e6 << ", " << v[p] << "\n" << endl;
 // outfile << constr_time[n] << " " << ver_time[n] << " " << proof_size[n] << "\n";

  outfile.close();
	//n = n*10;
//}
  
  //// Read the data file
  //vector<string> row;
  //vector<string> constr, ver, proof_sz;
  //string line, word, temp;
  //double x1, x2;
  //long x3;
  //ifstream fin("outfile_10.csv");
  ////int k = 0;
  //while(!fin.eof())
	  //{
		//////cout << k << "\n";
		//row.clear();
		//////cout << temp << endl;
		////getline(fin, line);
		
		////stringstream s(line);
		//////cout << s << "\n";
		////while (fin >> word) {
		////   row.push_back(word);
        ////}
        //////cout << row << "\n";
        //fin >> x1;
        //fin >> x2;
        //fin >> x3;
        //constr.push_back(x1);
        //ver.push_back(x2);
        //proof_sz.pushback(x3);
        //////cout << row << endl;
        ////keys.push_back(row);
        ////k += 1;
	//}
	
	//for(int k = 0; k < sizeof(constr); k++){
	  //cout << constr[k] << " " << ver[k] << " " << proof_sz[k] << "\n";
	   //}
	

  return 0;
}
