#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>

#include "ecc_gadget.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono; 


int main() {
  // Initialize the curve parameters
  ppT::init_public_params();
  init_curveparams();
  
  // Create protoboard

  libff::start_profiling();

  ofstream constr_file;
  constr_file.open("constr_time.csv");
  
  ofstream ver_file;
  ver_file.open("ver_time.csv");
  ofstream proof_file;
  proof_file.open("proof_size.csv");
  
  int i, n = 10, m = 2;
  vector<double_t> constr_time;
  vector<double_t> ver_time;
  vector<long> proof_size;
  double temp_constr_time = 0.0;
  double temp_ver_time = 0.0;
  long temp_proof_size = 0;
  
 // for(int l = 0; l < m; l++){
  
  protoboard<FieldT> pb[n+1];
  vector<FieldT> Cx_assets, Cy_assets;
  //FieldT Cx_sum = 0 , Cy_sum = 0, tempx = Cx_assets[0], tempy = Cy_assets[0];
  
  vector<r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> > keypair;
  vector<r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> > proof;
  
  for(i=0; i < n; i++){
	  srand(time(0));
	  // Create protoboard
	  //protoboard<FieldT> pb;
	  pb_variable<FieldT> x, s, cmx, cmy;
	  
	  s.allocate(pb[i], "s");
	  cmx.allocate(pb[i], "cmx");
	  cmy.allocate(pb[i], "cmy");
	  x.allocate(pb[i], "x");
	  
	  pb[i].set_input_sizes(3);
	  
	  // Initialize the gadget for calculating the pedersen commitment 
	  POA_gadget<FieldT> POA(pb[i], x, 256, 51, 256, s, cmx, cmy);
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
      
   pb_variable<FieldT> outx, outy;
   pb_variable<FieldT> a, b;
   
   outx.allocate(pb[n], "outx");
   outy.allocate(pb[n], "outy");
   a.allocate(pb[n], "a");
   b.allocate(pb[n], "b");
   
   pb[n].set_input_sizes(2);
   
   ec_pedersen_gadget<FieldT> ped(pb[n], outx, outy, a, b, 128, 512);
   ped.generate_r1cs_constraints();
   
   const r1cs_constraint_system<FieldT> constraint_system = pb[n].get_constraint_system();

   const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> kp = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
   keypair.emplace_back(kp);
   //Add witness values

   cout << "Prover" << endl;
  
   pb[i].val(a) = sum_b;
   pb[i].val(b) = sum_t;
   cout << "Computing " << pb[n].val(a) << "*G + " << pb[n].val(b) << "*H" << endl;

   ped.generate_r1cs_witness();
   
   Cx_assets.emplace_back(pb[n].val(outx));
   Cy_assets.emplace_back(pb[n].val(outy));
  
   auto start = high_resolution_clock::now();
   const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> pf = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(kp.pk, pb[n].primary_input(), pb[n].auxiliary_input());
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
   
   auto start2 = high_resolution_clock::now();
   FieldT Cx_sum = 0, Cy_sum = 0, tempx = Cx_assets[0], tempy = Cy_assets[0];
   for(size_t k = 1; k < n; k++){
	 // 
	  ec_add_points(Cx_sum, Cy_sum, tempx, tempy, Cx_assets[k], Cy_assets[k]);
	  //Cx_sum += Cx_assets[k];
	  //Cy_sum += Cy_assets[k];
	  tempx = Cx_sum;
	  tempy = Cy_sum;
	      }
	//  Cx_sum = tempx;
	//  Cy_sum = tempy;

  
  if((Cx_sum == Cx_assets[n]) && (Cy_sum == Cy_assets[n]))
		cout << "Sum of the assets are proved" << "\n";
  else
		cout << "Commitment doesn't satisfy the sum of the commitments" << "\n";
	
  auto stop2 = high_resolution_clock::now();
  auto duration2 = duration_cast<microseconds>(stop2 - start2);
  ver_time[n] += duration2.count();  
  
  cout << "Primary (public) input \n " << pb[n].primary_input() << "\n\n";
  cout << "Sum of the commitments \n" << Cx_sum << "\n" << Cy_sum << "\n\n";
  //cout << "n-th commitment \n" << Cx_assets[n] << "\n" << Cy_assets[n] << endl;
  
  cout << "\n" << sum_b << " " << sizeof(sum_b) << "\n";
  cout << sum_t << " " << sizeof(sum_t) << "\n";

   
  	  
   for(size_t p = 0; p < n+1; p++)
  		cout << constr_time[p]/1e6 << ", " << proof_size[p]/1e6 << ", " << ver_time[p]/1e6 << ", " << v[p] << "\n" << endl;
  constr_file << constr_time[n] << "\n";
  ver_file << ver_time[n] << "\n";
  proof_file << proof_size[n] << "\n";
 // n *= 10;
//}

constr_file.close();
ver_file.close();
proof_file.close();

//// Read the data file
  //ifstream fin1("constr_time.csv");
  //// Read the data file
  //vector<double_t> row;
  //vector<double_t> constr;
  //double_t line;
  
  //while(!fin1.eof())
	//{
		//row.clear();
		//fin1 >> line;
		////cout << line << "\n";
		//constr.push_back(line);
     //}
  
//// Read the data file
  //ifstream fin2("ver_time.csv");
  //// Read the data file
  ////vector<double_t> row;
  //vector<double_t> ver;
  ////double_t line;
  
  //while(!fin2.eof())
	//{
		//row.clear();
		//fin2 >> line;
		////cout << line << "\n";
		//ver.push_back(line);
     //}
     
   //// Read the data file
  //ifstream fin3("proof_size.csv");
  //// Read the data file
  //vector<long> row1;
  //vector<long> proof_sz;
  //long line1;
  
  //while(!fin3.eof())
	//{
		//row1.clear();
		//fin3 >> line1;
		////cout << line << "\n";
		//proof_sz.push_back(line1);
     //}

  //for(int k = 0; k < m; k++){
	  //cout << constr[k] << " " << ver[k] << " " << proof_sz[k] << "\n";
	   //}
   return 0;
}

	  


