#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cmath>
#include <ctime>
#include <chrono>


#include "scalarmul_gadget.hpp"
//#include "ecgadget.hpp"
#include "scalarmul.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono;

int main()
{
  // Initialize the curve parameters

  default_r1cs_gg_ppzksnark_pp::init_public_params();
  //init_curveparams();

  typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;
  
  // Create protoboard

  libff::start_profiling();

  cout << "Keypair" << endl;
  
  ofstream keyfile;
  keyfile.open("inputfile.csv");
  //keyfile << "SK" << " " << "PKx" << " " << "PKy" << " " << "balance" << " " << "b_i" << "\n";
  
  double temp_constr_time = 0;
  vector<double> constr_time;
  int n = 1, m = 4;
  for(size_t i = 0; i < n ; i++){ 

  protoboard<FieldT> pb;
  pb_variable<FieldT> outx, outy;
  pb_variable<FieldT> s, b;

  // The constant base point P
  //const FieldT Px = FieldT(0);
  //const FieldT Py = FieldT("11977228949870389393715360594190192321220966033310912010610740966317727761886");

  const FieldT Px = FieldT("55066263022277343669578718895168534326250603453777594175500187360389116729240");
  const FieldT Py = FieldT("32670510020758816978083085130507043184471273380659243275938904335757337482424");  
  
  // Allocate variables

  outx.allocate(pb, "outx");
  outy.allocate(pb, "outy");
  s.allocate(pb, "s");
  b.allocate(pb, "b");

  // This sets up the protoboard variables so that the first n of them
  // represent the public input and the rest is private input

  pb.set_input_sizes(3);

  // Initialize the gadget
  ec_constant_scalarmul_gadget<FieldT> sm(pb, outx, outy, s, 252, Px, Py);
  sm.generate_r1cs_constraints();

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

  // Add witness values

  
  cout << "Prover" << endl;
  
  pb.val(s) = FieldT::random_element();
  cout << "Computing " << pb.val(s) << "*G" << endl;

  sm.generate_r1cs_witness();

  auto start = high_resolution_clock::now();
  const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  constr_time.emplace_back(temp_constr_time + duration.count());
  cout << "Verifier" << endl;

  bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input length: " << pb.auxiliary_input().size() << endl;
////cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;
  //cout << "Address of private key" << &(pb.val(s)) << "*G" << endl;
  //cout << "Address of public key" << &(pb.primary_input()[0]) << "*G" << endl;
  //cout << "Address of public key" << &(pb.primary_input()[1]) << "*G" << endl;
  //cout << "Address of pb" << &(pb) << "*G" << endl;

  //ofstream pkfile("pk_scalarmul");
  //pkfile << keypair.pk;
  //pkfile.close();
  //ofstream vkfile("vk_scalarmul");
  //vkfile << keypair.vk;
  //vkfile.close();
  //ofstream pffile("proof_scalarmul");
  //pffile << proof;
  //pffile.close();

  srand(time(0));
  uint64_t bal = rand() % int(pow(2,51));
  pb.val(b) = FieldT::random_element();
  //cout << pb.val(s) << "*G" << " = (" << pb.val(outx) << ", " << pb.val(outy) << ")" << endl;
  keyfile << pb.val(s) << " " << pb.val(outx) << " " << pb.val(outy) << " " << bal << " " << pb.val(b) << "\n";
  temp_constr_time = constr_time[i];
  
  }
  keyfile.close();
  
  //// Read the data file
  //vector<string> row;
  //vector<vector<string>> keys;
  //string line, word, temp;
  //ifstream fin("inputfile.csv");
  //int k = 0;
  //while(!fin.eof())
	//{
		////cout << k << "\n";
		//row.clear();
		////cout << temp << endl;
		//getline(fin, line);
		
		//stringstream s(line);
		////cout << s << "\n";
		//while (s >> word) {
		
            //// add all the column data
            //// of a row to a vector
            //row.push_back(word);
        //}
        ////cout << row << "\n";
       //// size_t roll2 = stoi(row[0]);
  
        ////cout << row << endl;
        //keys.push_back(row);
        //k += 1;
	//}
	
		//cout << keys.size() << endl;
		//cout << keys[0].size() << endl;
      //for(size_t i = 0; i < n; i++) {
        //for (size_t j = 0; j < keys[0].size(); j++)
			//{
				//cout << keys[i][j] << "\n";
			//}
		//}
	 for(size_t i = 0; i < n; i++)
		cout << constr_time[i] << "\n";
  return 0;
}
