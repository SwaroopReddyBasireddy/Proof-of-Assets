#include <stdlib.h>
#include <iostream>
#include <fstream>

using namespace std;
//void write_in_file( ofstream &fout, int start){
   //for(int i = 1; i <= 128; i++){
     //fout<<start <<"\t";
     //start+=8;
   //}
   //fout<<"\n";
//}
int main(){
  ofstream fout;
  fout.open("out.csv");
  for(int i=1;i<=8;i++){
   // write_in_file(fout,i);
	  fout << i << " " << i+1 << endl;
	  //fout << i+1 << endl;
  }
  fout.close();
 }
