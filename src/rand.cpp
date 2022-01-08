#include <iostream>
#include <vector>
#include <cmath>
#include <ctime>
#include "uint256_t.h"
using std::string; 

int main()
{
  std::vector <string> some_vector {"pizza", "burger", "fries", "chicken"}; 
  
  srand(time(0));
  //unsigned long long int random = rand() % (unsigned long long int)(pow(2,51)); 
  uint256_t x = rand() % uint256_t(pow(2,256)-1);
  std::cout << random << " " << sizeof(random) << "\n"; 
 
  
  return 0;
}
