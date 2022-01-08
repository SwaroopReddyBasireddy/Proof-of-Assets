#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>

using namespace boost::multiprecision;
using namespace boost::random;


uint256_t rand_gen(){
	typedef independent_bits_engine<mt19937, 256, uint256_t> generator_type;
   generator_type gen;
   //
   // Generate some values:
   //
   //std::cout << std::hex << std::showbase;
   //for(unsigned i = 0; i < 10; ++i)
    //  std::cout << gen() << std::endl;
    return gen();
}
