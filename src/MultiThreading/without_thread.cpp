#include <thread>
#include <iostream>
#include <array>
#include <stdio.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

//void ThreadFunction( int x, string s )
//{
   //cout << "thread started: " << x << " " << s << endl;
//}

//int main()
//{
	////array<thread, 4> threads;
	
	////cout << threads.size() << endl;
	
	//auto start = high_resolution_clock::now();
    //for( int i = 0; i < 100; ++i )
		//{		
		   //ThreadFunction( i, "test" );
	 //}
	
	//auto stop = high_resolution_clock::now();
    //auto duration = duration_cast<microseconds>(stop - start);
    //cout << "Total duration:" << duration.count() << " microseconds" << endl;
    //return 0;
//}

int update(int x) {
	for(size_t i = 0; i < 1000; i++)
		++x;
	return x;
}

int main()
{
  int a = 0, b = 0, c = 0, d = 0;
  auto start = high_resolution_clock::now();
  //for (int i = 0;i < 8; i++)
  a = update(a);
  b = update(b);
  c = update(c);
  d = update(d);
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  cout << "Total duration:" << duration.count() << " microseconds" << endl;
  cout << a << " " << b << " " << c << " " << d << endl ;
  return 0;
}

