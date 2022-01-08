#include <thread>
#include <iostream>
#include <string>

void run(std::string threadName) {
  for (int i = 0; i < 10; i++) {
    std::string out = threadName + std::to_string(i) + "\n";
    std::cout << out;
  }
}

int main() {
  unsigned int c = std::thread::hardware_concurrency();
  std::cout << " number of cores: " << c << "\n";
  std::thread tA(run, "A");
  std::thread tB(run, "\tB");
  std::thread tC(run, "\t\tC");
  std::thread tD(run, "\t\t\tD");
  tA.join();
  tB.join();
  tC.join();
  tD.join();
}
