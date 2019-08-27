
// 'crypdev' is a tool (CLI/REPL) for testing and interacting with crypto functions

// standard includes
#include <iostream>

// libcrypton includes
#include "ModuleCryptoDev.hpp"

using namespace std;

using namespace libcrypton;

int
main(int argc, char* argv[])
{
   ModuleCryptoDev cdev;
   if (argc == 2) {
      std::string param1 = argv[1];
      if (param1 == string("-v")) {
         std::cout << "version " << cdev.version() << std::endl;
         return 0;
      }
      std::cerr << "not enough parameters... use -f \"FILE\" or -c \"COMMANDS;COMMANDS\" (semi-comma separated)" << std::endl;
      return 1;
   }

   if (argc == 3) {

      std::string param1 = argv[1];
      std::string param2 = argv[2];

      if (param1 == string("-f")) {
         // load from file (line by line)
         std::ifstream infile(param2);

         double spentTime = 0;
         // execute from file (non-verbose)
         return cdev.executeFromStream(infile, cout, false, spentTime);
      }

      if (param1 == string("-c")) {

         // load command list
         std::istringstream ss(param2);
         double spentTime = 0;
         // execute from file (non-verbose)
         return cdev.executeFromStream(ss, cout, false, spentTime);
      }

      std::cerr << "unrecognized option: '" << param1 << "'" << std::endl;
      return 1;
   }

   double spentTime = 0;
   // interactive mode (verbose = true)
   cdev.executeFromStream(cin, cout, true, spentTime);

   return 0;
}
