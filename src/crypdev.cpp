
// 'crypdev' is a tool (CLI/REPL) for testing and interacting with crypto functions

// standard includes
#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip> // fill zero for hex
#include <iostream>
#include <sstream>

// libcrypton includes
#include "Crypto.h"

using namespace std;

namespace libcrypton {

vbyte
parseTextBytes(string input)
{
   // remove spaces
   chelper::trim(input);

   if (input.size() < 2) {
      cerr << "malformed input, returning empty bytes" << endl;
      return vbyte(0);
   }

   if (input[0] == '"') {
      if (input[input.length() - 1] != '\"') {
         std::cerr << "failed to parse string (spaces not allowed)" << std::endl;
         return vbyte(0);
      }

      input = input.substr(1, input.length() - 2);
      //cout << "input now is '" << input << "'" << endl;
      // convert to hex
      input = chelper::ASCIIToHexString(input);
      //cout << "converted ascii to hex: '" << input << "'" << endl;
   }

   // removing prefix '0x' if existing
   if ((input[0] == '0') && (input[1] == 'x')) {
      input = input.substr(2, input.length());
   }

   return chelper::HexToBytes(input);
}

// finish useful stuff... move to some class!

string cryptest_curve = "secp256r1";
string cryptest_hash = "sha256";

bool
execHelp(istream& is, bool verbose)
{
   cout << endl;
   if (verbose)
      cout << "'help' command options: [ ]" << endl;
   cout << "existing commands are: " << endl;

   cout << "set [ ecc hash ] [ secp256r1 | sha256 ]" << endl;
   cout << "gen [ ECC_TYPE ] [ keypair pubkey privkey ] [ compressed uncompressed ] [ PRIVATE_KEY ]" << endl;
   cout << "hash [ hash160 hash256 sha256 ripemd160 none ] [ TEXT_OR_BYTES ]" << endl;
   cout << "bytes [ reverse length ] [ TEXT_OR_BYTES ]" << endl;
   cout << "sign [ ECC_TYPE ] [ PRIVATE_KEY ] [ HASH_TYPE ] [ TEXT_OR_BYTES ] " << endl;
   cout << "verify [ ECC_TYPE ] [ PUBLIC_KEY ] [ SIGNATURE ] [ HASH_TYPE ] [ TEXT_OR_BYTES ]  " << endl;
   cout << "rand [ BYTE_COUNT ] " << endl;
   cout << "show [ engine ]" << endl;

   return true;
}

bool
execSet(istream& is, bool verbose)
{

   if (verbose)
      cout << "'set' command options: [ ecc hash ]" << endl;
   string type;
   is >> type;

   if (type == "ecc") {
      if (verbose)
         cout << "'ecc' options: [ secp256r1 ]" << endl;
      string curve;
      is >> curve;
      if (curve == "secp256r1") {
         cryptest_curve = curve;
         // output
         cout << "DEFAULT ECC SET TO '" << cryptest_curve << "'" << endl;
         return true;
      }
      return false;
   }

   if (type == "hash") {
      if (verbose)
         cout << "'hash' options: [ sha256 ]" << endl;
      string shash;
      is >> shash;
      if (shash == "sha256") {
         cryptest_hash = shash;
         //output
         cout << "DEFAULT HASH SET TO '" << cryptest_hash << "'" << endl;
         return true;
      }
      return false;
   }

   return false;
}

bool
execHash(istream& is, bool verbose)
{
   if (verbose)
      cout << "'hash' command options: [ hash160 hash256 sha256 ripemd160 none ]" << endl;
   string type;
   is >> type;

   Crypto crypto;

   if (type == "hash160") {
      if (verbose)
         cout << "'hash160' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);
      vbyte bytes = parseTextBytes(tbytes);
      if (bytes.size() == 0) // check if parsed correctly
         return false;
      vbyte hash = crypto.Hash160(bytes);
      if (verbose)
         cout << "hash: ";
      // output
      cout << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "hash256") {
      if (verbose)
         cout << "'hash256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);
      vbyte bytes = parseTextBytes(tbytes);
      if (bytes.size() == 0) // check if parsed correctly
         return false;
      vbyte hash = crypto.Hash256(bytes);
      if (verbose)
         cout << "hash: ";
      //output
      cout << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "sha256") {
      if (verbose)
         cout << "'sha256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);
      vbyte bytes = parseTextBytes(tbytes);
      if (bytes.size() == 0) // check if parsed correctly
         return false;
      vbyte hash = crypto.Sha256(bytes);
      if (verbose)
         cout << "hash: ";
      // output
      cout << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "ripemd160") {
      if (verbose)
         cout << "'ripemd160' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);
      vbyte bytes = parseTextBytes(tbytes);
      if (bytes.size() == 0) // check if parsed correctly
         return false;
      vbyte hash = crypto.RIPEMD160(bytes);
      if (verbose)
         cout << "hash: ";
      // output
      cout << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "none") {
      if (verbose)
         cout << "'none' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);
      vbyte hash = parseTextBytes(tbytes);
      if (hash.size() == 0) // check if parsed correctly
         return false;
      if (verbose)
         cout << "hash: ";
      // output
      cout << chelper::ToHexString(hash) << endl;
      return true;
   }

   return false;
}

bool
execShow(istream& is, bool verbose)
{
   if (verbose)
      cout << "'show' command options: [ engine ]" << endl;
   string type;
   is >> type;

   if (type == "engine") {
      if (verbose)
         cout << "'engine' options: [ ]" << endl;
      Crypto crypto;
      if (verbose)
         cout << "libcrypton engine: ";
      // output
      cout << crypto.GetEngine() << endl;
      return true;
   }

   return false;
}

bool
execGen(istream& is, bool verbose)
{
   if (verbose)
      cout << "'gen' command options: [ ECC_TYPE ] [ keypair pubkey privkey ]" << endl;

   string ecc;
   is >> ecc;
   // ignoring 'ecc' right now.. assuming 'secp256r1'

   string type;
   is >> type;

   if (type == "keypair") {
      if (verbose)
         cout << "'keypair' options: [ ]" << endl;

      Crypto crypto;

      // creating private/public key pair (random each test)
      vbyte mypubkey;
      vbyte myprivkey = crypto.GenerateKeyPair(mypubkey);

      if (verbose)
         cout << "public key (compressed format): ";
      // output
      cout << chelper::ToHexString(mypubkey) << endl;
      if (verbose)
         cout << "private key: ";
      // output
      cout << chelper::ToHexString(myprivkey) << endl;

      return true;
   }

   if (type == "pubkey") {
      if (verbose)
         cout << "'pubkey' options: [ compressed uncompressed ]" << endl;

      string pubtype;
      is >> pubtype;

      bool compressed;
      if (pubtype == "compressed")
         compressed = true;
      else
         compressed = false;

      string tbytes;
      is >> tbytes;
      vbyte privkey = parseTextBytes(tbytes);

      if (privkey.size() != 32) // secp256r1
      {
         cerr << "ERROR: expected private key of size 32 bytes for secp256r1" << endl;
         return false;
      }

      Crypto crypto;

      // creating private/public key pair (random each test)
      vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(privkey, compressed);

      if (verbose)
         cout << "public key: " << chelper::ToHexString(mypubkey) << endl;

      return true;
   }

   if (type == "privkey") {
      if (verbose)
         cout << "'privkey' options: [ ]" << endl;

      Crypto crypto;

      vbyte privkey = crypto.RandBytes(32); // secp256r1

      if (verbose)
         cout << "private key: ";
      // output
      cout << chelper::ToHexString(privkey) << endl;

      return true;
   }

   return false;
}

bool
execBytes(istream& is, bool verbose)
{
   if (verbose)
      cout << "'bytes' command options: [ reverse length ]" << endl;
   string type;
   is >> type;

   if (type == "reverse") {
      if (verbose)
         cout << "'reverse' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      std::getline(is, tbytes);

      vbyte bytes = parseTextBytes(tbytes);
      std::reverse(std::begin(bytes), std::end(bytes));
      if (verbose)
         cout << "reversed bytes: ";
      // output
      cout << chelper::ToHexString(bytes) << endl;
      return true;
   }

   if (type == "length") {
      if (verbose)
         cout << "'length' options: [ TEXT_OR_BYTES ]" << endl;

      string tbytes;
      std::getline(is, tbytes);

      vbyte bytes = parseTextBytes(tbytes);
      if (verbose)
         cout << "length: ";
      // output
      cout << bytes.size() << endl;
      return true;
   }

   return false;
}

bool
execSign(istream& is, bool verbose)
{
   if (verbose)
      cout << "'sign' command options: [ ECC_TYPE ] [ PRIVATE_KEY ] [ HASH_TYPE ] [ TEXT_OR_BYTES ]" << endl;

   string ecc;
   is >> ecc;
   // ignoring 'ecc' right now.. assuming 'secp256r1'

   string sprivkey;
   is >> sprivkey;
   vbyte privkeybytes = parseTextBytes(sprivkey);

   if (privkeybytes.size() != 32) {
      std::cerr << "ERROR: private key should have 32 bytes for secp256r1" << std::endl;
      return false;
   }

   string htype;
   is >> htype;

   string smessage;
   std::getline(is, smessage);
   vbyte msgbytes = parseTextBytes(smessage);

   Crypto crypto;

   vbyte hashbytes;
   if (htype == "hash")
      htype = cryptest_hash; // default hash 'sha256'
   if (htype == "sha256")
      hashbytes = crypto.Sha256(msgbytes);
   else {
      if (verbose)
         std::cout << "Assuming hash type = 'none'" << endl;
      hashbytes = msgbytes;
   }

   if (hashbytes.size() != 32) {
      std::cerr << "ERROR: hash should have 32 bytes for secp256r1" << std::endl;
      return false;
   }

   // get compressed pubkey
   vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(privkeybytes, true);

   vbyte sig = crypto.SignData(hashbytes, privkeybytes, mypubkey);

   if (verbose)
      cout << "signature: ";
   // output
   cout << chelper::ToHexString(sig) << endl;
   return true;
}

bool
execVerify(istream& is, bool verbose)
{
   if (verbose)
      cout << "'verify' command options: [ ECC_TYPE ] [ PUBLIC_KEY ] [ SIGNATURE ] [ HASH_TYPE ]  [ TEXT_OR_BYTES ] " << endl;

   string ecc;
   is >> ecc;
   // ignoring 'ecc' right now.. assuming 'secp256r1'

   string spubkey;
   is >> spubkey;
   vbyte pubkeybytes = parseTextBytes(spubkey);

   if (pubkeybytes.size() != 33) {
      std::cerr << "ERROR: public key (compressed) should have 33 bytes for secp256r1" << std::endl;
      return false;
   }

   string ssig;
   is >> ssig;
   vbyte sigbytes = parseTextBytes(ssig);

   string htype;
   is >> htype;

   string smessage;
   std::getline(is, smessage);
   vbyte msgbytes = parseTextBytes(smessage);

   Crypto crypto;

   vbyte hashbytes;
   if (verbose)
      std::cout << "Assuming hash type = 'sha256'" << endl;
   hashbytes = msgbytes;

   if (sigbytes.size() != 64) {
      std::cerr << "ERROR: signature should have 64 bytes for secp256r1" << std::endl;
      return false;
   }

   // TODO: pass hash type option inside this function
   bool b = crypto.VerifySignature(msgbytes, sigbytes, pubkeybytes);

   if (verbose)
      cout << "verification result: ";
   // output
   cout << b << endl;

   return true;
}

bool
execRand(istream& is, bool verbose)
{
   if (verbose)
      cout << "'rand' command options: [ BYTE_COUNT ]" << endl;

   int count;
   is >> count;

   int MAX = 1024 * 10; // 10 KiB
   if ((count < 0) || (count > MAX))
      return false;

   Crypto crypto;
   vbyte bytes = crypto.RandBytes(count);

   if (verbose)
      cout << "generated bytes (" << bytes.size() << "): ";
   // output
   cout << chelper::ToHexString(bytes) << endl;
   return true;
}

bool
execute(string command, istream& is, bool verbose)
{
   if (command == "set")
      return execSet(is, verbose);

   if (command == "gen")
      return execGen(is, verbose);

   if (command == "hash")
      return execHash(is, verbose);

   if (command == "bytes") // byte operations
      return execBytes(is, verbose);

   if (command == "rand")
      return execRand(is, verbose);

   if (command == "sign")
      return execSign(is, verbose);

   if (command == "verify")
      return execVerify(is, verbose);

   if (command == "show")
      return execShow(is, verbose);

   if (command == "help")
      return execHelp(is, verbose);

   return false;
}

// execute crypdev from stream... may be 'cin', file (via -f) or a passed string (via -c)
int
executeFromStream(istream& is, bool verbose)
{
   if (verbose) {
      cout << "===============================================" << endl;
      cout << "Welcome to crypdev: a lib CryptoN tool for devs" << endl;
      cout << "===============================================" << endl;
      cout << "Type 'exit' to finish program (or 'help')" << endl;
   }

   if (verbose)
      cout << endl
           << ">";

   string command;
   is >> command;
   chelper::trim(command);

   // check exit conditions: "exit" or empty
   while ((command != "exit") && (command != "")) {
      if (verbose)
         cout << "crypdev command: '" << command << "'" << endl;

      if (!execute(command, is, verbose)) {
         cerr << "ERROR: command '" << command << "' failed!" << endl;
         if (!verbose) // will exit
            return 1;
      }

      // get new command
      if (verbose)
         cout << endl
              << ">";
      command = "";
      is >> command;
      chelper::trim(command);

      // comma-separated commands
      while (command == ";") {
         is >> command;
         chelper::trim(command);
      }
   }

   if (verbose)
      cout << "bye bye" << endl;

   return 0; // good
}

} // namespace libcrypton

using namespace libcrypton;

int
main(int argc, char* argv[])
{
   if (argc == 2) {
      std::string param1 = argv[1];
      if (param1 == string("-v")) {
         std::cout << "version libcrypton: 0.1" << std::endl;
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

         // execute from file (non-verbose)
         return executeFromStream(infile, false);
      }

      if (param1 == string("-c")) {

         // load command list
         std::istringstream ss(param2);
         // execute from file (non-verbose)
         return executeFromStream(ss, false);
      }

      std::cerr << "unrecognized option: '" << param1 << "'" << std::endl;
      return 1;
   }

   // interactive mode (verbose = true)
   executeFromStream(cin, true);

   return 0;
}
