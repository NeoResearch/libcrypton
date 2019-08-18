
// 'crypdev' is a tool (CLI/REPL) for testing and interacting with crypto functions

// standard includes
#include <algorithm>
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
   if (input.size() < 2) {
      cerr << "malformed input, returning empty bytes" << endl;
      return vbyte(0);
   }

   if (input[0] == '"') {
      input = input.substr(1, input.length() - 2);
      cout << "input now is '" << input << "'" << endl;
      // convert to hex
      input = chelper::ASCIIToHexString(input);
      cout << "converted ascii to hex: '" << input << "'" << endl;
   }

   // removing prefix '0x' if existing
   if ((input[0] == '0') && (input[1] == 'x')) {
      input = input.substr(2, input.length());
   }

   return chelper::HexToBytes(input);
}

// finish useful stuff... move to some class!

string cryptest_curve = "secp256r1";

bool
execHelp()
{
   cout << endl;
   cout << "'help' command options: [ ]" << endl;
   cout << "existing commands are: " << endl;

   cout << "set [ curve ] [ secp256r1 ]" << endl;
   cout << "gen [ keypair pubkey privkey ] [ compressed uncompressed ] [ BYTES ]" << endl;
   cout << "hash [ hash160 hash256 sha256 ripemd160 ] [ TEXT_OR_BYTES ]" << endl;
   cout << "bytes [ reverse length ] [ TEXT_OR_BYTES ]" << endl;
   cout << "rand [ BYTE_COUNT ] " << endl;
   cout << "show [ engine ]" << endl;

   return true;
}

bool
execSet()
{
   cout << "'set' command options: [ curve ]" << endl;
   string type;
   cin >> type;

   if (type == "curve") {
      cout << "'curve' options: [ secp256r1 ]" << endl;
      string curve;
      cin >> curve;
      if (curve == "secp256r1") {
         cryptest_curve = curve;
         cout << "CURVE SET TO '" << cryptest_curve << "'" << endl;
         return true;
      }
      return false;
   }

   return false;
}

bool
execHash()
{
   cout << "'hash' command options: [ hash160 hash256 sha256 ripemd160 ]" << endl;
   string type;
   cin >> type;

   Crypto crypto;

   if (type == "hash160") {
      cout << "'hash160' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.Hash160(bytes);
      cout << "hash: " << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "hash256") {
      cout << "'hash256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.Hash256(bytes);
      cout << "hash: " << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "sha256") {
      cout << "'sha256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.Sha256(bytes);
      cout << "hash: " << chelper::ToHexString(hash) << endl;
      return true;
   }

   if (type == "ripemd160") {
      cout << "'ripemd160' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.RIPEMD160(bytes);
      cout << "hash: " << chelper::ToHexString(hash) << endl;
      return true;
   }

   return false;
}

bool
execShow()
{
   cout << "'show' command options: [ engine ]" << endl;
   string type;
   cin >> type;

   if (type == "engine") {
      cout << "'engine' options: [ ]" << endl;
      Crypto crypto;
      cout << "libcrypton engine: " << crypto.GetEngine() << endl;
      return true;
   }

   return false;
}

bool
execGen()
{
   cout << "'gen' command options: [ keypair ]" << endl;
   string type;
   cin >> type;

   if (type == "keypair") {
      cout << "'keypair' options: [ ]" << endl;

      Crypto crypto;

      // creating private/public key pair (random each test)
      vbyte mypubkey;
      vbyte myprivkey = crypto.GeneratePrivateKey(mypubkey);

      cout << "public key (compressed format): " << chelper::ToHexString(mypubkey) << endl;
      cout << "private key: " << chelper::ToHexString(myprivkey) << endl;

      return true;
   }

   if (type == "pubkey") {
      cout << "'pubkey' options: [ compressed uncompressed ]" << endl;

      string pubtype;
      cin >> pubtype;

      bool compressed;
      if (pubtype == "compressed")
         compressed = true;
      else
         compressed = false;

      string tbytes;
      cin >> tbytes;
      vbyte privkey = parseTextBytes(tbytes);

      if (privkey.size() != 32) // secp256r1
      {
         cerr << "ERROR: expected private key of size 32 bytes for secp256r1" << endl;
         return false;
      }

      Crypto crypto;

      // creating private/public key pair (random each test)
      vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(privkey, compressed);

      cout << "public key: " << chelper::ToHexString(mypubkey) << endl;

      return true;
   }

   if (type == "privkey") {
      cout << "'privkey' options: [ ]" << endl;

      Crypto crypto;

      vbyte privkey = crypto.RandBytes(32); // secp256r1

      cout << "private key: " << chelper::ToHexString(privkey) << endl;

      return true;
   }

   return false;
}

bool
execBytes()
{
   cout << "'bytes' command options: [ reverse length ]" << endl;
   string type;
   cin >> type;

   if (type == "reverse") {
      cout << "'reverse' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      std::reverse(std::begin(bytes), std::end(bytes));
      cout << "reversed bytes: " << chelper::ToHexString(bytes) << endl;
      return true;
   }

   if (type == "length") {
      cout << "'length' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      cout << "length: " << bytes.size() << endl;
      return true;
   }

   return false;
}

bool
execRand()
{
   cout << "'rand' command options: [ BYTE_COUNT ]" << endl;
   int count;
   cin >> count;

   int MAX = 1024 * 10; // 10 KiB
   if ((count < 0) || (count > MAX))
      return false;

   Crypto crypto;
   vbyte bytes = crypto.RandBytes(count);

   cout << "generated bytes (" << bytes.size() << "): " << chelper::ToHexString(bytes) << endl;
   return true;
}

bool
execute(string command)
{
   if (command == "set")
      return execSet();

   if (command == "gen")
      return execGen();

   if (command == "hash")
      return execHash();

   if (command == "bytes") // byte operations
      return execBytes();

   if (command == "rand")
      return execRand();

   if (command == "show")
      return execShow();

   if (command == "help")
      return execHelp();

   return false;
}

} // namespace libcrypton

using namespace libcrypton;

int
main()
{
   cout << "===============================================" << endl;
   cout << "Welcome to crypdev: a lib CryptoN tool for devs" << endl;
   cout << "===============================================" << endl;
   cout << "Type 'exit' to finish program (or 'help')" << endl;

   cout << endl
        << ">";
   string command;

   cin >> command;
   while (command != "exit") {
      cout << "crypdev command: '" << command << "'" << endl;

      if (!execute(command))
         cout << "ERROR: command '" << command << "' failed!" << endl;
      // get new command
      cout << endl
           << ">";
      cin >> command;
   }

   cout << "bye bye" << endl;

   return 0;
}
