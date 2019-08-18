
// 'crypdev' is a tool (CLI/REPL) for testing and interacting with crypto functions

// standard includes
#include <functional>
#include <iomanip> // fill zero for hex
#include <iostream>
#include <sstream>

// libcrypton includes
#include "Crypto.h"

using namespace std;

namespace libcrypton {

static string
ToHexString(const vbyte& v)
{
   //std::cout << "ToHexString!!!!" << std::endl;
   stringstream ss;
   // TODO: check if format is this
   for (unsigned i = 0; i < v.size(); i++) // TODO: use foreach
      ss << std::setfill('0') << std::setw(2) << std::hex << (int)v[i];
   //std::cout << "ToHexString!!!! RESULT = " << ss.str() << std::endl;

   return ss.str();
}

static string
ToHexString(const byte& b)
{
   return ToHexString(vbyte(1, b));
}

string
ASCIIToHexString(const string& chars)
{
   stringstream ss;
   for (unsigned i = 0; i < chars.size(); i++)
      ss << std::setfill('0') << std::setw(2) << std::hex << int((byte)chars[i]);
   return ss.str();
}

vbyte
HexToBytes(const string& hex)
{
   // TODO: implement (begin 0x)
   //NEOPT_EXCEPTION("Not implemented yet: HexToBytes");
   vbyte bytes(hex.length() / 2);

   for (uint i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      byte b = (byte)strtol(byteString.c_str(), NULL, 16);
      bytes[i / 2] = b;
   }
   return bytes;
}

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
      input = ASCIIToHexString(input);
      cout << "converted ascii to hex: '" << input << "'" << endl;
   }

   // removing prefix '0x' if existing
   if ((input[0] == '0') && (input[1] == 'x')) {
      input = input.substr(2, input.length());
   }

   return HexToBytes(input);
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
   cout << "gen [ keypair ]" << endl;
   cout << "hash [ hash160 hash256 sha256 ripemd160 ] [ TEXT_OR_BYTES ]" << endl;
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
      cout << "hash: " << ToHexString(hash) << endl;
      return true;
   }

   if (type == "hash256") {
      cout << "'hash256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.Hash256(bytes);
      cout << "hash: " << ToHexString(hash) << endl;
      return true;
   }

   if (type == "sha256") {
      cout << "'sha256' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.Sha256(bytes);
      cout << "hash: " << ToHexString(hash) << endl;
      return true;
   }

   if (type == "ripemd160") {
      cout << "'ripemd160' options: [ TEXT_OR_BYTES ]" << endl;
      string tbytes;
      cin >> tbytes;
      vbyte bytes = parseTextBytes(tbytes);
      vbyte hash = crypto.RIPEMD160(bytes);
      cout << "hash: " << ToHexString(hash) << endl;
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

      cout << "public key (compressed format): " << ToHexString(mypubkey) << endl;
      cout << "private key: " << ToHexString(myprivkey) << endl;

      return true;
   }
   return false;
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
   cout << "===========================================" << endl;
   cout << "Welcome to crypdev: a CryptoN tool for devs" << endl;
   cout << "===========================================" << endl;
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
