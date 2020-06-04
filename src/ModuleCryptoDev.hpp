#ifndef MODULE_CRYPTODEV_HPP
#define MODULE_CRYPTODEV_HPP

// standard includes
#include <algorithm>
#include <chrono> // chrono
#include <fstream>
#include <functional>
#include <iomanip> // fill zero for hex
#include <iostream>
#include <sstream>

// libcrypton includes
#include "Crypto.h"

using namespace std;

namespace libcrypton {

class ModuleCryptoDev
{
public:
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
         //os << "input now is '" << input << "'" << endl;
         // convert to hex
         input = chelper::ASCIIToHexString(input);
         //os << "converted ascii to hex: '" << input << "'" << endl;
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
   execHelp(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      os << endl;
      if (verbose)
         os << "'help' command options: [ ]" << endl;
      os << "existing commands are: " << endl;

      os << "set [ ecc hash ] [ secp256r1 | sha256 ]" << endl;
      os << "gen [ ECC_TYPE ] [ keypair pubkey privkey ] [ compressed uncompressed ] [ PRIVATE_KEY ]" << endl;
      os << "hash [ hash160 hash256 sha256 ripemd160 none ] [ TEXT_OR_BYTES ]" << endl;
      os << "bytes [ reverse length ] [ TEXT_OR_BYTES ]" << endl;
      os << "sign [ ECC_TYPE ] [ PRIVATE_KEY ] [ HASH_TYPE ] [ TEXT_OR_BYTES ] " << endl;
      os << "verify [ ECC_TYPE ] [ PUBLIC_KEY ] [ SIGNATURE ] [ HASH_TYPE ] [ TEXT_OR_BYTES ]  " << endl;
      os << "rand [ BYTE_COUNT ] " << endl;
      os << "show [ engine ecc hash ]" << endl;

      return true;
   }

   bool
   execSet(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'set' command options: [ ecc hash ]" << endl;
      string type;
      is >> type;

      if (type == "ecc") {
         if (verbose)
            os << "'ecc' options: [ secp256r1 ]" << endl;
         string curve;
         is >> curve;
         if (curve == "secp256r1") {
            cryptest_curve = curve;
            // output
            os << "DEFAULT ECC SET TO '" << cryptest_curve << "'" << endl;
            return true;
         }
         return false;
      }

      if (type == "hash") {
         if (verbose)
            os << "'hash' options: [ sha256 ]" << endl;
         string shash;
         is >> shash;
         if (shash == "sha256") {
            cryptest_hash = shash;
            //output
            os << "DEFAULT HASH SET TO '" << cryptest_hash << "'" << endl;
            return true;
         }
         return false;
      }

      return false;
   }

   bool
   execHash(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'hash' command options: [ hash160 hash256 sha256 ripemd160 none ]" << endl;
      string type;
      is >> type;

      Crypto crypto;

      if (type == "hash160") {
         if (verbose)
            os << "'hash160' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);
         vbyte bytes = parseTextBytes(tbytes);
         auto t_start = std::chrono::high_resolution_clock::now();
         vbyte hash = crypto.Hash160(bytes);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();
         if (verbose)
            os << "hash: ";
         // output
         os << chelper::ToHexString(hash) << endl;
         return true;
      }

      if (type == "hash256") {
         if (verbose)
            os << "'hash256' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);
         vbyte bytes = parseTextBytes(tbytes);
         auto t_start = std::chrono::high_resolution_clock::now();
         vbyte hash = crypto.Hash256(bytes);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();
         if (verbose)
            os << "hash: ";
         //output
         os << chelper::ToHexString(hash) << endl;
         return true;
      }

      if (type == "sha256") {
         if (verbose)
            os << "'sha256' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);
         vbyte bytes = parseTextBytes(tbytes);
         auto t_start = std::chrono::high_resolution_clock::now();
         vbyte hash = crypto.Sha256(bytes);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();
         if (verbose)
            os << "hash: ";
         // output
         os << chelper::ToHexString(hash) << endl;
         return true;
      }

      if (type == "ripemd160") {
         if (verbose)
            os << "'ripemd160' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);
         vbyte bytes = parseTextBytes(tbytes);
         auto t_start = std::chrono::high_resolution_clock::now();
         vbyte hash = crypto.RIPEMD160(bytes);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();
         if (verbose)
            os << "hash: ";
         // output
         os << chelper::ToHexString(hash) << endl;
         return true;
      }

      if (type == "none") {
         if (verbose)
            os << "'none' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);
         vbyte hash = parseTextBytes(tbytes);
         if (verbose)
            os << "hash: ";
         // output
         os << chelper::ToHexString(hash) << endl;
         return true;
      }

      return false;
   }

   bool
   execShow(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'show' command options: [ engine ecc show ]" << endl;
      string type;
      is >> type;

      if (type == "engine") {
         if (verbose)
            os << "'engine' options: [ ]" << endl;
         Crypto crypto;
         if (verbose)
            os << "libcrypton engine: ";
         // output
         os << crypto.GetEngine() << endl;
         return true;
      }

      if (type == "ecc") {
         if (verbose)
            os << "'ecc' options: [ ]" << endl;
         Crypto crypto;
         if (verbose)
            os << "libcrypton default ecc: ";
         // output
         os << cryptest_curve << endl;
         return true;
      }

      if (type == "hash") {
         if (verbose)
            os << "'hash' options: [ ]" << endl;
         Crypto crypto;
         if (verbose)
            os << "libcrypton default hash: ";
         // output
         os << cryptest_hash << endl;
         return true;
      }

      return false;
   }

   bool
   execGen(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'gen' command options: [ ECC_TYPE ] [ keypair pubkey privkey ]" << endl;

      string ecc;
      is >> ecc;
      // ignoring 'ecc' right now.. assuming 'secp256r1'

      string type;
      is >> type;

      if (type == "keypair") {
         if (verbose)
            os << "'keypair' options: [ ]" << endl;

         Crypto crypto;

         // creating private/public key pair (random each test)
         vbyte mypubkey;
         auto t_start = std::chrono::high_resolution_clock::now();
         SecureBytes myprivkey = crypto.GenerateKeyPair(mypubkey);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

         if (verbose)
            os << "public key (compressed format): ";
         // output
         os << chelper::ToHexString(mypubkey) << endl;
         if (verbose)
            os << "private key: ";
         // output
         os << chelper::ToHexString(myprivkey.ToUnsafeBytes()) << endl;

         return true;
      }

      if (type == "pubkey") {
         if (verbose)
            os << "'pubkey' options: [ compressed uncompressed ]" << endl;

         string pubtype;
         is >> pubtype;

         bool compressed;
         if (pubtype == "compressed")
            compressed = true;
         else
            compressed = false;

         string tbytes;
         is >> tbytes;
         SecureBytes privkey = parseTextBytes(tbytes);

         if (privkey.size() != 32) // secp256r1
         {
            cerr << "ERROR: expected private key of size 32 bytes for secp256r1" << endl;
            return false;
         }

         Crypto crypto;

         auto t_start = std::chrono::high_resolution_clock::now();
         // creating private/public key pair (random each test)
         vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(privkey, compressed);
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

         if (verbose)
            os << "public key: ";
         // output
         os << chelper::ToHexString(mypubkey) << endl;

         return true;
      }

      if (type == "privkey") {
         if (verbose)
            os << "'privkey' options: [ ]" << endl;

         Crypto crypto;

         auto t_start = std::chrono::high_resolution_clock::now();
         SecureBytes privkey = crypto.RandBytes(32); // secp256r1
         auto t_end = std::chrono::high_resolution_clock::now();
         spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

         if (verbose)
            os << "private key: ";
         // output
         os << chelper::ToHexString(privkey.ToUnsafeBytes()) << endl;

         return true;
      }

      return false;
   }

   bool
   execBytes(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'bytes' command options: [ reverse length ]" << endl;
      string type;
      is >> type;

      if (type == "reverse") {
         if (verbose)
            os << "'reverse' options: [ TEXT_OR_BYTES ]" << endl;
         string tbytes;
         std::getline(is, tbytes);

         vbyte bytes = parseTextBytes(tbytes);
         std::reverse(std::begin(bytes), std::end(bytes));
         if (verbose)
            os << "reversed bytes: ";
         // output
         os << chelper::ToHexString(bytes) << endl;
         return true;
      }

      if (type == "length") {
         if (verbose)
            os << "'length' options: [ TEXT_OR_BYTES ]" << endl;

         string tbytes;
         std::getline(is, tbytes);

         vbyte bytes = parseTextBytes(tbytes);
         if (verbose)
            os << "length: ";
         // output
         os << bytes.size() << endl;
         return true;
      }

      return false;
   }

   bool
   execSign(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'sign' command options: [ ECC_TYPE ] [ PRIVATE_KEY ] [ HASH_TYPE ] [ TEXT_OR_BYTES ]" << endl;

      string ecc;
      is >> ecc;
      // ignoring 'ecc' right now.. assuming 'secp256r1'

      string sprivkey;
      is >> sprivkey;
      SecureBytes privkeybytes = parseTextBytes(sprivkey);

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
            os << "Assuming hash type = 'none'" << endl;
         hashbytes = msgbytes;
      }

      if (hashbytes.size() != 32) {
         std::cerr << "ERROR: hash should have 32 bytes for secp256r1" << std::endl;
         return false;
      }

      // get compressed pubkey
      vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(privkeybytes, true);

      auto t_start = std::chrono::high_resolution_clock::now();
      vbyte sig = crypto.SignData(hashbytes, privkeybytes, mypubkey);
      auto t_end = std::chrono::high_resolution_clock::now();
      spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

      if (verbose)
         os << "signature: ";
      // output
      os << chelper::ToHexString(sig) << endl;
      return true;
   }

   bool
   execVerify(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'verify' command options: [ ECC_TYPE ] [ PUBLIC_KEY ] [ SIGNATURE ] [ HASH_TYPE ]  [ TEXT_OR_BYTES ] " << endl;

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
         os << "Assuming hash type = 'sha256'" << endl;
      hashbytes = msgbytes;

      if (sigbytes.size() != 64) {
         std::cerr << "ERROR: signature should have 64 bytes for secp256r1" << std::endl;
         return false;
      }

      auto t_start = std::chrono::high_resolution_clock::now();
      // TODO: pass hash type option inside this function
      bool b = crypto.VerifySignature(msgbytes, sigbytes, pubkeybytes);
      auto t_end = std::chrono::high_resolution_clock::now();
      spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

      if (verbose)
         os << "verification result: ";
      // output
      os << b << endl;

      return true;
   }

   bool
   execRand(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose)
         os << "'rand' command options: [ BYTE_COUNT ]" << endl;

      int count;
      is >> count;

      int MAX = 1024 * 10; // 10 KiB
      if ((count < 0) || (count > MAX))
         return false;

      Crypto crypto;
      auto t_start = std::chrono::high_resolution_clock::now();
      SecureBytes bytes = crypto.RandBytes(count);
      auto t_end = std::chrono::high_resolution_clock::now();
      spentTime += std::chrono::duration<double, std::milli>(t_end - t_start).count();

      if (verbose)
         os << "generated bytes (" << bytes.size() << "): ";
      // output
      os << chelper::ToHexString(bytes.ToUnsafeBytes()) << endl;
      return true;
   }

   bool
   execute(string command, istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (command == "set")
         return execSet(is, os, verbose, spentTime);

      if (command == "gen")
         return execGen(is, os, verbose, spentTime);

      if (command == "hash")
         return execHash(is, os, verbose, spentTime);

      if (command == "bytes") // byte operations
         return execBytes(is, os, verbose, spentTime);

      if (command == "rand")
         return execRand(is, os, verbose, spentTime);

      if (command == "sign")
         return execSign(is, os, verbose, spentTime);

      if (command == "verify")
         return execVerify(is, os, verbose, spentTime);

      if (command == "show")
         return execShow(is, os, verbose, spentTime);

      if (command == "help")
         return execHelp(is, os, verbose, spentTime);

      return false;
   }

   // execute crypdev from stream... may be 'cin', file (via -f) or a passed string (via -c)
   int
   executeFromStream(istream& is, ostream& os, bool verbose, double& spentTime)
   {
      if (verbose) {
         os << "===============================================" << endl;
         os << "Welcome to crypdev: a lib CryptoN tool for devs" << endl;
         os << "===============================================" << endl;
         os << "Type 'exit' to finish program (or 'help')" << endl;
      }

      if (verbose)
         os << endl
            << ">";

      string command;
      is >> command;
      chelper::trim(command);

      // check exit conditions: "exit" or empty
      while ((command != "exit") && (command != "")) {
         if (verbose)
            os << "crypdev command: '" << command << "'" << endl;

         if (verbose)
            spentTime = 0; // reset every new command (using 'cin' interactive)
         if (!execute(command, is, os, verbose, spentTime)) {
            cerr << "ERROR: command '" << command << "' failed!" << endl;
            if (!verbose) // will exit
               return 1;
         }
         if (verbose && spentTime > 0)
            os << " -> Spent " << spentTime << " ms" << endl;

         // get new command
         if (verbose)
            os << endl
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
         os << "bye bye" << endl;

      return 0; // good
   }

   std::string version() const
   {
      return "libcrypton: 0.3";
   }

}; // ModuleCryotoDev

} // namespace libcrypton

#endif // MODULE_CRYPTODEV_HPP
