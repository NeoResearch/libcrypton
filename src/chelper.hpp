#ifndef LIBCRYPTON_CHELPER_HPP
#define LIBCRYPTON_CHELPER_HPP

// Crypto Helper: chelper

// system
#include <algorithm> //std:: generate
#include <functional>
#include <iomanip>
#include <limits.h> // CHAR
#include <random>
#include <sstream>
#include <vector>

// ========

#include "SecureBytes.hpp"
#include "types.h"

// neo core
//#include <numbers/UInt160.hpp>
//#include <system/types.h>

//using namespace std; // TODO: avoid!

namespace libcrypton {
//

// crypto helper class
class chelper
{
public:
   static void ltrim(std::string& s)
   {
      s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
                 return !std::isspace(ch);
              }));
   }

   static void rtrim(std::string& s)
   {
      s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
                 return !std::isspace(ch);
              }).base(),
              s.end());
   }

   static void trim(std::string& s)
   {
      ltrim(s);
      rtrim(s);
   }

   static std::string
   ToHexString(const vbyte& v, bool cs = false)
   {
      //std::cout << "ToHexString!!!!" << std::endl;
      std::stringstream ss;
      // TODO: check if format is this
      for (unsigned i = 0; i < v.size(); i++) // TODO: use foreach
      {
         if (cs)
            ss << std::uppercase;
         ss << std::setfill('0') << std::setw(2) << std::hex << (int)v[i];
      }
      //std::cout << "ToHexString!!!! RESULT = " << ss.str() << std::endl;

      return ss.str();
   }

   static std::string
   ToHexString(const byte& b, bool cs = false)
   {
      return ToHexString(vbyte(1, b), cs);
   }


   static std::string
   ASCIIToHexString(const std::string& chars)
   {
      std::stringstream ss;
      for (unsigned i = 0; i < chars.size(); i++)
         ss << std::setfill('0') << std::setw(2) << std::hex << int((byte)chars[i]);
      return ss.str();
   }

   static vbyte
   HexToBytes(const std::string& hex)
   {
      // TODO: implement (begin 0x)
      //CRYPTON_EXCEPTION("Not implemented yet: HexToBytes");
      vbyte bytes(hex.length() / 2);

      for (unsigned int i = 0; i < hex.length(); i += 2) {
         std::string byteString = hex.substr(i, 2);
         byte b = (byte)strtol(byteString.c_str(), NULL, 16);
         bytes[i / 2] = b;
      }
      return bytes;
   }

   /*
   static UInt160 ToScriptHash(const vbyte& v)
   {
      CRYPTON_EXCEPTION("Not implemented: ToScriptHash");
      return UInt160();
   }
*/

   static std::string Base58CheckEncode(const vbyte& data)
   {
      CRYPTON_EXCEPTION("Not implemented: Base58CheckEncode");
      return "";
   }

   static vbyte Base58CheckDecode(std::string address)
   {
      CRYPTON_EXCEPTION("Not implemented: Base58CheckDecode");
      return vbyte(0);
   }
};

// TODO: define all operators here that are necessary
}

#endif // LIBCRYPTON_CHELPER_HPP
