#ifndef CHELPER_H
#define CHELPER_H

// Crypto Helper: chelper

// system
#include <sstream>
#include <vector>

// neo core
#include <numbers/UInt160.hpp>
#include <system/types.h>

using namespace std; // TODO: avoid!

namespace neopt {

// crypto helper class
class chelper
{
public:
   static UInt160 ToScriptHash(const vbyte& v)
   {
      NEOPT_EXCEPTION("Not implemented: ToScriptHash");
      return UInt160();
   }

   static string Base58CheckEncode(const vbyte& data)
   {
      NEOPT_EXCEPTION("Not implemented: Base58CheckEncode");
      return "";
   }

   static vbyte Base58CheckDecode(string address)
   {
      NEOPT_EXCEPTION("Not implemented: Base58CheckDecode");
      return vbyte(0);
   }
};

// TODO: define all operators here that are necessary

}

#endif
