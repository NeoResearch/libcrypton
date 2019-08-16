#ifndef ECPOINT_HPP
#define ECPOINT_HPP

// c++ standard part
// ... none

// neopt core part
#include<numbers/UInt256.hpp>

using namespace std; // TODO: do not use that in the future... prefer std::vector instead

namespace neopt
{

class ECPoint
{
public:

   // what to put here?

   vbyte EncodePoint(bool encode) const
   {
      // TODO: implement
      return vbyte(0);
   }

   //static const int AddressVersion = 21;
};

}

#endif
