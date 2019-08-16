#ifndef ICRYPTO_H
#define ICRYPTO_H

// WARNING: do not include .hpp here, or things may break!

// system includes
// none ..

// core includes
#include <system/types.h>

namespace neopt {

class ICrypto
{
public:
   // Hash160 = SHA256 + RIPEMD160
   virtual vbyte Hash160(const vbyte& message) const
   {
      return RIPEMD160(Sha256(message));
   }

   // Hash256 = SHA256 + SHA256
   virtual vbyte Hash256(const vbyte& message) const
   {
      return Sha256(Sha256(message));
   }

   // Verify signature against public key on elliptic curve NIST P-256 (secp256r1)
   virtual bool VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey) const = 0;

   // -----------------------------------------------------
   // not available on Neo ICrypto, but important for usage
   // -----------------------------------------------------

   virtual vbyte Sign(const vbyte& message, const vbyte& prikey, const vbyte& pubkey) const = 0;
   //{
   //   // TODO: implement
   //   return vbyte(0);
   //}

   // SHA256
   virtual vbyte Sha256(const vbyte& message) const = 0;

   // RIPEMD160
   virtual vbyte RIPEMD160(const vbyte& message) const = 0;

   // -----------------
   // proposed methods
   // -----------------

   // this definition is mileading, vpubkey is an output parameter...
   // this method will be changed soon, to return a pair or ECPoint (TODO: think about it)
   virtual vbyte GeneratePrivateKey(vbyte& vpubkey) const
   {
      return vbyte(0);
   }

   virtual vbyte GetPublicKeyFromPrivateKey(const vbyte& priv) const
   {
      // TODO: if (!EC_POINT_mul(ecdsa->group, pub_key, priv_key, NULL, NULL, ctx))
      return vbyte(0);
   }
};

}

#endif
