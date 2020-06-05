#ifndef ICRYPTO_H
#define ICRYPTO_H

// WARNING: do not include .hpp here, or things may break!

// system includes
#include <vector>

// only for random
#include <algorithm> //std:: generate
#include <functional>
#include <limits.h> // CHAR
#include <random>

// core includes
//#include <system/types.h>
#include "chelper.hpp"

//using namespace std; // TODO: remove

namespace libcrypton {

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
   virtual bool VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey, bool useSha256 = true) const = 0;

   // -----------------------------------------------------
   // not available on Neo ICrypto, but important for usage
   // -----------------------------------------------------

   virtual vbyte Sign(const vbyte& message, const SecureBytes& prikey, const vbyte& pubkey, bool verify = true) const = 0;
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

   virtual SecureBytes GeneratePrivateKey()
   {
      return RandBytes(32);
   }

   // returns private and updates public (TODO: rethink method)
   virtual SecureBytes GenerateKeyPair(vbyte& vpubkey) const
   {
      return vbyte(0);
   }

   // 'priv' is UNSIGNED BIG-ENDIAN BIG-INTEGER (of 32-bytes)
   virtual vbyte GetPublicKeyFromPrivateKey(const SecureBytes& priv, bool compressed) const
   {
      // TODO: if (!EC_POINT_mul(ecdsa->group, pub_key, priv_key, NULL, NULL, ctx))
      return vbyte(0);
   }

   // string for implementation engine. expected values: "openssl", "crypto++", "unknown"
   virtual std::string GetEngine() const
   {
      return "unknown";
   }

   // generate random bytes, used for private applications
   // Note: this is 'const', but it's non-deterministic (takes entropy from system)
   virtual SecureBytes RandBytes(int count) const
   {
      int MAX = 1024 * 10; // 10KiB MAX
      if ((count < 0) || (count > MAX))
         return vbyte(0);
      vbyte vbytes(count, 0x00);

      // defining an independent bit engine
      using random_bytes_engine = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char>;

      // default random to seed it (perhaps using /dev/random?)
      std::random_device rd;
      //if (rd.entropy() == 0)   // no entropy or always zero (?) - looks like a bug in gcc...
      //   return vbyte(0);

      // seed random_bytes_engine with random_device (otherwise it becomes deterministic...)
      random_bytes_engine rbe(rd());
      std::generate(std::begin(vbytes), std::end(vbytes), std::ref(rbe));
      return vbytes;
   }
};
//
} // namespace libcrypton

#endif
