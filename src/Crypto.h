#ifndef CRYPTO_H
#define CRYPTO_H

// WARNING: do not include .hpp here, or things may break!

// implementation of Crypto

// system includes
#include <assert.h>
#include <cstring>
#include <string>

/*
// third-party includes
#include <openssl/obj_mac.h> // for NID_secp192k1

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/ripemd.h>
#include <openssl/sha.h>
*/
// core includes
#include <crypto/ICrypto.h>

namespace neopt {

// cryptography for Neo
class Crypto : public ICrypto
{
private:
   static ICrypto* _crypto;

public:
   static const ICrypto& Default()
   {
      if (_crypto == nullptr)
         _crypto = new Crypto();
      return *_crypto;
   }

   static void Free()
   {
      if (_crypto != nullptr)
         delete _crypto;
      _crypto = nullptr;
   }

   vbyte Hash160(const vbyte& message) const;

   vbyte Hash256(const vbyte& message) const;

   bool VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey) const;

   // SHA256
   vbyte Sha256(const vbyte& message) const;

   // RIPEMD160
   vbyte RIPEMD160(const vbyte& message) const;

   vbyte Sign(const vbyte& message, const vbyte& privkey, const vbyte& pubkey) const
   {
      return SignData(Sha256(message), privkey, pubkey);
   }
   /*
   public byte[] Sign(byte[] message, byte[] prikey, byte[] pubkey)
{
    using (var ecdsa = ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        D = prikey,
        Q = new ECPoint
        {
            X = pubkey.Take(32).ToArray(),
            Y = pubkey.Skip(32).ToArray()
        }
    }))
    {
        return ecdsa.SignData(message, HashAlgorithmName.SHA256);
    }
}
*/

   // TODO: receive pubkey or already ECPoint(X,Y) ?
   vbyte SignData(const vbyte& digest, const vbyte& prikey, const vbyte& pubkey) const;

   virtual vbyte GeneratePrivateKey(vbyte& vpubkey) const;

   // manually added
   static vbyte FromHexString(std::string hex)
   {
      vbyte bytes(hex.length() / 2);
      for (unsigned int i = 0; i < hex.length(); i += 2) {
         std::string byteString = hex.substr(i, 2);
         byte b = (byte)strtol(byteString.c_str(), NULL, 16);
         bytes[i] = b;
      }
      return bytes;
   }

   // Sha3 (optional) - implemented via openssl... keccak (older) or NIST SHA-3?
   vbyte Sha3NIST(const vbyte& message) const;
};

}

#endif
