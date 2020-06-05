#ifndef LIBCRYPTON_CRYPTO_H
#define LIBCRYPTON_CRYPTO_H

// WARNING: do not include .hpp here, or things may break!

// implementation of Crypto

// system includes
#include <assert.h>
#include <cstring>
#include <iostream>
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
#include "ICrypto.h"

namespace libcrypton {

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

   // string for implementation engine. expected values: "openssl", "crypto++", "unknown"
   virtual std::string GetEngine() const override;

   vbyte Hash160(const vbyte& message) const;

   vbyte Hash256(const vbyte& message) const;

   bool VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey, bool useSha256 = true) const;

   // SHA256
   vbyte Sha256(const vbyte& message) const;

   // RIPEMD160
   vbyte RIPEMD160(const vbyte& message) const;

   // =================================================
   // We support two modes of AES:
   //    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
   // =================================================
   // - Electronic codebook (ECB)
   // - Cipher block chaining (CBC)
   // =================================================
   // We also support Padding or NoPadding strategies
   // =================================================
   // CBC mode requires an Initialization Vector (IV)
   // - It is important that an initialization vector is never reused under the same key.
   // - It can be public.
   // - In CBC mode, the IV must, in addition, be unpredictable at encryption time.
   // =================================================
   // ECB does not require an Initialization Vector (thus pass an empty 'vbyte')
   // =================================================

   SecureBytes AESEncrypt(const SecureBytes& message, const SecureBytes& key, const SecureBytes& iv, bool padding, bool ecb) const;

   SecureBytes AESDecrypt(const SecureBytes& message, const SecureBytes& key, const SecureBytes& iv, bool padding, bool ecb) const;

   SecureBytes Scrypt64(const SecureBytes& pass, const SecureBytes& salt, const int n, const int r, const int p) const;

   vbyte XOR(const vbyte& v1, const vbyte& v2) const
   {
      vbyte vout(v1.size(), 0x00);
      if (v1.size() != v2.size())
         return vbyte{}; // empty
      for (unsigned i = 0; i < v1.size(); i++)
         vout[i] = v1[i] ^ v2[i];
      return vout;
   }

   vbyte Sign(const vbyte& message, const SecureBytes& privkey, const vbyte& pubkey, bool verify = true) const
   {
      vbyte hashedMsg = Sha256(message);
      vbyte signedMsg = SignData(hashedMsg, privkey, pubkey, verify);
      // No need to verify here!
      /*
      if (verify)
         // try many times to sign... why do we need this?
         while (!VerifySignature(message, signedMsg, pubkey)) {
            std::cout << "WARNING: libcrypton 'verify' on Sign had to sign again..." << std::endl;
            signedMsg = SignData(hashedMsg, privkey, pubkey);
         }
      */
      return signedMsg;
   }

   vbyte GetPublicKeyFromPrivateKey(const SecureBytes& priv, bool compressed) const;
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
   vbyte SignData(const vbyte& digest, const SecureBytes& prikey, const vbyte& pubkey, bool verify = true) const;

   virtual SecureBytes GenerateKeyPair(vbyte& vpubkey) const;

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

   ///vbyte RandBytes(int count); // generate random bytes, used for private applications

   static SecureBytes NO_IV;
}; // class Crypto
//
} // namespace libcrypton

#endif // LIBCRYPTON_CRYPTO_H
