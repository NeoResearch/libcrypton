#ifndef CRYPTO_EXTRA_H
#define CRYPTO_EXTRA_H

// WARNING: do not include .hpp here, or things may break!

// implementation of Crypto Extra (using cryptopp lib)

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

class CryptoExtra
{
public:

   // Sha3 (optional) - implemented via openssl... keccak (older) or NIST SHA-3?
   vbyte Sha3NIST(const vbyte& message) const;

   // Keccak "official" (not new NIST SHA-3)
   vbyte Sha3Keccak(const vbyte& message) const;
};

}

#endif
