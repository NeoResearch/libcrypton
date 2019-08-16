#include <crypto/CryptoExtra.h>

#include <crypto/cryptopp/keccak.h> // sha-3 keccak (not NIST SHA-3)

#include<iostream>

using namespace neopt;

void
lComputeKeccak(const unsigned char *message, size_t message_len, vbyte& digest);


vbyte CryptoExtra::Sha3NIST(const vbyte& message) const
{
   NEOPT_EXCEPTION("NOT IMPLEMENTED SHA3 NIST");
   vbyte voutput(0);
   return voutput;
}

vbyte CryptoExtra::Sha3Keccak(const vbyte& message) const
{
   vbyte digest;
   lComputeKeccak(message.data(), message.size(), digest);
   return digest;
}

void
lComputeSHA3(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
}

// "official" keccak via cryptopp
void
lComputeKeccak(const unsigned char *message, size_t message_len, vbyte& digest)
{
   std::cout << "Creating Keccak" << std::endl;
  	 CryptoPP::Keccak_256 hash;	
    std::cout << "Update hash Keccak" << std::endl;
    hash.Update(message, message_len);

    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    /*
    bool verified = hash.Verify((const byte*)digest.data());

if (verified == true)
    std::cout << "Verified hash over message" << std::endl;
else
    std::cout << "Failed to verify hash over message" << std::endl;
    */

    std::cout << "Finished Keccak" << std::endl;
}

