#include <crypto/Crypto.h>

// third-party includes
#include <openssl/obj_mac.h> // for NID_secp192k1

#include <openssl/ec.h>    // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h> // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <openssl/evp.h> // sha-3 (unknown if keccak or post-keccak / NIST SHA-3)

#include<iostream>

using namespace neopt;

// first thing, declare private static variable _crypto
ICrypto* Crypto::_crypto = nullptr;

// ==================
// external functions
// ==================

// borrowed from the neo-HyperVM project

// public:
// Constants
static const int32 SHA1_LENGTH = 20;
static const int32 SHA256_LENGTH = 32;
static const int32 RIPEMD160_LENGTH = 20;
static const int32 HASH160_LENGTH = RIPEMD160_LENGTH;
static const int32 HASH256_LENGTH = SHA256_LENGTH;

// Methods

void
lComputeSHA1(byte* data, int32 length, byte* output);
void
lComputeSHA256(const byte* data, int32 length, byte* output);
void
lComputeHash160(const byte* data, int32 length, byte* output);
void
lComputeHash256(const byte* data, int32 length, byte* output);
void
lComputeRIPEMD160(const byte* data, int32 length, byte* output);

void
lComputeSHA3OpenSSL(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

void
lComputeKeccak(const unsigned char *message, size_t message_len, vbyte& digest);


// -1=ERROR , 0= False , 1=True
static int16
lVerifySignature(const byte* data, int32 dataLength, const byte* signature, int32 signatureLength, const byte* pubKey, int32 pubKeyLength);

//private:
static const int32 _curve = NID_X9_62_prime256v1; // secp256r1
// see: https://www.ietf.org/rfc/rfc5480.txt

// Empty hashes

//static const byte EMPTY_RIPEMD160[RIPEMD160_LENGTH];
//static const byte EMPTY_HASH160[HASH160_LENGTH];
//static const byte EMPTY_HASH256[HASH256_LENGTH];
//static const byte EMPTY_SHA1[SHA1_LENGTH];
//static const byte EMPTY_SHA256[SHA256_LENGTH];

const byte EMPTY_SHA1[] = {
   0xda,
   0x39,
   0xa3,
   0xee,
   0x5e,
   0x6b,
   0x4b,
   0x0d,
   0x32,
   0x55,
   0xbf,
   0xef,
   0x95,
   0x60,
   0x18,
   0x90,
   0xaf,
   0xd8,
   0x07,
   0x09
};

const byte EMPTY_HASH160[] = {
   0xb4,
   0x72,
   0xa2,
   0x66,
   0xd0,
   0xbd,
   0x89,
   0xc1,
   0x37,
   0x06,
   0xa4,
   0x13,
   0x2c,
   0xcf,
   0xb1,
   0x6f,
   0x7c,
   0x3b,
   0x9f,
   0xcb
};

const byte EMPTY_SHA256[] = {
   0xe3,
   0xb0,
   0xc4,
   0x42,
   0x98,
   0xfc,
   0x1c,
   0x14,
   0x9a,
   0xfb,
   0xf4,
   0xc8,
   0x99,
   0x6f,
   0xb9,
   0x24,
   0x27,
   0xae,
   0x41,
   0xe4,
   0x64,
   0x9b,
   0x93,
   0x4c,
   0xa4,
   0x95,
   0x99,
   0x1b,
   0x78,
   0x52,
   0xb8,
   0x55
};

const byte EMPTY_HASH256[] = {
   0x5d,
   0xf6,
   0xe0,
   0xe2,
   0x76,
   0x13,
   0x59,
   0xd3,
   0x0a,
   0x82,
   0x75,
   0x05,
   0x8e,
   0x29,
   0x9f,
   0xcc,
   0x03,
   0x81,
   0x53,
   0x45,
   0x45,
   0xf5,
   0x5c,
   0xf4,
   0x3e,
   0x41,
   0x98,
   0x3f,
   0x5d,
   0x4c,
   0x94,
   0x56
};

const byte EMPTY_RIPEMD160[] = {
   0x9c,
   0x11,
   0x85,
   0xa5,
   0xc5,
   0xe9,
   0xfc,
   0x54,
   0x61,
   0x28,
   0x08,
   0x97,
   0x7e,
   0xe8,
   0xf5,
   0x48,
   0xb2,
   0x25,
   0x8d,
   0x31
};

vbyte
Crypto::Hash160(const vbyte& message) const
{
   vbyte voutput(HASH160_LENGTH);
   ::lComputeHash160(message.data(), message.size(), voutput.data());
   return voutput;
}

vbyte
Crypto::Hash256(const vbyte& message) const
{
   vbyte voutput(HASH256_LENGTH);
   lComputeHash256(message.data(), message.size(), voutput.data());
   return voutput;
}

bool
Crypto::VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey) const
{
   int16 ret = lVerifySignature(message.data(), message.size(), signature.data(), signature.size(), pubkey.data(), pubkey.size());
   if (ret == -1)
      NEOPT_EXCEPTION("ERROR ON VerifySignature");
   return ret == 1;
}

vbyte
Crypto::Sha256(const vbyte& message) const
{
   vbyte voutput(SHA256_LENGTH);
   lComputeSHA256(message.data(), message.size(), voutput.data());
   return voutput;
}

vbyte Crypto::Sha3NIST(const vbyte& message) const
{
   //lComputeSHA3(message.data(), message.size(), voutput.data());
   unsigned char *digest;
   unsigned int digest_len;
   lComputeSHA3OpenSSL(message.data(), message.size(), &digest, &digest_len);
   vbyte voutput(digest, digest+digest_len);
   return voutput;
}


vbyte
Crypto::RIPEMD160(const vbyte& message) const
{
   vbyte voutput(RIPEMD160_LENGTH);
   lComputeRIPEMD160(message.data(), message.size(), voutput.data());
   return voutput;
}

// message is already received as a SHA256 digest
// TODO: better to receive pubkey in general format or specific ECPoint(X,Y) ?
vbyte
Crypto::SignData(const vbyte& digest, const vbyte& privkey, const vbyte& pubkey) const
{
   //printf("\n\nSignData\n");
   // TODO: implement low level lSignData? (or keep C++ mixed?)
   // TODO: apply SHA256 here to make sure?
   const byte* hash = digest.data();
   int hashLen = 32;
   if (digest.size() != hashLen) {
      NEOPT_EXCEPTION("Failed to have digest of 32 bytes for SignData");
      return vbyte(0);
   }
   const byte* pubKey = pubkey.data();
   int pubKeyLength = pubkey.size();
   const byte* mypriv = privkey.data();

   // initialize environment and initialize private key
   EC_KEY* eckey = EC_KEY_new();
   if (NULL == eckey) {
      NEOPT_EXCEPTION("Failed to create new EC Key");
      return vbyte(0);
   }

   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve); //NID_secp192k1);
   if (NULL == ecgroup) {
      NEOPT_EXCEPTION("Failed to create new EC Group");
      return vbyte(0);
   }

   int set_group_status = EC_KEY_set_group(eckey, ecgroup);
   const int set_group_success = 1;
   if (set_group_success != set_group_status) {
      NEOPT_EXCEPTION("Failed to set group for EC Key");
      return vbyte(0);
   }

   byte* realPubKey = nullptr;
   int realPublicKeyLength = 65;

   if (pubKeyLength == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03)) {
      // remove const from array: must make sure realPubKey data is never changed
      realPubKey = const_cast<byte*>(pubKey);
      realPublicKeyLength = 33;
   } else if (pubKeyLength == 64) {
      // 0x04 first

      // TODO: verify if no leak happens in this case
      realPubKey = new byte[65];
      realPubKey[0] = 0x04;

      memcpy(&realPubKey[1], pubKey, 64);
   } else if (pubKeyLength == 65) {
      if (pubKey[0] != 0x04) {
         NEOPT_EXCEPTION("Error on signing");
         return vbyte(0);
      }

      // remove const from array: must make sure realPubKey data is never changed
      realPubKey = const_cast<byte*>(pubKey);
   } else if (pubKeyLength != 65) {
      NEOPT_EXCEPTION("Error on signing 2");
      return vbyte(0);
   }

   BIGNUM* bn = BN_bin2bn(realPubKey, realPublicKeyLength, nullptr);
   EC_POINT* pub = EC_POINT_bn2point(ecgroup, bn, nullptr, nullptr);
   BIGNUM* priv = BN_bin2bn(&mypriv[0], 32, nullptr);

   if (pub != nullptr) {
      int32 gen_status = EC_KEY_set_public_key(eckey, pub);
      int32 gen_status2 = EC_KEY_set_private_key(eckey, priv);
   }

   ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, eckey);
   if (NULL == signature) {
      NEOPT_EXCEPTION("Failed to generate EC Signature\n");
      return vbyte(0);
   }

   // non-DER format (double bignum format)
   //BIGNUM* r = BN_new();
   //BIGNUM* s = BN_new();
   //const BIGNUM** pr = (const BIGNUM**)malloc(sizeof(BIGNUM**));
   //const BIGNUM** ps = (const BIGNUM**)malloc(sizeof(BIGNUM**));
   const BIGNUM* r; // do not delete it
   const BIGNUM* s; // do not delete it
   //ECDSA_SIG_get0(signature, (const BIGNUM**)&r, (const BIGNUM**)&s);
   //ECDSA_SIG_get0(signature, pr, ps);
   ECDSA_SIG_get0(signature, &r, &s);
   //signature->r  gives forward declaration issue

   vbyte vsig(64, 0);
   BN_bn2bin(r, vsig.data() + 0);
   BN_bn2bin(s, vsig.data() + 32);
   //BN_bn2bin(*pr, vsig.data()+0);
   //BN_bn2bin(*ps, vsig.data()+32);
   //BN_free(r);
   //BN_free(s);
   //free(pr);
   //free(ps);

   /*
	// DER
	//int der_len = ECDSA_size(eckey);
	// problem here TODO!
	//byte* der = (byte*)calloc(der_len, sizeof(byte));
	int der_len = i2d_ECDSA_SIG(signature, nullptr);
	vbyte vsig(der_len, 0);
	byte* sigdata = vsig.data();
	i2d_ECDSA_SIG(signature, &sigdata);
	//i2d_ECDSA_SIG(signature, &der);
	//int conv_error = BN_bn2bin(priv, vpriv.data());
	*/

   //, BN_bn2hex(signature->s)

   ECDSA_SIG_free(signature);
   EC_KEY_free(eckey);
   EC_POINT_free(pub);
   BN_free(priv);
   BN_free(bn);
   EC_GROUP_free(ecgroup);

   return std::move(vsig);
}

// =========================
// internal implementations
// =========================

int16
lVerifySignature(
  const byte* data,
  int32 dataLength,
  const byte* signature,
  int32 signatureLength,
  const byte* pubKey,
  int32 pubKeyLength)
{
   if (signatureLength != 64)
      return -1;

   byte* realPubKey = nullptr;
   int32 realPublicKeyLength = 65;

   if (pubKeyLength == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03)) {
      // remove const from array: must make sure realPubKey data is never changed
      realPubKey = const_cast<byte*>(pubKey);
      realPublicKeyLength = 33;
   } else if (pubKeyLength == 64) {
      // 0x04 first

      // TODO: verify if no leak happens in this case
      realPubKey = new byte[65];
      realPubKey[0] = 0x04;

      memcpy(&realPubKey[1], pubKey, 64);
   } else if (pubKeyLength == 65) {
      if (pubKey[0] != 0x04)
         return -1;

      // remove const from array: must make sure realPubKey data is never changed
      realPubKey = const_cast<byte*>(data);
   } else if (pubKeyLength != 65) {
      return -1;
   }

   int32 ret = -1;
   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve);

   if (ecgroup != nullptr) {
      EC_KEY* eckey = EC_KEY_new_by_curve_name(_curve);

      if (eckey != nullptr) {
         BIGNUM* bn = BN_bin2bn(realPubKey, realPublicKeyLength, nullptr);
         EC_POINT* pub = EC_POINT_bn2point(ecgroup, bn, nullptr, nullptr);

         if (pub != nullptr) {
            int32 gen_status = EC_KEY_set_public_key(eckey, pub);

            if (gen_status == 0x01) {
               // DER encoding

               BIGNUM* r = BN_bin2bn(&signature[0], 32, nullptr);
               BIGNUM* s = BN_bin2bn(&signature[32], 32, nullptr);

               ECDSA_SIG* sig = ECDSA_SIG_new();
               gen_status = ECDSA_SIG_set0(sig, r, s);

               if (sig != nullptr) {
                  if (gen_status == 0x01) {
                     byte hash[::SHA256_LENGTH];
                     lComputeSHA256(data, dataLength, hash);
                     ret = ECDSA_do_verify(hash, ::SHA256_LENGTH, sig, eckey);
                  }

                  // Free r,s and sig

                  ECDSA_SIG_free(sig);
               } else {
                  // TODO: Check this free

                  BN_free(r);
                  BN_free(s);
               }
            }

            EC_POINT_free(pub);
            BN_free(bn);
         }
         EC_KEY_free(eckey);
      }
      EC_GROUP_free(ecgroup);
   }

   // free

   if (realPubKey != pubKey) {
      delete[](realPubKey);
   }

   return ret == 0x01 ? 0x01 : 0x00;
}

// generates private key and updates parameter vpubkey (TODO: update function format)
vbyte
Crypto::GeneratePrivateKey(vbyte& vpubkey) const
{
   //printf("generating priv/pub key\n");
   EC_KEY* eckey = EC_KEY_new();
   if (NULL == eckey) {
      NEOPT_EXCEPTION("Failed to create new EC Key");
      return vbyte(0);
   }

   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve); //NID_secp192k1);
   if (NULL == ecgroup) {
      NEOPT_EXCEPTION("Failed to create new EC Group");
      return vbyte(0);
   }

   int set_group_status = EC_KEY_set_group(eckey, ecgroup);
   const int set_group_success = 1;
   if (set_group_success != set_group_status) {
      NEOPT_EXCEPTION("Failed to set group for EC Key");
      return vbyte(0);
   }

   const int gen_success = 1;
   int gen_status = EC_KEY_generate_key(eckey);
   if (gen_success != gen_status) {
      NEOPT_EXCEPTION("Failed to generate EC Key");
      return vbyte(0);
   }

   //EC_POINT* pub = EC_KEY_get0_public_key(eckey);
   const BIGNUM* priv = EC_KEY_get0_private_key(eckey);
   vbyte vpriv(32);
   int conv_error = BN_bn2bin(priv, vpriv.data());

   /*
	char * number_str = BN_bn2hex(priv);
	printf("private_key hexstr: %s\n", number_str);
	free(number_str);
	*/

   BN_CTX* ctx;
   ctx = BN_CTX_new(); // ctx is an optional buffer to save time from allocating and deallocating memory whenever required

   // plan A
   const EC_POINT* pub_key = EC_KEY_get0_public_key(eckey);
   // plan B
   //EC_POINT* pub_key = EC_POINT_new(ecgroup);
   //if (!EC_POINT_mul(ecgroup, pub_key, priv, NULL, NULL, ctx))
   //{
   //	NEOPT_EXCEPTION("Error at EC_POINT_mul. Getting pubkey failed.");
   //	return vbyte(0);
   //}

   //printf("printing pubkey:\n");
   /*
   // print plan A
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	if (EC_POINT_get_affine_coordinates_GFp(ecgroup, pub_key, x, y, NULL)) {
		 BN_print_fp(stdout, x);
		 putc('\n', stdout);
		 BN_print_fp(stdout, y);
		 putc('\n', stdout);
	}

	// print plan B
	char *cc = EC_POINT_point2hex(ecgroup, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx);
	printf("pubkey (uncompressed): %d %s\n", strlen(cc), cc);
	std::string scc(cc);
	printf("mystr: %s\n", scc.c_str());
	vpubkey = Crypto::FromHexString(scc);
	//free(cc);
	*/

   /*
	char *cc2 = EC_POINT_point2hex(ecgroup, pub_key, POINT_CONVERSION_COMPRESSED, ctx);
	printf("pubkey (compressed): %s\n", cc2);
	free(cc2);
	*/

   // point_conversion_form_t
   vpubkey = vbyte(33);
   //byte* pubkdata = vpubkey.data();
   size_t converr = EC_POINT_point2oct(ecgroup, pub_key, POINT_CONVERSION_COMPRESSED, vpubkey.data(), vpubkey.size(), ctx);

   //     assert(EC_POINT_bn2point(group, &res, pub_key, ctx)); // Null here

   ////EC_KEY_set_public_key(eckey, pub_key);

   BN_CTX_free(ctx);
   EC_KEY_free(eckey);
   //EC_POINT_free(pub_key);
   EC_GROUP_free(ecgroup);

   return std::move(vpriv);
}

void
lComputeHash160(const byte* data, int32 length, byte* output)
{
   if (length <= 0) {
      memcpy(output, ::EMPTY_HASH160, ::HASH160_LENGTH);
      return;
   }

   byte digest[SHA256_DIGEST_LENGTH];

   // First SHA256

   lComputeSHA256(data, length, digest);

   // Then RIPEMD160

   RIPEMD160_CTX c;

   RIPEMD160_Init(&c);
   RIPEMD160_Update(&c, digest, SHA256_DIGEST_LENGTH);
   RIPEMD160_Final(output, &c);
   OPENSSL_cleanse(&c, sizeof(c));
}

void
lComputeRIPEMD160(const byte* data, int32 length, byte* output)
{
   if (length <= 0) {
      memcpy(output, ::EMPTY_RIPEMD160, ::RIPEMD160_LENGTH);
      return;
   }

   RIPEMD160_CTX c;
   RIPEMD160_Init(&c);
   RIPEMD160_Update(&c, data, length);
   RIPEMD160_Final(output, &c);
   OPENSSL_cleanse(&c, sizeof(c));
}

void
lComputeHash256(const byte* data, int32 length, byte* output)
{
   if (length <= 0) {
      memcpy(output, ::EMPTY_HASH256, ::HASH256_LENGTH);
      return;
   }

   byte digest[::SHA256_LENGTH];

   // First SHA256

   lComputeSHA256(data, length, digest);

   // Then SHA256 Again

   lComputeSHA256(digest, ::SHA256_LENGTH, output);
}

void
lComputeSHA256(const byte* data, int32 length, byte* output)
{
   if (length <= 0) {
      memcpy(output, ::EMPTY_SHA256, ::SHA256_LENGTH);
      return;
   }

   SHA256_CTX c;
   SHA256_Init(&c);
   SHA256_Update(&c, data, length);
   SHA256_Final(output, &c);
   OPENSSL_cleanse(&c, sizeof(c));
}

void handleErrors()
{
   NEOPT_EXCEPTION("ERROR IN SHA3!");
}

void
lComputeSHA3OpenSSL(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
  	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha3_256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}



void
lComputeSHA1(byte* data, int32 length, byte* output)
{
   if (length <= 0) {
      memcpy(output, ::EMPTY_SHA1, ::SHA1_LENGTH);
      return;
   }

   SHA_CTX c;
   SHA1_Init(&c);
   SHA1_Update(&c, data, length);
   SHA1_Final(output, &c);
   OPENSSL_cleanse(&c, sizeof(c));
}
