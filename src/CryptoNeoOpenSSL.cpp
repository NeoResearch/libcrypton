#include <Crypto.h>

// third-party includes
#include <openssl/obj_mac.h> // for NID_secp192k1

#include <openssl/aes.h>
#include <openssl/ec.h>    // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h> // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <openssl/evp.h> // sha-3 (unknown if keccak or post-keccak / NIST SHA-3)
#include <openssl/kdf.h> // scrypt

#include <iostream>

#include <openssl/rand.h>

#include <assert.h>

using namespace libcrypton;
//using namespace std; // do not use

SecureBytes Crypto::NO_IV = std::move(vbyte{}); // empty array representing NO_IV

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

void
handleErrors()
{
   CRYPTON_EXCEPTION("ERROR IN libcrypton!");
}

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

int
lAESEncrypt(const byte* plaintext, int32 plaintext_len, const byte* key, int32 keylength, byte* iv, int32 ivlength, byte* ciphertext, int32 outlength, bool padding, bool ecb);
int
lAESDecrypt(const byte* ciphertext, int32 ciphertext_len, const byte* key, int32 keylength, byte* iv, int32 ivlength, byte* plaintext, int32 plaintext_len, bool padding, bool ecb);
int
lScrypt64(const byte* pass, const int32 pass_len, const byte* salt, const int32 salt_len, const uint64_t n, const uint32_t r, const uint32_t p, byte* derive, size_t derive_len);

void
lComputeSHA3OpenSSL(const unsigned char* message, size_t message_len, unsigned char** digest, unsigned int* digest_len);

void
lComputeKeccak(const unsigned char* message, size_t message_len, vbyte& digest);

// -1=ERROR , 0= False , 1=True
static int16
lVerifySignature(const byte* data, int32 dataLength, const byte* signature, int32 signatureLength, const byte* pubKey, int32 pubKeyLength, bool useSha256);

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

std::string
Crypto::GetEngine() const
{
   return "openssl";
}

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
Crypto::VerifySignature(const vbyte& message, const vbyte& signature, const vbyte& pubkey, bool useSha256) const
{
   int16 ret = lVerifySignature(message.data(), message.size(), signature.data(), signature.size(), pubkey.data(), pubkey.size(), useSha256);
   if (ret == -1)
      CRYPTON_EXCEPTION("ERROR ON VerifySignature");
   return ret == 1;
}

vbyte
Crypto::Sha256(const vbyte& message) const
{
   vbyte voutput(SHA256_LENGTH);
   lComputeSHA256(message.data(), message.size(), voutput.data());
   return voutput;
}

vbyte
Crypto::Sha3NIST(const vbyte& message) const
{
   //lComputeSHA3(message.data(), message.size(), voutput.data());
   unsigned char* digest;
   unsigned int digest_len;
   lComputeSHA3OpenSSL(message.data(), message.size(), &digest, &digest_len);
   vbyte voutput(digest, digest + digest_len);
   return voutput;
}

vbyte
Crypto::RIPEMD160(const vbyte& message) const
{
   vbyte voutput(RIPEMD160_LENGTH);
   lComputeRIPEMD160(message.data(), message.size(), voutput.data());
   return voutput;
}

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

SecureBytes
Crypto::AESEncrypt(const SecureBytes& message, const SecureBytes& key, const SecureBytes& iv, bool padding, bool ecb) const
{
   // must guarantee there's enough room for: 'message.size()' + cipher_block_size
   //
   const size_t encslength = ((message.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
   //
   // Note that, when 'nopadding' option is activated, one would never use extra block (see example below)
   //    const size_t encslength = ((message.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
   //
   // Anyway, we should guarantee enough space for both padding and nopadding modes, and we adjust real size after execution.
   //
   if (ecb && (iv.size() > 0))
      return vbyte{}; // do not pass 'IV' to 'ECB' Mode.

   vbyte voutput(encslength, 0x00);
   int real_size = lAESEncrypt(message.data(), message.size(), key.data(), key.size(), (unsigned char*)iv.data(), iv.size(), voutput.data(), voutput.size(), padding, ecb);
   std::cout << "given size: " << voutput.size() << " out_size=" << real_size << std::endl;
   vbyte realout(voutput.begin(), voutput.begin() + real_size);
   //assert(voutput.size() == real_size);
   return realout;
   //return voutput;
}

SecureBytes
Crypto::AESDecrypt(const SecureBytes& cyphertext, const SecureBytes& key, const SecureBytes& iv, bool padding, bool ecb) const
{
   // must guarantee there's enough room for: 'cyphertext.size()' + cipher_block_size
   // https://www.openssl.org/docs/man1.1.1/man3/EVP_DecryptUpdate.html
   //
   const size_t plaintextsize = ((cyphertext.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
   //
   vbyte voutput(plaintextsize, 0x00);
   //
   if (ecb && (iv.size() > 0))
      return vbyte{}; // do not pass 'IV' to 'ECB' Mode.

   int real_size = lAESDecrypt(cyphertext.data(), cyphertext.size(), key.data(), key.size(), (unsigned char*)iv.data(), iv.size(), voutput.data(), voutput.size(), padding, ecb);
   std::cout << "given size: " << voutput.size() << " out_size=" << real_size << std::endl;
   vbyte realout(voutput.begin(), voutput.begin() + real_size);
   //assert(voutput.size() == real_size);
   return realout;
}

SecureBytes
Crypto::Scrypt64(const SecureBytes& pass, const SecureBytes& salt, const int n, const int r, const int p) const
{
   vbyte voutput(64, 0x00);
   int real_size = lScrypt64(pass.data(), pass.size(), salt.data(), salt.size(), n, r, p, voutput.data(), voutput.size());
   //std::cout << "given size: " << voutput.size() << " out_size=" << real_size << std::endl;
   //vbyte realout(voutput.begin(), voutput.begin() + real_size);
   //assert(voutput.size() == real_size);
   return voutput;
}

// message is already received as a SHA256 digest
// TODO: better to receive pubkey in general format or specific ECPoint(X,Y) ?
vbyte
Crypto::SignData(const vbyte& digest, const SecureBytes& privkey, const vbyte& pubkey, bool verify) const
{
   // only compressed pubkey is accepted for the moment
   if ((privkey.size() != 32) || (pubkey.size() != 33)) {
      std::cout << "WARNING: libcrypton SignData bad inputs!" << std::endl;
      return vbyte{};
   }
   //printf("\n\nSignData\n");
   // TODO: implement low level lSignData? (or keep C++ mixed?)
   // TODO: apply SHA256 here to make sure?
   const byte* hash = digest.data();
   int hashLen = 32;
   if (digest.size() != hashLen) {
      CRYPTON_EXCEPTION("Failed to have digest of 32 bytes for SignData");
      return vbyte(0);
   }
   const byte* pubKey = pubkey.data();
   int pubKeyLength = pubkey.size();
   const byte* mypriv = privkey.data();

   // initialize environment and initialize private key
   EC_KEY* eckey = EC_KEY_new();
   if (NULL == eckey) {
      CRYPTON_EXCEPTION("Failed to create new EC Key");
      return vbyte(0);
   }

   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve); //NID_secp192k1);
   if (NULL == ecgroup) {
      CRYPTON_EXCEPTION("Failed to create new EC Group");
      return vbyte(0);
   }

   int set_group_status = EC_KEY_set_group(eckey, ecgroup);
   const int set_group_success = 1;
   if (set_group_success != set_group_status) {
      CRYPTON_EXCEPTION("Failed to set group for EC Key");
      return vbyte(0);
   }

   BIGNUM* bn = BN_bin2bn(&pubKey[0], pubKeyLength, nullptr);
   EC_POINT* pub = EC_POINT_bn2point(ecgroup, bn, nullptr, nullptr);
   BIGNUM* priv = BN_bin2bn(&mypriv[0], 32, nullptr);

   if (pub != nullptr) {
      int32 gen_status = EC_KEY_set_public_key(eckey, pub);
      int32 gen_status2 = EC_KEY_set_private_key(eckey, priv);
   }

   ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, eckey);
   if (NULL == signature) {
      CRYPTON_EXCEPTION("Failed to generate EC Signature\n");
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

   int rBytes = BN_num_bytes(r);
   int sBytes = BN_num_bytes(s);
   vbyte vsig(64, 0x00);
   BN_bn2bin(r, vsig.data() + 32 - rBytes); // Place R first in the buffer
   BN_bn2bin(s, vsig.data() + 64 - sBytes); // Place S last in the buffer

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

   int16 verif = 1;
   if (verify) {
      // ===============================
      // check signature (paranoid mode)
      // ===============================
      // verify here if signature matches with 'useSha256 = false'
      //
      verif = lVerifySignature(digest.data(), digest.size(), vsig.data(), vsig.size(), pubkey.data(), pubkey.size(), false);
      //
      // ===============================
   }

   ECDSA_SIG_free(signature);
   EC_KEY_free(eckey);
   EC_POINT_free(pub);
   BN_free(priv);
   BN_free(bn);
   EC_GROUP_free(ecgroup);

   if (verif != 1) {
      std::cout << "WARNING: libcrypton Signature not verified!" << std::endl;
      return vbyte{};
   } else
      return vsig;
}

// =========================
// internal implementations
// =========================

int16
lVerifySignature(const byte* data, int32 dataLength, const byte* signature, int32 signatureLength, const byte* pubKey, int32 pubKeyLength, bool useSha256)
{
   if ((!useSha256) && (dataLength != 32)) {
      std::cout << "WARNING: libcrypton not using SHA256 on verify with size not 32..." << std::endl;
   }

   if (signatureLength != 64)
      return -1;

   int32 ret = -1;
   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve);

   if (ecgroup != nullptr) {
      EC_KEY* eckey = EC_KEY_new_by_curve_name(_curve);

      if (eckey != nullptr) {
         BIGNUM* bn = BN_bin2bn(&pubKey[0], pubKeyLength, nullptr);
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
                     if (useSha256) {
                        byte hash[::SHA256_LENGTH];
                        lComputeSHA256(data, dataLength, hash);
                        ret = ECDSA_do_verify(hash, ::SHA256_LENGTH, sig, eckey);
                     } else
                        ret = ECDSA_do_verify(data, ::SHA256_LENGTH, sig, eckey);
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

   return ret == 0x01 ? 0x01 : 0x00;
}

// generates private key and updates parameter vpubkey (TODO: update function format)
SecureBytes
Crypto::GenerateKeyPair(vbyte& vpubkey) const
{
   //printf("generating priv/pub key\n");
   EC_KEY* eckey = EC_KEY_new();
   if (NULL == eckey) {
      CRYPTON_EXCEPTION("Failed to create new EC Key");
      return vbyte(0);
   }

   EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(_curve); //NID_secp192k1);
   if (NULL == ecgroup) {
      CRYPTON_EXCEPTION("Failed to create new EC Group");
      return vbyte(0);
   }

   int set_group_status = EC_KEY_set_group(eckey, ecgroup);
   const int set_group_success = 1;
   if (set_group_success != set_group_status) {
      CRYPTON_EXCEPTION("Failed to set group for EC Key");
      return vbyte(0);
   }

   const int gen_success = 1;
   int gen_status = EC_KEY_generate_key(eckey);
   if (gen_success != gen_status) {
      CRYPTON_EXCEPTION("Failed to generate EC Key");
      return vbyte(0);
   }

   const BIGNUM* priv = EC_KEY_get0_private_key(eckey);
   // Big-Endian private key from 'BN_bn2bin()'
   // beware that 'priv' may be smaller than 32... example: 0x00010203...
   int usedSize = BN_num_bytes(priv);
   SecureBytes vpriv(32, 0x00);
   int realSize = BN_bn2bin(priv, vpriv.data() + (32 - usedSize));
   //std::copy(vpriv1.data(), vpriv1.data()+realSize, vpriv.data()+(32-realSize));
   //std:: cout << "size bn priv: " << realSize << std::endl;

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
   //	CRYPTON_EXCEPTION("Error at EC_POINT_mul. Getting pubkey failed.");
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

   // =================================================================
   // ================= CHECK PRIVATE AND PUBLIC KEYS =================
   //
   // test simple signature
   vbyte testMsg = this->RandBytes(32).ToUnsafeBytes();
   //vbyte testMsg = {0x01, 0x02, 0x03};
   vbyte sign1 = SignData(testMsg, vpriv, vpubkey);
   bool vsig = VerifySignature(testMsg, sign1, vpubkey, false); // do NOT use sha256
   // clean 'testMsg' and 'sign1' (get rid of everything...)
   memset(testMsg.data(), 0, testMsg.size());
   SecureBytes::escape(testMsg.data());
   // TODO: may also use cleaning from OpenSSL here...
   memset(sign1.data(), 0, sign1.size());
   SecureBytes::escape(sign1.data());
   // TODO: may also use cleaning from OpenSSL here...
   //
   // get compressed pubkey from this private key (just generated...)
   vbyte newPub = GetPublicKeyFromPrivateKey(vpriv, true);
   if (vsig && (newPub == vpubkey)) {
      return vpriv; // all is fine!
   }

   else {
      std::cout << "WARNING: verify when getpubkey is eventually not same as gen keypair on openssl" << std::endl;
      std::cout << "vsig = " << vsig << std::endl;
      std::cout << "newPub = " << chelper::ToHexString(newPub) << std::endl;
      std::cout << "vpubkey = " << chelper::ToHexString(vpubkey) << std::endl;
      return GenerateKeyPair(vpubkey); // try again!
   }
}

vbyte
Crypto::GetPublicKeyFromPrivateKey(const SecureBytes& priv, bool compressed) const
{
   if (priv.size() != 32)
      return vbyte{}; // ERROR
   // ctx is optional buffer
   BN_CTX* ctx = BN_CTX_new();
   // 'res' will receive private key value
   BIGNUM* res = BN_new();
   // convert 'priv' to hexstring (uppercase = true)
   // TODO: avoid 'ToUnsafeBytes' and support a 'ToHexString' directly from SecureBytes
   // TODO: remember to zero-fill 'spriv' after that.
   std::string spriv = chelper::ToHexString(priv.ToUnsafeBytes(), true);
   // create big integer from hexstring on 'priv'
   int r = BN_hex2bn(&res, spriv.c_str());
   // define working curve (secp256r1)
   EC_KEY* eckey = EC_KEY_new_by_curve_name(_curve);
   const EC_GROUP* group = EC_KEY_get0_group(eckey);
   EC_POINT* pub_key = EC_POINT_new(group);

   EC_KEY_set_private_key(eckey, res);

   if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx)) {
      CRYPTON_EXCEPTION("Error at EC_POINT_mul.\n");
      return vbyte(0);
   }

   int out = EC_KEY_set_public_key(eckey, pub_key);
   if (out == 0) {
      std::cout << "WARNING: libcrypton error on pubkey set" << std::endl;
      return vbyte{};
   }

   char* cc;

   if (compressed)
      cc = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_COMPRESSED, ctx); // point_conversion_form_t
   else
      cc = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx); // point_conversion_form_t

   // hex to bytes
   std::string str(cc);

   vbyte vpubkey = chelper::HexToBytes(str);

   if (compressed ? (vpubkey.size() != 33) : (vpubkey.size() != 64)) {
      std::cout << "WARNING: libcrypton some strange pubkey occurred!" << std::endl;
      std::cout << "c = '" << cc << "'  str='" << str << "'" << std::endl;
      return vbyte{};
   }

   BN_CTX_free(ctx);

   OPENSSL_free(cc);

   EC_KEY_free(eckey);

   return vpubkey;
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

static void
hex_print(const void* pv, size_t len)
{
   const unsigned char* p = (const unsigned char*)pv;
   if (NULL == pv)
      printf("NULL");
   else {
      size_t i = 0;
      for (; i < len; ++i)
         printf("%02X ", *p++);
   }
   printf("\n");
}

int
lAESEncrypt(const byte* plaintext, int32 plaintext_len, const byte* key, int32 keylength, byte* iv, int32 ivlength, byte* ciphertext, int32 outlength, bool padding, bool ecb)
{
   std::cout << "" << std::endl;
   std::cout << "inputs length: " << plaintext_len << std::endl;
   std::string strplain((char*)plaintext, plaintext_len);
   std::cout << "plaintext: '" << strplain << "'" << std::endl;
   std::cout << "keylength: " << keylength << std::endl;
   std::cout << "ivlength: " << ivlength << std::endl;
   std::cout << "outlength: " << outlength << std::endl;
   std::cout << "AES_BLOCK_SIZE: " << AES_BLOCK_SIZE << std::endl;

   //const size_t encslength = ((plaintext_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
   // ===========================================================
   // See -1 (in 'AES_BLOCK_SIZE - 1')... NO PADDING.. may be necessary in some situations!
   // DO NOT DO THAT!
   //
   // https://stackoverflow.com/questions/18152913/aes-aes-cbc-128-aes-cbc-192-aes-cbc-256-encryption-decryption-with-openssl-c/18158278
   /*
   @Puffin that is NOT correct. There must be room for up to one full block of padding. 
   That's how PKCS#5 padding works. Anything that "works" for you without taking that case into 
   account does so only because the plaintext being encrypted is not an exact multiple 
   of the AES block size (16 bytes), and is consequently a ticking time bomb for when that 
   case eventually arrises. See PKCS5/7 padding here, and specifically, the paragraph describing 
   what happens when an exact block-size multiple is encountered. 
   */
   // ===========================================================
   //
   // TODO: use methods with EVP prefix to avoid padding (explicitly)
   // No padding leaks info on size.
   // https://stackoverflow.com/questions/20000749/aes-encryption-of-16-bytes-without-padding
   /*
   So your steps are:
    Call EVP_CIPHER_CTX_new to create a context
    Call EVP_EncryptInit_ex with the context
    Call EVP_CIPHER_CTX_set_padding on the context
    Call EVP_EncryptUpdate_ex to encrypt the data
    Call EVP_EncryptFinal_ex to retrieve the cipher text
   */
   // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
   // ===========================================================

   EVP_CIPHER_CTX* ctx;

   int len;

   int ciphertext_len;

   /* Create and initialise the context */
   if (!(ctx = EVP_CIPHER_CTX_new()))
      handleErrors();

   /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
   if (ecb) {
      std::cout << "MODE ECB: " << ecb << std::endl;
      int result;
      switch (keylength) {
         case 32:
            result = EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
         case 16:
            result = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
      }
      if (1 != result)
         handleErrors();
   } else {
      std::cout << "MODE CBC: " << !ecb << std::endl;
      assert(keylength == 32);
      assert(keylength * 8 == 256);
      assert(AES_BLOCK_SIZE == 16);
      assert(ivlength == AES_BLOCK_SIZE);
      if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
         handleErrors();
   }

   if (!padding) {
      assert(plaintext_len % 16 == 0); // assert that input is multiply since no padding
      // disable padding
      if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
         handleErrors();
   }

   /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
   if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
      handleErrors();
   ciphertext_len = len;

   /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
   if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
      handleErrors();
   ciphertext_len += len;

   /* Clean up */
   EVP_CIPHER_CTX_free(ctx);

   std::cout << "USED: " << ciphertext_len << std::endl;
   return ciphertext_len;
}

int
lAESDecrypt(const byte* ciphertext, int32 ciphertext_len, const byte* key, int32 keylength, byte* iv, int32 ivlength, byte* plaintext, int32 plaintext_len, bool padding, bool ecb)
{
   // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Padding

   EVP_CIPHER_CTX* ctx;

   int len;

   /* Create and initialise the context */
   if (!(ctx = EVP_CIPHER_CTX_new()))
      handleErrors();

   /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
   if (ecb) {
      std::cout << "MODE ECB: " << ecb << std::endl;
      int result;
      switch (keylength) {
         case 32:
            result = EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
         case 16:
            result = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
      }
      if (1 != result)
         handleErrors();
   } else {
      std::cout << "MODE CBC: " << !ecb << std::endl;
      assert(keylength == 32);
      assert(keylength * 8 == 256);
      assert(AES_BLOCK_SIZE == 16);
      assert(ivlength == AES_BLOCK_SIZE);
      if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
         handleErrors();
   }

   if (!padding) {
      assert(plaintext_len % 16 == 0); // assert that input is multiply since no padding
      // disable padding
      if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
         handleErrors();
   }

   /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
   if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
      handleErrors();
   plaintext_len = len;

   /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
   if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
      handleErrors();
   plaintext_len += len;

   /* Clean up */
   EVP_CIPHER_CTX_free(ctx);

   return plaintext_len;
}

int
lScrypt64(const byte* pass, const int32 pass_len, const byte* salt, const int32 salt_len, const uint64_t n, const uint32_t r, const uint32_t p, byte* derive, size_t derive_len)
{
   EVP_PKEY_CTX* pctx;
   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

   if (EVP_PKEY_derive_init(pctx) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_derive_init");
   }
   if (EVP_PKEY_CTX_set1_pbe_pass(pctx, pass, pass_len) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_CTX_set1_pbe_pass");
   }
   if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, salt_len) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_CTX_set1_scrypt_salt");
   }
   if (EVP_PKEY_CTX_set_scrypt_N(pctx, n) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_CTX_set_scrypt_N");
   }
   if (EVP_PKEY_CTX_set_scrypt_r(pctx, r) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_CTX_set_scrypt_r");
   }
   if (EVP_PKEY_CTX_set_scrypt_p(pctx, p) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_CTX_set_scrypt_p");
   }
   if (EVP_PKEY_derive(pctx, derive, &derive_len) <= 0) {
      CRYPTON_EXCEPTION("EVP_PKEY_derive");
   }
   EVP_PKEY_CTX_free(pctx);
   return derive_len;

   /* Openssl KDP 3.0
   EVP_KDF* kdf;
   EVP_KDF_CTX* kctx;
   OSSL_PARAM params[6], *p = params;
   kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
   kctx = EVP_KDF_CTX_new(kdf);
   EVP_KDF_free(kdf);
   *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                            pass,
                                            pass_len);
   *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                            salt,
                                            salt_len);
   *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, n);
   *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, r);
   *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, p);
   *p = OSSL_PARAM_construct_end();

   if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
      CRYPTON_EXCEPTION("EVP_KDF_CTX_set_params");
   }
   if (EVP_KDF_derive(kctx, derive, derive_len) <= 0) {
      CRYPTON_EXCEPTION("EVP_KDF_derive");
   }
   EVP_KDF_CTX_free(kctx);
   return derive_len;
   */
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

void
lComputeSHA3OpenSSL(const unsigned char* message, size_t message_len, unsigned char** digest, unsigned int* digest_len)
{
   EVP_MD_CTX* mdctx;

   if ((mdctx = EVP_MD_CTX_create()) == NULL)
      handleErrors();

   if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
      handleErrors();

   if (1 != EVP_DigestUpdate(mdctx, message, message_len))
      handleErrors();

   if ((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha3_256()))) == NULL)
      handleErrors();

   if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
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
