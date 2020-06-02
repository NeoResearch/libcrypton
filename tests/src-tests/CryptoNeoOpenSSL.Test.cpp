#include <catch2/catch.hpp>

// core includes
#include <Crypto.h>
#include <ICrypto.h>
//#include<system/vhelper.hpp>
//#include<system/shelper.h>
//#include "chelper.hpp"

using namespace libcrypton;

TEST_CASE("CryptoTest:  Test_Hash160_Empty")
{
   Crypto crypto;
   vbyte v(0); // '': empty byte array
   REQUIRE(crypto.Hash160(v) == crypto.RIPEMD160(crypto.Sha256(v)));
}

TEST_CASE("CryptoTest:  Test_Hash160_Zero")
{
   Crypto crypto;
   vbyte v(1, 0); // 0x00
   REQUIRE(crypto.Hash160(v) == crypto.RIPEMD160(crypto.Sha256(v)));
}

TEST_CASE("CryptoTest:  Test_Hash256_Empty")
{
   Crypto crypto;
   vbyte v(0); // '': empty byte array
   REQUIRE(crypto.Hash256(v) == crypto.Sha256(crypto.Sha256(v)));
}

TEST_CASE("CryptoTest:  Test_AESCbcEncrypt256_10_0x58")
{
   Crypto crypto;
   
   vbyte data = chelper::HexToBytes(chelper::ASCIIToHexString("00000000000000000000000000000000"));
   vbyte key = chelper::HexToBytes(chelper::ASCIIToHexString("12345678123456781234567812345678"));
   vbyte iv = chelper::HexToBytes(chelper::ASCIIToHexString("1234567812345678"));
   assert(iv.size() == 16);
   vbyte result = libcrypton::chelper::HexToBytes("07c748cf7d326782f82e60ebe60e2fac289e84e9ce91c1bc41565d14ecb53640");
   
   REQUIRE(crypto.AESCbcEncrypt256(data,key,iv) == result);
}

TEST_CASE("CryptoTest:  Test_Hash256_Zero")
{
   Crypto crypto;
   vbyte v(1, 0); // 0x00
   REQUIRE(crypto.Hash256(v) == crypto.Sha256(crypto.Sha256(v)));
}

// verification tests

TEST_CASE("CryptoTest:  Test_SignData_EmptyMessage")
{
   Crypto crypto;
   vbyte msg(0); // '': empty message

   int countFail = 0;

   constexpr double MAX_EXEC = 10000;

   for (unsigned t = 0; t < MAX_EXEC; t++) {
      // creating private/public key pair (random each test)
      vbyte mypubkey;
      vbyte myprivkey = crypto.GenerateKeyPair(mypubkey);

      // sign empty message
      vbyte sig = crypto.SignData(crypto.Sha256(msg), myprivkey, mypubkey);

      // test if signature matches public key for message
      if (!crypto.VerifySignature(msg, sig, mypubkey))
         countFail++;
   }

   // less than 5% failures
   REQUIRE(countFail / MAX_EXEC <= 0.05);
}

TEST_CASE("CryptoTest:  Test_GeneratePublicKey")
{
   Crypto crypto;

   int countFail = 0;

   constexpr double MAX_EXEC = 10000;

   for (unsigned t = 0; t < MAX_EXEC; t++) {
      // creating private/public key pair (random each test)
      vbyte mypubkey;
      vbyte myprivkey = crypto.GenerateKeyPair(mypubkey);

      // re-generate pubkey in compressed format (= true)
      vbyte otherpub = crypto.GetPublicKeyFromPrivateKey(myprivkey, true);

      // test sizes
      REQUIRE(mypubkey.size() == otherpub.size());
      // test pubkeys
      if (mypubkey != otherpub)
         countFail++;
   }

   // less than 0% failures
   REQUIRE(countFail / MAX_EXEC <= 0.00);
}
