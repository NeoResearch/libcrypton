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

TEST_CASE("CryptoTest:  Test_AES_Encrypt_Decrypt_CBC_NOPadding")
{
   Crypto crypto;

   vbyte data = chelper::HexToBytes(chelper::ASCIIToHexString("00000000000000000000000000000000"));
   vbyte key = chelper::HexToBytes(chelper::ASCIIToHexString("12345678123456781234567812345678"));
   vbyte iv = chelper::HexToBytes(chelper::ASCIIToHexString("1234567812345678"));
   assert(iv.size() == 16); // 16 bytes is AES block (both CBC and CFB)
   vbyte result = libcrypton::chelper::HexToBytes("07c748cf7d326782f82e60ebe60e2fac289e84e9ce91c1bc41565d14ecb53640");

   std::cout << "message size = " << data.size() << std::endl;
   std::cout << "key size = " << key.size() << std::endl;
   std::cout << "iv size = " << iv.size() << std::endl;
   vbyte out = crypto.AESEncrypt(data, key, iv, false, false);
   std::cout << "out size = " << out.size() << std::endl;

   std::cout << "result size = " << result.size() << std::endl;

   REQUIRE(out == result);

   vbyte resultDecrypt = crypto.AESDecrypt(result,key,iv,false,false);

   std::cout << "resultDecrypt size = " << resultDecrypt.size() << std::endl;
   
   REQUIRE(data == resultDecrypt);
}


TEST_CASE("CryptoTest:  Test_AES_Encrypt_Decrypt_ECB_NOPadding")
{
   Crypto crypto;

   vbyte data = chelper::HexToBytes(chelper::ASCIIToHexString("00000000000000000000000000000000"));
   vbyte key = chelper::HexToBytes(chelper::ASCIIToHexString("1234567812345678"));
   vbyte iv = chelper::HexToBytes(chelper::ASCIIToHexString(""));
   vbyte result = libcrypton::chelper::HexToBytes("f69e0923d8247eef417d6a78944a4b39f69e0923d8247eef417d6a78944a4b39");

   std::cout << "message size = " << data.size() << std::endl;
   std::cout << "key size = " << key.size() << std::endl;
   std::cout << "iv size = " << iv.size() << std::endl;
   vbyte out = crypto.AESEncrypt(data, key, iv, false, true);
   std::cout << "out size = " << out.size() << std::endl;

   std::cout << "result size = " << result.size() << std::endl;

   REQUIRE(out == result);

   vbyte resultDecrypt = crypto.AESDecrypt(result,key,iv,false,true);

   std::cout << "resultDecrypt size = " << resultDecrypt.size() << std::endl;
   
   REQUIRE(data == resultDecrypt);
}

TEST_CASE("CryptoTest:  Test_AES_Encrypt_Decrypt_Example_OpenSSL_Padding_CBC")
{
   Crypto crypto;

   // A 256 bit key 
   std::string str_key = "01234567890123456789012345678901";

   // A 128 bit IV 
   std::string str_iv = "0123456789012345";

   // Message to be encrypted 
   std::string str_plaintext = "The quick brown fox jumps over the lazy dog";
        
   vbyte data = chelper::HexToBytes(chelper::ASCIIToHexString(str_plaintext));
   vbyte key = chelper::HexToBytes(chelper::ASCIIToHexString(str_key));
   vbyte iv = chelper::HexToBytes(chelper::ASCIIToHexString(str_iv));
   assert(iv.size() == 16); // 16 bytes is AES block (both CBC and CFB)

   vbyte vcypher = crypto.AESEncrypt(data,key,iv,true,false);


   vbyte result = libcrypton::chelper::HexToBytes("e06f63a711e8b7aa9f9440107d4680a117994380ea31d2a299b95302d439b9702c8e65a99236ec920704915cf1a98a44");
   // 0000 - e0 6f 63 a7 11 e8 b7 aa-9f 94 40 10 7d 46 80 a1   .oc.......@.}F..
   // 0010 - 17 99 43 80 ea 31 d2 a2-99 b9 53 02 d4 39 b9 70   ..C..1....S..9.p
   // 0020 - 2c 8e 65 a9 92 36 ec 92-07 04 91 5c f1 a9 8a 44   ,.e..6.....\...D

   std::cout << "message size = " << data.size() << std::endl;
   std::cout << "key size = " << key.size() << std::endl;
   std::cout << "iv size = " << iv.size() << std::endl;
   //vbyte out = crypto.AESCbcEncrypt256NoPadding(data,key,iv);
   //std::cout << "out size = " << out.size() << std::endl;

   std::cout << "result size = " << result.size() << std::endl;
   
   REQUIRE(vcypher == result);

   vbyte resultDecrypt = crypto.AESDecrypt(vcypher,key,iv,true,false);

   std::cout << "resultDecrypt size = " << resultDecrypt.size() << std::endl;
   
   REQUIRE(data == resultDecrypt);
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
