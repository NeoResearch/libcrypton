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

   SecureBytes data = chelper::HexToBytes(chelper::ASCIIToHexString("00000000000000000000000000000000"));
   SecureBytes key = chelper::HexToBytes(chelper::ASCIIToHexString("12345678123456781234567812345678"));
   SecureBytes iv = chelper::HexToBytes(chelper::ASCIIToHexString("1234567812345678"));
   assert(iv.size() == 16); // 16 bytes is AES block (both CBC and CFB)
   SecureBytes result = libcrypton::chelper::HexToBytes("07c748cf7d326782f82e60ebe60e2fac289e84e9ce91c1bc41565d14ecb53640");

   std::cout << "message size = " << data.size() << std::endl;
   std::cout << "key size = " << key.size() << std::endl;
   std::cout << "iv size = " << iv.size() << std::endl;
   SecureBytes out = crypto.AESEncrypt(data, key, iv, false, false);
   std::cout << "out size = " << out.size() << std::endl;

   std::cout << "result size = " << result.size() << std::endl;

   REQUIRE(out == result);

   SecureBytes resultDecrypt = crypto.AESDecrypt(result, key, iv, false, false);

   std::cout << "resultDecrypt size = " << resultDecrypt.size() << std::endl;

   REQUIRE(data == resultDecrypt);
}

TEST_CASE("CryptoTest:  Test_AES_Encrypt_Decrypt_ECB_NOPadding")
{
   Crypto crypto;

   SecureBytes data = chelper::HexToBytes(chelper::ASCIIToHexString("00000000000000000000000000000000"));
   SecureBytes key = chelper::HexToBytes(chelper::ASCIIToHexString("1234567812345678"));
   SecureBytes result = libcrypton::chelper::HexToBytes("f69e0923d8247eef417d6a78944a4b39f69e0923d8247eef417d6a78944a4b39");

   std::cout << "message size = " << data.size() << std::endl;
   std::cout << "key size = " << key.size() << std::endl;
   SecureBytes out = crypto.AESEncrypt(data, key, Crypto::NO_IV, false, true);
   std::cout << "out size = " << out.size() << std::endl;

   std::cout << "result size = " << result.size() << std::endl;

   REQUIRE(out == result);

   SecureBytes resultDecrypt = crypto.AESDecrypt(result, key, Crypto::NO_IV, false, true);

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

   SecureBytes data = chelper::HexToBytes(chelper::ASCIIToHexString(str_plaintext));
   SecureBytes key = chelper::HexToBytes(chelper::ASCIIToHexString(str_key));
   SecureBytes iv = chelper::HexToBytes(chelper::ASCIIToHexString(str_iv));
   assert(iv.size() == 16); // 16 bytes is AES block (both CBC and CFB)

   SecureBytes vcypher = crypto.AESEncrypt(data, key, iv, true, false);

   SecureBytes result = libcrypton::chelper::HexToBytes("e06f63a711e8b7aa9f9440107d4680a117994380ea31d2a299b95302d439b9702c8e65a99236ec920704915cf1a98a44");
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

   SecureBytes resultDecrypt = crypto.AESDecrypt(vcypher, key, iv, true, false);

   std::cout << "resultDecrypt size = " << resultDecrypt.size() << std::endl;

   REQUIRE(data == resultDecrypt);
}

TEST_CASE("CryptoTest:  Test_Scrypt64_OpenSSL")
{
   Crypto crypto;

   std::string str_pass = "password";
   std::string str_salt = "NaCl";

   SecureBytes pass = chelper::HexToBytes(chelper::ASCIIToHexString(str_pass));
   SecureBytes salt = chelper::HexToBytes(chelper::ASCIIToHexString(str_salt));

   SecureBytes derive = crypto.Scrypt64(pass, salt, 1024, 8, 16);

   SecureBytes result = libcrypton::chelper::HexToBytes("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");

   REQUIRE(derive == result);
}

TEST_CASE("CryptoTest:  Test_Scrypt64_NEO_Example")
{
   Crypto crypto;

   SecureBytes pass = libcrypton::chelper::HexToBytes("010203");
   SecureBytes salt = libcrypton::chelper::HexToBytes("040506");

   SecureBytes derive = crypto.Scrypt64(pass, salt, 32, 2, 2);

   SecureBytes result = libcrypton::chelper::HexToBytes("b6274d3a81892c24335ab46a08ec16d040ac00c5943b212099a44b76a9b8102631ab988fa07fb35357cee7b0e3910098c0774c0e97399997676d890b2bf2bb25");

   REQUIRE(derive == result);
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

   constexpr double MAX_EXEC = 10000;

   for (unsigned t = 0; t < MAX_EXEC; t++) {
      // creating private/public key pair (random each test)
      vbyte mypubkey;
      SecureBytes myprivkey = crypto.GenerateKeyPair(mypubkey);

      // sign empty message
      vbyte sig = crypto.SignData(crypto.Sha256(msg), myprivkey, mypubkey);

      // test if signature matches public key for message
      REQUIRE(crypto.VerifySignature(msg, sig, mypubkey));
   }
}

TEST_CASE("CryptoTest:  Test_GeneratePublicKey")
{
   Crypto crypto;

   constexpr double MAX_EXEC = 10000;

   for (unsigned t = 0; t < MAX_EXEC; t++) {
      // creating private/public key pair (random each test)
      vbyte mypubkey;
      SecureBytes myprivkey = crypto.GenerateKeyPair(mypubkey);

      // re-generate pubkey in compressed format (= true)
      vbyte otherpub = crypto.GetPublicKeyFromPrivateKey(myprivkey, true);

      // test sizes
      REQUIRE(mypubkey.size() == otherpub.size());
      // test pubkeys
      REQUIRE(mypubkey == otherpub);
   }
}

TEST_CASE("CryptoTest:  Test_XOR")
{
   Crypto crypto;

   // just random strings with 'hello', some random internet example
   std::string s1 = "hello";
   vbyte v1 = chelper::HexToBytes(chelper::ASCIIToHexString(s1));
   vbyte v2 = { 0x89, 0x82, 0x0B, 0x4D, 0xED };
   vbyte v3 = crypto.XOR(v1, v2);
   vbyte vexpected = { 0xE1, 0xE7, 0x67, 0x21, 0x82 };
   REQUIRE(v3 == vexpected);

   // practical testing with ones and zeroes
   vbyte vx_zero = { 0x00, 0x00, 0x00, 0x00 };
   vbyte vx_one = { 0xFF, 0xFF, 0xFF, 0xFF };
   vbyte vx1 = { 0x00, 0xFF, 0x00, 0xFF };
   vbyte vx2 = { 0xFF, 0x00, 0xFF, 0x00 };

   REQUIRE(crypto.XOR(vx1, vx2) == vx_one);
   REQUIRE(crypto.XOR(vx1, vx1) == vx_zero);
   REQUIRE(crypto.XOR(vx2, vx2) == vx_zero);
   REQUIRE(crypto.XOR(vx_one, vx_one) == vx_zero);
   REQUIRE(crypto.XOR(vx_zero, vx_zero) == vx_zero);

   // single 10101010 (0xAA) with 00000101 (0x05) -> 10101111 (0xAF)
   REQUIRE(crypto.XOR(vbyte{ 0xAA }, vbyte{ 0x05 }) == vbyte{ 0xAF });
}

TEST_CASE("CryptoTest:  Test_SecureBytes")
{
   std::string abc = "abc";
   libcrypton::SecureBytes sb{ std::move(abc) };
   //
   REQUIRE(sb.size() == 3);
   REQUIRE(sb.at(0) == 'a');
   REQUIRE(sb.at(1) == 'b');
   REQUIRE(sb.at(2) == 'c');
   //
   REQUIRE(abc.length() == 3);
   REQUIRE(abc[0] == '\0');
   REQUIRE(abc[1] == '\0');
   REQUIRE(abc[2] == '\0');
   //
   libcrypton::SecureBytes sb2{ std::move(sb) };
   //
   REQUIRE(sb.size() == 0);
   REQUIRE(sb.data() == nullptr);
   //
   REQUIRE(sb2.size() == 3);
   REQUIRE(sb2.at(0) == 'a');
   REQUIRE(sb2.at(1) == 'b');
   REQUIRE(sb2.at(2) == 'c');
   //
   vbyte xyz = { 0x01, 0x02, 0x03 };
   libcrypton::SecureBytes sb3{ std::move(xyz) };
   //
   REQUIRE(sb3.size() == 3);
   REQUIRE(sb3.at(0) == 0x01);
   REQUIRE(sb3.at(1) == 0x02);
   REQUIRE(sb3.at(2) == 0x03);
   //
   REQUIRE(xyz.size() == 3);
   REQUIRE(xyz[0] == 0x00);
   REQUIRE(xyz[1] == 0x00);
   REQUIRE(xyz[2] == 0x00);
   //
   // regular copy (the two will have same data protected with same rules)
   libcrypton::SecureBytes sb4{ sb3 };
   //
   REQUIRE(sb3.size() == 3);
   REQUIRE(sb3.at(0) == 0x01);
   REQUIRE(sb3.at(1) == 0x02);
   REQUIRE(sb3.at(2) == 0x03);
   //
   REQUIRE(sb4.size() == 3);
   REQUIRE(sb4.at(0) == 0x01);
   REQUIRE(sb4.at(1) == 0x02);
   REQUIRE(sb4.at(2) == 0x03);
}

TEST_CASE("CryptoTest:  Test_GetPubkey_from_Zero_Private")
{
   Crypto crypto;
   vbyte msg(0);                    // '': empty message
   SecureBytes myprivkey(32, 0x00); // zero big int (Big-Endian)
   //
   vbyte mypubkey = crypto.GetPublicKeyFromPrivateKey(myprivkey, true); // compressed
   //
   // BAD PRIVATE KEY CANNOT GENERATE PUBKEY!
   //
   REQUIRE(mypubkey.size() == 0);
}