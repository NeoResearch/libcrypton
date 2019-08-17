#include <gtest/gtest.h>

// core includes
#include <Crypto.h>
#include <ICrypto.h>
//#include<system/vhelper.hpp>
//#include<system/shelper.h>

using namespace neopt;

TEST(CryptoTest, Test_Hash160_Empty)
{
   Crypto crypto;
   vbyte v(0); // '': empty byte array
   EXPECT_EQ(crypto.Hash160(v), crypto.RIPEMD160(crypto.Sha256(v)));
}

TEST(CryptoTest, Test_Hash160_Zero)
{
   Crypto crypto;
   vbyte v(1, 0); // 0x00
   EXPECT_EQ(crypto.Hash160(v), crypto.RIPEMD160(crypto.Sha256(v)));
}

TEST(CryptoTest, Test_Hash256_Empty)
{
   Crypto crypto;
   vbyte v(0); // '': empty byte array
   EXPECT_EQ(crypto.Hash256(v), crypto.Sha256(crypto.Sha256(v)));
}

TEST(CryptoTest, Test_Hash256_Zero)
{
   Crypto crypto;
   vbyte v(1, 0); // 0x00
   EXPECT_EQ(crypto.Hash256(v), crypto.Sha256(crypto.Sha256(v)));
}

// verification tests

TEST(CryptoTest, Test_SignData_EmptyMessage)
{
   Crypto crypto;
   vbyte msg(0); // '': empty message

   // creating private/public key pair (random each test)
   vbyte mypubkey;
   vbyte myprivkey = crypto.GeneratePrivateKey(mypubkey);

   // sign empty message
   vbyte sig = crypto.SignData(crypto.Sha256(msg), myprivkey, mypubkey);

   // test if signature matches public key for message
   EXPECT_EQ(crypto.VerifySignature(msg, sig, mypubkey), 1);
}

