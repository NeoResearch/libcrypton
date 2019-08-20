#include <gtest/gtest.h>

// core includes
#include <ModuleCryptoDev.hpp>

using namespace libcrypton;

TEST(ModuleCryptoDevTest, Test_Hash_SHA256_Empty)
{
   ModuleCryptoDev cdev;

   std::string params = "hash sha256 \"\"";
   std::istringstream ss(params);

   std::ostringstream sout;

   int r = cdev.executeFromStream(ss, sout, false);
   EXPECT_EQ(r, 0); // good execution
   std::string out = sout.str();
   chelper::trim(out);
   // sha256 for empty bytearray
   EXPECT_EQ(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(ModuleCryptoDevTest, Test_Hash_SHA256_0x00)
{
   ModuleCryptoDev cdev;

   std::string params = "hash sha256 0x00";
   std::istringstream ss(params);

   std::ostringstream sout;

   int r = cdev.executeFromStream(ss, sout, false);
   EXPECT_EQ(r, 0); // good execution
   std::string out = sout.str();
   chelper::trim(out);
   // sha256 for 0x00
   EXPECT_EQ(out, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
}

TEST(ModuleCryptoDevTest, Test_Set_Hash)
{
   ModuleCryptoDev cdev;

   std::istringstream ss1("set hash sha256");
   std::ostringstream sout1;
   int r1 = cdev.executeFromStream(ss1, sout1, false);
   EXPECT_EQ(r1, 0); // good execution

   std::istringstream ss2("show hash");
   std::ostringstream sout2;
   int r2 = cdev.executeFromStream(ss2, sout2, false);
   EXPECT_EQ(r2, 0); // good execution

   std::string out = sout2.str();
   chelper::trim(out);
   EXPECT_EQ(out, "sha256");
}

TEST(ModuleCryptoDevTest, Test_Sign_Verify_Random_32_Message_50_secp256r1)
{
   ModuleCryptoDev cdev;

   // TODO: test 'gen ecc keypair' (requires two output lines)

   std::istringstream ss1("rand 32");
   std::ostringstream sout1;
   EXPECT_EQ(cdev.executeFromStream(ss1, sout1, false), 0); // good execution
   std::string out1 = sout1.str();
   chelper::trim(out1); // privkey

   std::stringstream ss_gen_pubkey;
   ss_gen_pubkey << "gen ecc pubkey compressed " << out1;
   std::istringstream ss2(ss_gen_pubkey.str());
   std::ostringstream sout2;
   EXPECT_EQ(cdev.executeFromStream(ss2, sout2, false), 0); // good execution
   std::string out2 = sout2.str();
   chelper::trim(out2); // pubkey compressed

   // payload has 50 bytes
   std::istringstream ss3("rand 50");
   std::ostringstream sout3;
   EXPECT_EQ(cdev.executeFromStream(ss3, sout3, false), 0); // good execution
   std::string out3 = sout3.str();
   chelper::trim(out3); // message

   std::stringstream ss_sign;
   ss_sign << "sign ecc " << out1 << " sha256 " << out3;
   std::istringstream ss4(ss_sign.str());
   std::ostringstream sout4;
   EXPECT_EQ(cdev.executeFromStream(ss4, sout4, false), 0); // good execution
   std::string out4 = sout4.str();
   chelper::trim(out4); // signature

   std::stringstream ss_verify;
   ss_verify << "verify ecc " << out2 << " " << out4 << " sha256 " << out3;
   std::istringstream ss5(ss_verify.str());
   std::ostringstream sout5;
   EXPECT_EQ(cdev.executeFromStream(ss5, sout5, false), 0); // good execution
   std::string out5 = sout5.str();
   chelper::trim(out5); // true or false

   EXPECT_EQ(out5, "1");
}