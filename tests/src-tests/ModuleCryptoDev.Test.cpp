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
