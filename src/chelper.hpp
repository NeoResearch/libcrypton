#ifndef LIBCRYPTON_CHELPER_H
#define LIBCRYPTON_CHELPER_H

// Crypto Helper: chelper

// system
#include <algorithm> //std:: generate
#include <functional>
#include <iomanip>
#include <limits.h> // CHAR
#include <random>
#include <sstream>
#include <vector>

#if defined(_MSC_VER)
// supporting windows native secure memory
#include <Windows.h>
#endif

// neo core
//#include <numbers/UInt160.hpp>
//#include <system/types.h>

//using namespace std; // TODO: avoid!

namespace libcrypton {

#define CRYPTON_EXCEPTION(str)                             \
   {                                                       \
      printf("libcrypton error(%s): %s\n", __func__, str); \
      exit(1);                                             \
   }

typedef unsigned char byte;

typedef std::vector<byte> vbyte;

typedef short int16;

typedef int int32;

// SecureBytes is intended to hold bytes that are safely clean after usage (set to '0')
// It can receive rvalue references && of strings and vbytes, for interoperability (these will be cleanup automatically)
class SecureBytes final
{
private:
   libcrypton::byte* bytes_ptr;
   size_t len;

public:
   // take dead vector of pointer
   SecureBytes(vbyte&& corpse)
     : bytes_ptr{ copy_and_zero(corpse.data(), corpse.size()) }
     , len{ corpse.size() }
   {
   }

   // take dead string
   SecureBytes(std::string&& corpse)
     : bytes_ptr{ copy_and_zero((unsigned char*)corpse.c_str(), corpse.length()) }
     , len{ corpse.length() }
   {
   }

   // take dead SecureBytes
   SecureBytes(SecureBytes&& corpse)
     : bytes_ptr{ corpse.bytes_ptr }
     , len{ corpse.len }
   {
      corpse.bytes_ptr = nullptr;
      corpse.len = 0;
   }

   // copy SecureBytes
   SecureBytes(const SecureBytes& other)
     : SecureBytes(other.data(), other.size())
   {
   }

   // just copy: do not care about other! make sure '_other' is safely set to zero!
   SecureBytes(const unsigned char* _other, size_t _len)
     : bytes_ptr{ just_copy(_other, _len) }
     , len{ _len }
   {
   }

private:
   byte* just_copy(const byte* ptr, size_t len)
   {
      byte* _bytes_ptr = new byte[len];
      std::copy(ptr, ptr + len, _bytes_ptr);
      return _bytes_ptr;
   }

   byte* copy_and_zero(byte* ptr, size_t len)
   {
      byte* _bytes_ptr = new byte[len];
      std::copy(ptr, ptr + len, _bytes_ptr);
// using native windows support, if on visual studio compiler
#if defined(_MSC_VER)
      SecureZeroMemory(ptr, len); // requires "Windows.h"
#else
      std::memset(ptr, 0, len);
      // by declaring a volatile asm, compiler is likely to not optimize it out.. and this is IMPORTANT!
      escape(ptr);
#endif
      return _bytes_ptr;
   }

public:
   // get 'byte' at position 'index'
   byte at(unsigned index) const
   {
      return bytes_ptr[index];
   }

   // get internal pointer
   byte* data()
   {
      return bytes_ptr;
   }

   // get internal pointer (const)
   const byte* data() const
   {
      return bytes_ptr;
   }

   // get number of bytes in SecureBytes
   size_t size() const
   {
      return len;
   }

private:
   // using "trick" from google-benchmark talk
   // CppCon 2015: Chandler Carruth "Tuning C++: Benchmarks, and CPUs, and Compilers! Oh My!"
   // this is used in different "flavors"
   static void escape(void* p)
   {
      // TODO: verify option 'g' here... on some places it's a 'r'
      // Best to check this on profiler, as an individual project 'SecureBytes'
      asm volatile(""
                   :
                   : "g"(p)
                   : "memory");
   }
   // also useful to prevent optimizations
   static void clobber()
   {
      asm volatile(""
                   :
                   :
                   : "memory");
   }

public:
   ~SecureBytes()
   {
      if (len > 0) {
// using native windows support, if on visual studio compiler
#if defined(_MSC_VER)
         SecureZeroMemory(bytes_ptr, len); // requires "Windows.h"
#else
         std::memset(bytes_ptr, 0, len);
         // by declaring a volatile asm, compiler is likely to not optimize it out.. and this is IMPORTANT!
         escape(bytes_ptr);
#endif
         // free bytes pointer
         delete[] bytes_ptr;
         // finish with pointer reference
         bytes_ptr = nullptr;
         // is it ok to clobber after disposal?
         clobber();
      }
   }
}; // SecureBytes class

// crypto helper class
class chelper
{
public:
   static void ltrim(std::string& s)
   {
      s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
                 return !std::isspace(ch);
              }));
   }

   static void rtrim(std::string& s)
   {
      s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
                 return !std::isspace(ch);
              }).base(),
              s.end());
   }

   static void trim(std::string& s)
   {
      ltrim(s);
      rtrim(s);
   }

   static std::string
   ToHexString(const vbyte& v, bool cs = false)
   {
      //std::cout << "ToHexString!!!!" << std::endl;
      std::stringstream ss;
      // TODO: check if format is this
      for (unsigned i = 0; i < v.size(); i++) // TODO: use foreach
      {
         if (cs)
            ss << std::uppercase;
         ss << std::setfill('0') << std::setw(2) << std::hex << (int)v[i];
      }
      //std::cout << "ToHexString!!!! RESULT = " << ss.str() << std::endl;

      return ss.str();
   }

   static std::string
   ToHexString(const byte& b, bool cs = false)
   {
      return ToHexString(vbyte(1, b), cs);
   }

   static std::string
   ASCIIToHexString(const std::string& chars)
   {
      std::stringstream ss;
      for (unsigned i = 0; i < chars.size(); i++)
         ss << std::setfill('0') << std::setw(2) << std::hex << int((byte)chars[i]);
      return ss.str();
   }

   static vbyte
   HexToBytes(const std::string& hex)
   {
      // TODO: implement (begin 0x)
      //CRYPTON_EXCEPTION("Not implemented yet: HexToBytes");
      vbyte bytes(hex.length() / 2);

      for (unsigned int i = 0; i < hex.length(); i += 2) {
         std::string byteString = hex.substr(i, 2);
         byte b = (byte)strtol(byteString.c_str(), NULL, 16);
         bytes[i / 2] = b;
      }
      return bytes;
   }

   /*
   static UInt160 ToScriptHash(const vbyte& v)
   {
      CRYPTON_EXCEPTION("Not implemented: ToScriptHash");
      return UInt160();
   }
*/

   static std::string Base58CheckEncode(const vbyte& data)
   {
      CRYPTON_EXCEPTION("Not implemented: Base58CheckEncode");
      return "";
   }

   static vbyte Base58CheckDecode(std::string address)
   {
      CRYPTON_EXCEPTION("Not implemented: Base58CheckDecode");
      return vbyte(0);
   }
};

// TODO: define all operators here that are necessary
}

#endif // LIBCRYPTON_CHELPER_H
