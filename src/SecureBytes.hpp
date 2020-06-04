#ifndef LIBCRYPTON_SECUREBYTES_HPP
#define LIBCRYPTON_SECUREBYTES_HPP

#if defined(_MSC_VER)
// supporting windows native secure memory
#include <Windows.h>
#endif

#include "types.h"

namespace libcrypton {

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

   // space initialization
   SecureBytes(size_t _len, byte default_value = 0x00)
     : bytes_ptr{ new byte[_len] }
     , len{ _len }
   {
      // set values to default
      memset(this->bytes_ptr, default_value, _len);
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

public:
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

   bool operator==(const SecureBytes& sb) const
   {
      if (this->len != sb.len)
         return false;
      for (unsigned i = 0; i < this->len; i++)
         if (this->bytes_ptr[i] != sb.bytes_ptr[i])
            return false;
      return true;
   }

   bool operator!=(const SecureBytes& sb) const
   {
      return !((*this) == sb);
   }

   // returns copy of unsafe string (please properly zero-fill this string when used)
   std::string ToUnsafeString() const
   {
      return std::string((char*)this->bytes_ptr, (char*)this->bytes_ptr + this->len);
   }

   // returns copy of unsafe bytearray (please properly zero-fill this array when used)
   vbyte ToUnsafeBytes() const
   {
      return vbyte(this->bytes_ptr, this->bytes_ptr + this->len);
   }

}; // SecureBytes class
//
} // namespace libcrypton

#endif // LIBCRYPTON_SECUREBYTES_HPP