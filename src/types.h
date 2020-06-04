

#include <vector>

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

} // namespace libcrypton