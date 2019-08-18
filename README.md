# libcrypton

## CryptoN: a cryptography library on C++ for Neo blockchain ecosystem

This project is part of the [neopt](https://github.com/neoresearch/neopt) macro project, a C++ implementation of Neo Blockchain components, focused on portability.

## Try it! (for developers interested in using crypdev tool)

There's an amazing tool here, called `crypdev`, specially made for crypto developers.

To build it (on linux):
- Get submodules: `git submodule update --init --recursive` (specially gets openssl)
- build openssl engine: `mkdir -p libopenssl/build && cd libopenssl/build && cmake .. && make`
- go back to root, and type `cd ../../ && make` (this will add it to `bin/crypdev`).

If you open `./bin/crypdev` you get a simple user terminal:

```
===========================================
Welcome to crypdev: a CryptoN tool for devs
===========================================
Type 'exit' to finish program (or 'help')

>help
crypdev command: 'help'

'help' command options: [ ]
existing commands are: 
set [ curve ] [ secp256r1 ]
gen [ keypair ]
hash [ hash160 hash256 sha256 ripemd160 ] [ TEXT_OR_BYTES ]
show [ engine ]
```

One simple example is, hashing an empty string on SHA256 (or other hashes: `hash160`,`hash256`,`ripemd160`):

```
>hash sha256 ""
hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
Or hashing byte `0x00`:
```
>hash sha256 0x00
hash: 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

Other nice example is generating a random keypair for elliptic curve `secp256r1`:

```
>set curve secp256r1
CURVE SET TO 'secp256r1'

>gen keypair
public key (compressed format): 037c50d797720fefe9194ecd5b4ef3c25b3791abb45639aa8453d110bae08a945a
private key: 13043155bf3e00b6e6352ffafba9f7fa96704de08c7db2fe810a92d644199258
```

Since `libcrypton` can be implemented in multiple engines, you can check underlying engine:

```
>show engine
libcrypton engine: openssl
```

## Why chosing C/C++ language for that?
Existing frameworks use high-level languages that may not be suitable for very lightweight architectures,
such as microcontrollers with very limited computing capabilities.

C/C++ is interoperable with nearly all existing languages, so the idea is to provide modules that can be
reused on other projects (on other languages too).

**Note:** this project is still being __ported out__ of neopt, since other community projects have interest in using this special component in a very separate manner. In a few days, much more things should be here ;)

## Build Instructions
There are three intended implementations for libcrypton: native (using `csBigInteger++` library), using `cryptopp` and `libopenssl`.

### C++ Native implementation
This implementation depends on [csBigInteger](https://github.com/neoresearch/csbiginteger.cpp) C++ implementation.
On debian-based systems (or ubuntu), just type `make vendor` (it will install `libgmp-dev` package).

### OpenSSL implementation

This will depend on `libopenssl` installed. Type `make vendor` to get it.

### tests

It will also configure test library (as long as you cloned this project with `--submodules` too).
To test, just run `make test`.


## C++ Standard
Currently, C++11 is adopted, in order to keep the best compatibility between conversors and compilers. However, it is recommended to migrate to C++17 as soon as possible, if this does not break compatibility with any existing modules and tools.

Let's please follow the [CppCoreGuidelines](https://github.com/isocpp/CppCoreGuidelines).

#### vscode IDE
If using vscode IDE, it is recommended to install the following extensions:
* C/C++ (currently 0.23.0-insiders2)
* C++ Intellisense (currently 0.2.2)
* GoogleTest Adapter (currently 1.8.3)

#### C++ Format Style
The currently adopted style for C++ is `Mozilla`, with indentation level set to 3.
Recommended configuration for vscode:
```json
{
    "[cpp]": {
        "editor.tabSize" : 3,
        "editor.detectIndentation": false
    },
    "C_Cpp.clang_format_fallbackStyle": "{ BasedOnStyle : Mozilla , ColumnLimit : 0, IndentWidth: 3, AccessModifierOffset: -3}"
}
```

#### Variable Naming Style
The naming style for variables and methods is based on `C#` language.
So, CamelCase is used and `public` variables start with upper-case letters, while `private` and `local` variables start with lower-case.
The idea is to preseve maximum compatibility with reference project (which is on C#).

Anything that is beyond the scope of the reference project can use classic CamelCase `C++` naming (for example, starting variables with lower-case).

### License

Code follows `MIT License`.

Implementation `BigIntegerGMP.cpp` (class implementation of standard `BigInteger.h`) is `LGPLv3`. The reason is that this implementation depends on GNU MP Bignum Library (licensed LGPLv3 since version 6), what means that all modifications of `BigIntegerGMP.cpp`, or usage of its code (even partially) on other projects should also adopt `LGPLv3` (not MIT License).

Implementation `BigIntegerMono.cpp` depends on Mono license, which is also MIT License.

The binaries generated by this project (`nvm3_native.so` or `nvm3_mono.so`) can be freely used on other projects, regardless of license.
