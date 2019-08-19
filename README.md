# libcrypton

## CryptoN: a cryptography library on C++ for Neo blockchain ecosystem

This project is part of the [neopt](https://github.com/neoresearch/neopt) macro project, a C++ implementation of Neo Blockchain components, focused on portability.

## Try it! (for developers interested in using crypdev tool)

There's an amazing tool here, called `crypdev`, specially made for crypto developers.

To build it (on linux):
- Get submodules: `git submodule update --init --recursive` (specially gets openssl)
- to build openssl engine: `make vendor`
- to build `libcrypton` and `crypdev`: just type `make` (this will add it to `bin/crypdev`).

If you open `./bin/crypdev` you get a simple user terminal:

```
===============================================
Welcome to crypdev: a lib CryptoN tool for devs
===============================================
Type 'exit' to finish program (or 'help')

>help
crypdev command: 'help'

'help' command options: [ ]
existing commands are: 
set [ ecc hash ] [ secp256r1 | sha256 ]
gen [ ECC_TYPE ] [ keypair pubkey privkey ] [ compressed uncompressed ] [ PRIVATE_KEY ]
hash [ hash160 hash256 sha256 ripemd160 none ] [ TEXT_OR_BYTES ]
bytes [ reverse length ] [ TEXT_OR_BYTES ]
sign [ ECC_TYPE ] [ PRIVATE_KEY ] [ HASH_TYPE ] [ TEXT_OR_BYTES ] 
verify [ ECC_TYPE ] [ PUBLIC_KEY ] [ SIGNATURE ] [ HASH_TYPE ] [ TEXT_OR_BYTES ]  
rand [ BYTE_COUNT ] 
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

Reversing and counting bytes:
```
>bytes reverse 0x010203
reversed bytes: 030201
>bytes length 0x010203
length: 3
```

Other nice example is generating a random keypair for elliptic curve `secp256r1`:

```
>set ecc secp256r1
CURVE SET TO 'secp256r1'

>gen ecc keypair
public key (compressed format): 037c50d797720fefe9194ecd5b4ef3c25b3791abb45639aa8453d110bae08a945a
private key: 13043155bf3e00b6e6352ffafba9f7fa96704de08c7db2fe810a92d644199258
```

Or even better, manually generating private key (randomly) and attached public key:
```
>gen ecc privkey
private key: 914083f84a7550d7ed21da047f7cfa60c5fddad98d1156b068c48b26fbe60831

>gen ecc pubkey compressed 914083f84a7550d7ed21da047f7cfa60c5fddad98d1156b068c48b26fbe60831
public key: 023115c1e143a8f05dddceb0c6adc687c6fa942ec73122f757db811d236ef72fc0

>gen ecc pubkey uncompressed 914083f84a7550d7ed21da047f7cfa60c5fddad98d1156b068c48b26fbe60831
public key: 043115c1e143a8f05dddceb0c6adc687c6fa942ec73122f757db811d236ef72fc05a0a78e2b2278e0ca244383caf09f7a69e5f288b3b632e6466f23da71c5afc22
```

`gen ecc privkey` is equivalent to `rand 32`, for curve `secp256r1`:
```
>rand 32
generated bytes (32): 914083f84a7550d7ed21da047f7cfa60c5fddad98d1156b068c48b26fbe60831
```

Signing a payload of 50 bytes:
```
>rand 50
generated bytes (50): 9ec1171a37169a9e4b38726127730d64bed872f7840afeaf54028834e531e2d89a8d269f78eb426628f6cc3dc3ad99a2a43b

>gen ecc keypair
public key (compressed format): 02bff10e1aa6b544fd9fc07b28488425931e6a0d9c44b5f3fd6b7c2f489a9987ad
private key: 4f7f56c979e2fafbe26c5d9164066ea581b4e08a52805ca377d573a853f0aa5e

>sign ecc 4f7f56c979e2fafbe26c5d9164066ea581b4e08a52805ca377d573a853f0aa5e hash 9ec1171a37169a9e4b38726127730d64bed872f7840afeaf54028834e531e2d89a8d269f78eb426628f6cc3dc3ad99a2a43b
signature: 7b6d7a7b0738f98bfcb7f94bcc7f5e4c4dd3469d321235d52117711096360e8eb133d42831f01a603d94574b626eb68b2d3686d7e75433b8d69874bc4f3948ce

>verify ecc 02bff10e1aa6b544fd9fc07b28488425931e6a0d9c44b5f3fd6b7c2f489a9987ad 7b6d7a7b0738f98bfcb7f94bcc7f5e4c4dd3469d321235d52117711096360e8eb133d42831f01a603d94574b626eb68b2d3686d7e75433b8d69874bc4f3948ce hash 9ec1171a37169a9e4b38726127730d64bed872f7840afeaf54028834e531e2d89a8d269f78eb426628f6cc3dc3ad99a2a43b 
verification result: 1
```


Since `libcrypton` can be implemented in multiple engines, you can check underlying engine:

```
>show engine
libcrypton engine: openssl
```

#### directly executing on file or command-line (silent mode)

If you want to embed `crypdev` on any script, you can use command mode `-c`, separating commands by semi-colon:

```
./bin/crypdev -c "rand 5 ; rand 10 ; rand 1"
d070440077
a313e92ddb08a706b23a
9b
```

Some commands often require reading until end of line, so it's good to protect by adding a line break before semi-colon:

```
./bin/crypdev -c "rand 5 ; hash none 0x0001 `echo $'\n'$';'` rand 10 "
1e52f7557c
0001
afeaec7e0dac88ecfc51
```

Finally, it's even easier when reading from script file on disk (see `scriptttest.txt`):
```
cat scripttest.txt 
rand 5
hash sha256 0x0001
rand 10

./bin/crypdev -f scripttest.txt 
b2c6db7ab4
b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2
635c59ca7d16aab29eb6
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
