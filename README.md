# README for MbedTLS_wrapper
Mbed TLS uses macros to handle data between values and memory in a specific byte-order (endianness).
Until about version 3.., these macros weren't optimized, neither to the endiannes of the system, fast intrinsic processor functions or optimized library functions.
In the long-time support version **2.28.x** these macros were collected to one file (common.h) with the possibilty to replace them.
This option is used with this .h file:)

ARM intrinsic functions and GNU library functions are supported to make the swap functions more efficient.
In the Mbed TLS branch 3.5.x you can find optimizations for clang and MSVC (in file alignment.h).
Include new optimizations at:
```c
// add optimizations for other systems here
```

An automatic endianness detection is supported for the ARM (CMSIS) and GNU library.
Include endianness detection for other librarys/systems at:
```c
// add detection for other systems here
```

## Usage
Include the .h file in your Mbed TLS config file - ```MBEDTLS_CONFIG_FILE```
```c
#include "mbedtls_swaper.h"
```
## Troubleshooting
If the endianness detection failed, you can define it manually before including this .h file:
```c
#define MBEDTLS_IS_BIG_ENDIAN true/false
```
Example to check the endianness manually on the target system (alignment.h):
```c
static const uint16_t mbedtls_byte_order_detector = { 0x0100 };
if(*((unsigned char *) (&mbedtls_byte_order_detector)) == 0x01) {
    // set MBEDTLS_IS_BIG_ENDIAN true
}
else {
    // set MBEDTLS_IS_BIG_ENDIAN true
}
```
