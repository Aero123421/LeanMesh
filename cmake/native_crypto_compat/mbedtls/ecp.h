/* Native-build shim, equivalent to ESP-IDF components/mbedtls/port/include/mbedtls/ecp.h minus
 * the ESP32 hardware-accelerator declarations. The Espressif TF-PSA-Crypto fork includes
 * "mbedtls/ecp.h" and relies on that IDF wrapper to reach the private header. */
#pragma once
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif
#include "mbedtls/private/ecp.h"
