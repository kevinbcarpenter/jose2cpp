#pragma once

// Umbrella header — include this to get the full library.
//
// Most code only needs the unified entry points:
//   jose::sign / jose::verify              (jose/crypto/signing.hpp)
//   jose::encrypt / jose::decrypt          (jose/crypto/encryption.hpp)
//   jose::generate_*_key / random_bytes    (jose/crypto/keygen.hpp)

#include "jose/algorithm.hpp"
#include "jose/base64url.hpp"
#include "jose/error.hpp"
#include "jose/jwk.hpp"
#include "jose/secure_bytes.hpp"
#include "jose/version.hpp"

#include "jose/crypto/encryption.hpp"
#include "jose/crypto/keygen.hpp"
#include "jose/crypto/signing.hpp"

#include "jose/crypto/aes_cbc_hmac.hpp"
#include "jose/crypto/aes_gcm.hpp"
#include "jose/crypto/aes_gcm_kw.hpp"
#include "jose/crypto/aes_kw.hpp"
#include "jose/crypto/ec.hpp"
#include "jose/crypto/ecdh.hpp"
#include "jose/crypto/eddsa.hpp"
#include "jose/crypto/hmac.hpp"
#include "jose/crypto/openssl_util.hpp"
#include "jose/crypto/pbes2.hpp"
#include "jose/crypto/rsa.hpp"
