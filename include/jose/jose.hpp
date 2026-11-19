#pragma once

/// @file
/// Umbrella header: include this to get the full library.
///
/// Most code wants jose::jwt (jwt.hpp) for tokens, jose::jws and jose::jwe
/// (jws.hpp, jwe.hpp) for signing and encryption in general, and
/// jose::jwk (jwk.hpp) for keys. The algorithms underneath are in
/// jose/crypto/: jose::sign and jose::verify (signing.hpp), jose::encrypt
/// and jose::decrypt (encryption.hpp), and key generation (keygen.hpp).

#include "jose/algorithm.hpp"
#include "jose/async.hpp"
#include "jose/base64url.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwe.hpp"
#include "jose/jwk.hpp"
#include "jose/jws.hpp"
#include "jose/jwt.hpp"
#include "jose/opaque.hpp"
#include "jose/secure_bytes.hpp"
#include "jose/task.hpp"
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
