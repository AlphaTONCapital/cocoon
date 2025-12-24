#pragma once

#include "openssl/x509.h"

#include "td/utils/UInt.h"

namespace tdx {

struct RATLSAttestation {
  td::UInt384 image_hash;
};

struct RATLSExtensions {
  X509_EXTENSION *quota{nullptr};
  X509_EXTENSION *user_claims{nullptr};
};

}  // namespace tdx
