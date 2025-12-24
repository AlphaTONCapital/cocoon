#pragma once

#include "openssl/x509.h"

#include "td/utils/UInt.h"

namespace sev {

struct RATLSAttestation {
  td::UInt384 measurement;
};

struct RATLSExtensions {
  X509_EXTENSION *report_data{nullptr};
  X509_EXTENSION *attestation_report{nullptr};
  X509_EXTENSION *vcek{nullptr};
};

}  // namespace sev
