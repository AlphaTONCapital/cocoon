#pragma once

#include "td/utils/UInt.h"
#include "tee/cocoon/sev/RATLS.h"
#include "tee/cocoon/tdx/RATLS.h"

namespace cocoon {

class RATLSInterface {
 public:
  virtual ~RATLSInterface() = default;

 public:
  virtual td::Result<sev::RATLSAttestation> validate(const td::UInt512& user_claims,
                                                     const sev::RATLSExtensions& extensions) = 0;

  virtual td::Result<tdx::RATLSAttestation> validate(const td::UInt512& user_claims,
                                                     const tdx::RATLSExtensions& extensions) = 0;
};

}  // namespace cocoon
