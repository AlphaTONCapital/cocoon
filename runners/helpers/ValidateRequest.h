#pragma once

#include "common/bitstring.h"
#include "td/utils/buffer.h"
#include "td/utils/Status.h"

namespace cocoon {

td::Result<td::BufferSlice> validate_modify_request(std::string url, td::BufferSlice request, std::string *model,
                                                    td::int64 *max_tokens, const td::Bits256 *private_key,
                                                    bool client_mode);
td::Result<td::BufferSlice> validate_encrypt_answer_part(std::string url, td::BufferSlice request, std::string *model,
                                                         td::int64 *max_tokens, const td::Bits256 *private_key);

}  // namespace cocoon
