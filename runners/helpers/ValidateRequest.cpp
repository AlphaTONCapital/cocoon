#include "ValidateRequest.h"
#include "Ed25519.h"
#include "checksum.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "nlohmann/detail/input/json_sax.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Random.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Status.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/misc.h"
#include "tdport/td/e2e/MessageEncryption.h"
#include "runners/helpers/Ton.h"

#include <memory>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <set>

namespace cocoon {

static td::Result<td::SecureString> generate_shared_secret(const td::Bits256 &pk_b256, const td::Bits256 &pub_b256,
                                                           const td::Bits256 &expected_public_key, td::Slice nonce,
                                                           bool client_to_worker) {
  td::Ed25519::PrivateKey pk(td::SecureString{pk_b256.as_slice()});
  {
    TRY_RESULT(v, pk.get_public_key());
    if (v.as_octet_string().as_slice() != expected_public_key.as_slice()) {
      return td::Status::Error(ton::ErrorCode::error, "public key mismatch");
    }
  }

  td::Ed25519::PublicKey pub(td::SecureString{pub_b256.as_slice()});
  TRY_RESULT(shared_secret, td::Ed25519::compute_shared_secret(pub, pk));

  td::SecureString tmp(32 + nonce.size() + 1);

  tmp.as_mutable_slice().copy_from(shared_secret.as_slice());
  tmp.as_mutable_slice().remove_prefix(32).copy_from(nonce);
  tmp.as_mutable_slice().remove_prefix(32 + nonce.size()).copy_from(client_to_worker ? "c" : "w");
  auto val = td::sha256_bits256(tmp.as_slice());
  return td::SecureString(val.as_slice());
}

static const std::vector<std::string> json_encryption_related_str_fields{"is_encrypted", "sender_public_key",
                                                                         "receiver_public_key", "encryption_nonce"};
static const std::vector<std::string> do_not_encrypt_fields{"model", "debug"};

bool should_encrypt_field(td::Slice name) {
  for (const auto &s : json_encryption_related_str_fields) {
    if (s == name) {
      return false;
    }
  }
  for (const auto &s : do_not_encrypt_fields) {
    if (s == name) {
      return false;
    }
  }
  return true;
}

static td::Result<std::string> decrypt_string(td::Slice S, td::Slice secret) {
  auto encryption_type = S.copy().truncate(4);
  S.remove_prefix(4);

  if (encryption_type == "ENC_") {
    TRY_RESULT(v, td::hex_decode(S));
    TRY_RESULT(res, tde2e_core::MessageEncryption::decrypt_data(v, secret));
    return res.as_slice().str();
  } else if (encryption_type == "DEC_") {
    return S.str();
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "bad encryption method: " << S);
  }
}

static std::string encrypt_string(td::Slice S, td::Slice secret) {
  auto enc_value = tde2e_core::MessageEncryption::encrypt_data(S, secret);
  td::UniqueSlice buf(2 * enc_value.size() + 4);
  auto t = buf.as_mutable_slice();
  t.copy_from("ENC_");
  t.remove_prefix(4);
  t.copy_from(td::hex_encode(enc_value.as_slice()));
  return buf.as_slice().str();
}

static td::Status decrypt_all_strings(nlohmann::json &b, td::Slice shared_secret) {
  for (auto &[key, value] : b.items()) {
    if (should_encrypt_field(key)) {
      if (value.is_string()) {
        auto v = value.get<std::string>();
        TRY_RESULT(nv, decrypt_string(v, shared_secret));
        value = nv;
      } else if (value.is_structured()) {
        TRY_STATUS(decrypt_all_strings(value, shared_secret));
      }
    }
  }
  return td::Status::OK();
}

static td::Status encrypt_all_strings(nlohmann::json &b, td::Slice shared_secret) {
  for (auto &[key, value] : b.items()) {
    if (should_encrypt_field(key)) {
      if (value.is_string()) {
        value = encrypt_string(value.get<std::string>(), shared_secret);
      } else if (value.is_structured()) {
        encrypt_all_strings(value, shared_secret);
      }
    }
  }
  return td::Status::OK();
}

static td::Result<nlohmann::json> parse_json(td::Slice S) {
  auto b = nlohmann::json::parse(S.begin(), S.end(), nullptr, false, false);

  if (b.is_discarded()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "expected json object");
  }
  if (!b.is_object()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "expected json object");
  }
  return b;
}

struct Ctx {
  struct Level {
    Level(nlohmann::json *obj, std::string path) : obj(obj), path(std::move(path)) {
    }
    nlohmann::json *obj;
    std::string path;
    std::set<std::string> processed_fields;
  };
  std::vector<Level> levels;

  std::string model;
  td::int64 default_max_tokens;
  td::int64 max_tokens;

  Ctx(nlohmann::json *obj) {
    levels.emplace_back(obj, "");
  }

  const std::string &path() const {
    return levels.back().path;
  }

  nlohmann::json *obj() const {
    return levels.back().obj;
  }

  void replace_object(nlohmann::json j) {
    *levels.back().obj = std::move(j);
  }

  template <typename F>
  td::Status process_obj_field(const std::string &name, bool is_required, F &&run) {
    levels.back().processed_fields.insert(name);

    auto e = levels.back().obj;
    if (!e) {
      if (is_required) {
        return td::Status::Error(ton::ErrorCode::protoviolation,
                                 PSTRING() << "'" << path() << "' must have a field '" << name << "'");
      }
      return td::Status::OK();
    }
    if (!e->contains(name)) {
      if (is_required) {
        return td::Status::Error(ton::ErrorCode::protoviolation,
                                 PSTRING() << "'" << path() << "' must have a field '" << name << "'");
      }
      return td::Status::OK();
    }

    auto &el = (*e)[name];
    levels.emplace_back(&el, PSTRING() << path() << "." << name);
    TRY_STATUS(run(*this));
    if (el.is_object()) {
      TRY_STATUS(check_unprocessed_fields());
    }
    levels.pop_back();
    return td::Status::OK();
  }

  template <typename F>
  td::Status process_array(bool is_required, F &&run) {
    auto e = obj();
    if (!e) {
      if (is_required) {
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must exist");
      }
    }
    if (!e->is_array()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must be an array");
    }

    size_t idx = 0;
    for (auto &el : *e) {
      levels.emplace_back(&el, PSTRING() << path() << "[" << (idx++) << "]");
      TRY_STATUS(run(*this));
      if (el.is_object()) {
        TRY_STATUS(check_unprocessed_fields());
      }
      levels.pop_back();
    }

    return td::Status::OK();
  }

  td::Status check_unprocessed_fields() {
    auto e = levels.back().obj;
    if (!e || !e->is_object()) {
      return td::Status::OK();
    }

    for (auto &[name, value] : e->items()) {
      if (!levels.back().processed_fields.contains(name)) {
        return td::Status::Error(ton::ErrorCode::protoviolation,
                                 PSTRING() << path() << " has unknown field '" << name << "'");
      }
    }
    return td::Status::OK();
  }

  td::Result<std::string> get_string() {
    auto e = obj();
    if (!e || !e->is_string()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must be a string");
    }
    return e->get<std::string>();
  }

  td::Result<td::int64> get_integer() {
    auto e = obj();
    if (!e || !e->is_number_integer()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must be a string");
    }
    return e->get<long long>();
  }

  td::Result<bool> get_boolean() {
    auto e = obj();
    if (!e || !e->is_boolean()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must be a string");
    }
    return e->get<bool>();
  }

  void set_field_as_processed(std::string v) {
    levels.back().processed_fields.insert(std::move(v));
  }
};

static td::Status process_string(Ctx &ctx) {
  if (!ctx.obj()->is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_STATUS(ctx.get_string());
  return td::Status::OK();
}

static td::Status process_string_b64(Ctx &ctx) {
  if (!ctx.obj()->is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_RESULT(v, ctx.get_string());
  if (v.size() % 2 != 0) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a hex string");
  }
  for (auto c : v) {
    bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!is_hex) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a hex string");
    }
  }
  return td::Status::OK();
}

static td::Status process_string_url_or_b64(Ctx &ctx) {
  if (!ctx.obj()->is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_STATUS(ctx.get_string());
  return td::Status::OK();
}

static td::Status process_double(Ctx &ctx) {
  if (!ctx.obj()->is_number()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a number");
  }
  return td::Status::OK();
}

static td::Status process_integer(Ctx &ctx) {
  if (!ctx.obj()->is_number_integer()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a number");
  }
  return td::Status::OK();
}

static td::Status process_boolean(Ctx &ctx) {
  if (!ctx.obj()->is_boolean()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a boolean");
  }
  return td::Status::OK();
}

template <typename F>
static td::Status process_string_or_array(Ctx &ctx, F &&run) {
  if (ctx.obj()->is_array()) {
    return ctx.process_array(true, std::move(run));
  }
  return process_string(ctx);
}

template <typename F>
static td::Status process_string_or_object(Ctx &ctx, F &&run) {
  if (ctx.obj()->is_object()) {
    return ctx.process_array(true, std::move(run));
  }
  return process_string(ctx);
}

static td::Status process_image_url(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("url", true, process_string_url_or_b64));
  TRY_STATUS(ctx.process_obj_field("detail", false, process_string));
  return td::Status::OK();
}

static td::Status process_content_part_text(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("text", true, process_string));
  return td::Status::OK();
}

static td::Status process_content_part_image(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("image", true, process_image_url));
  return td::Status::OK();
}

static td::Status process_content_part_audio(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("input_audio", true, [](Ctx &ctx) {
    ctx.process_obj_field("format", true, process_string);
    ctx.process_obj_field("data", true, process_string_b64);
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_content_part_file(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("file", true, [](Ctx &ctx) {
    ctx.process_obj_field("file_data", false, process_string_b64);
    ctx.process_obj_field("file_id", false, process_string);
    ctx.process_obj_field("filename", false, process_string);
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_content_part_refusal(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("refusal", true, process_string));
  return td::Status::OK();
}

static td::Status process_content_part(Ctx &ctx) {
  std::string type;
  TRY_STATUS(ctx.process_obj_field("type", true, [&type](Ctx &ctx) {
    TRY_RESULT_ASSIGN(type, ctx.get_string());
    if (type.size() >= 128) {
      return td::Status::Error(ton::ErrorCode::protoviolation,
                               PSTRING() << ctx.path() << " must be a string not longer than 128 chars");
    }
    return td::Status::OK();
  }));

  bool is_text = type.find("text");
  bool is_image = type.find("image");
  bool is_audio = type.find("audio");
  bool is_file = type.find("file");
  bool is_refusal = ctx.obj()->contains("refusal");
  if (is_refusal) {
    return process_content_part_refusal(ctx);
  } else if (is_text) {
    return process_content_part_text(ctx);
  } else if (is_image) {
    return process_content_part_image(ctx);
  } else if (is_audio) {
    return process_content_part_audio(ctx);
  } else if (is_file) {
    return process_content_part_file(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown type " << type);
  }
}

static td::Status process_developer_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_system_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_user_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_function_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("arguments", true, process_string));
  TRY_STATUS(ctx.process_obj_field("name", true, process_string));
  return td::Status::OK();
}

static td::Status process_function_tool_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("function", true, process_function_call));
  return td::Status::OK();
}

static td::Status process_custom_tool_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("custom", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("input", true, process_string));
    TRY_STATUS(ctx.process_obj_field("name", true, process_string));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_tool_call(Ctx &ctx) {
  std::string type;
  TRY_STATUS(ctx.process_obj_field("type", true, [&type](Ctx &ctx) {
    TRY_RESULT_ASSIGN(type, ctx.get_string());
    return td::Status::OK();
  }));
  if (type == "function") {
    return process_function_tool_call(ctx);
  } else if (type == "custom") {
    return process_custom_tool_call(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown type " << type);
  }
}

static td::Status process_assistant_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("audio", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("id", true, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("content", false,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("function_call", false, process_function_call));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  TRY_STATUS(ctx.process_obj_field("refusal", false, process_string));
  TRY_STATUS(ctx.process_obj_field("tool_calls", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_tool_call));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_tool_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("tool_call_id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  return td::Status::OK();
}

static td::Status process_function_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("name", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true, process_string));
  return td::Status::OK();
}

static td::Status process_message(Ctx &ctx) {
  std::string role;
  TRY_STATUS(ctx.process_obj_field("role", true, [&role](Ctx &ctx) {
    TRY_RESULT_ASSIGN(role, ctx.get_string());
    return td::Status::OK();
  }));

  if (role == "developer") {
    return process_developer_message(ctx);
  } else if (role == "system") {
    return process_system_message(ctx);
  } else if (role == "user") {
    return process_user_message(ctx);
  } else if (role == "assistant") {
    return process_assistant_message(ctx);
  } else if (role == "tool") {
    return process_tool_message(ctx);
  } else if (role == "function") {
    return process_function_message(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown role " << role);
  }
}

static td::Status process_static_content(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("type", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  return td::Status::OK();
}

static td::Status process_stream_options(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("include_obfuscation", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("include_usage", false, process_boolean));
  return td::Status::OK();
}

static td::Status process_chat_completions(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("messages", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(true, process_message));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("audio", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("format", true, process_string));
    TRY_STATUS(ctx.process_obj_field("voice", true, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("id", true, process_string));
        return td::Status::OK();
      });
    }));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("frequency_penalty", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("function_call", false, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("name", true, process_string));
        return td::Status::OK();
      });
    }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field("function", false, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("name", true, process_string));
        TRY_STATUS(ctx.process_obj_field("description", false, process_string));
        TRY_STATUS(ctx.process_obj_field("parameters", false, [](Ctx &ctx) { return td::Status::OK(); }));
        return td::Status::OK();
      });
    }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field("logit_bias", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("logprobs", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("metadata", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(
      ctx.process_obj_field("modalities", false, [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("n", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("parallel_tool_calls", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("prediction", false, process_static_content));
  TRY_STATUS(ctx.process_obj_field("presence_penalty", false, process_double));
  TRY_STATUS(ctx.process_obj_field("prompt_cache_key", false, process_string));
  TRY_STATUS(ctx.process_obj_field("prompt_cache_retention", false, process_string));
  TRY_STATUS(ctx.process_obj_field("reasoning_effort", false, process_string));
  TRY_STATUS(ctx.process_obj_field("response_format", false, [](Ctx &ctx) {  // do not validate
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("safety_identifier", false, process_string));
  TRY_STATUS(ctx.process_obj_field("seed", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("service_tier", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("stop", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("store", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("tool_choice", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field(
        "tools", false, [](Ctx &ctx) { return ctx.process_array(false, [](Ctx &ctx) { return td::Status::OK(); }); }));
  }
  TRY_STATUS(ctx.process_obj_field("top_logprobs", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("top_p", false, process_double));
  TRY_STATUS(ctx.process_obj_field("user", false, process_string));
  TRY_STATUS(ctx.process_obj_field("verbosity", false, process_string));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("web_search_options", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("skip_special_tokens", false, process_boolean)); /* non-standard */

  auto &obj = *ctx.obj();

  if (has_stream) {
    obj["stream_options"]["include_usage"] = true;
  } else {
    obj.erase("stream_options");
  }

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }

  obj["max_tokens"] = max_completion_tokens;
  obj["max_completion_tokens"] = max_completion_tokens;
  ctx.max_tokens = max_completion_tokens;
  ctx.model = model;

  return td::Status::OK();
}

static td::Status process_completions(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("prompt", true, [](Ctx &ctx) {
    TRY_STATUS(process_string_or_array(ctx, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("best_of", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("echo", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("frequency_penalty", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("logit_bias", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("logprobs", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("n", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("presence_penalty", false, process_double));
  TRY_STATUS(ctx.process_obj_field("seed", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("stop", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("suffix", false, process_string));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  TRY_STATUS(ctx.process_obj_field("top_p", false, process_double));
  TRY_STATUS(ctx.process_obj_field("user", false, process_string));
  TRY_STATUS(ctx.process_obj_field("skip_special_tokens", false, process_boolean)); /* non-standard */

  auto &obj = *ctx.obj();

  if (has_stream) {
    obj["stream_options"]["include_usage"] = true;
  } else {
    obj.erase("stream_options");
  }

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }

  obj["max_tokens"] = max_completion_tokens;
  obj["max_completion_tokens"] = max_completion_tokens;
  ctx.max_tokens = max_completion_tokens;
  ctx.model = model;

  return td::Status::OK();
}

static td::Status process_create_audio_transcription(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("file", true, [](Ctx &ctx) {
    TRY_STATUS(process_string_or_array(ctx, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("chunking_strategy", false, [](Ctx &ctx) {
    return process_string_or_object(ctx, [](Ctx &ctx) {
      TRY_STATUS(ctx.process_obj_field("type", true, process_string));
      TRY_STATUS(ctx.process_obj_field("prefix_padding_ms", false, process_integer));
      TRY_STATUS(ctx.process_obj_field("silence_duration_ms", false, process_integer));
      TRY_STATUS(ctx.process_obj_field("threshold", false, process_double));
      return td::Status::OK();
    });
  }));
  TRY_STATUS(
      ctx.process_obj_field("include", false, [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("known_speaker_names", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("known_speaker_references", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("language", false, process_string));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("prompt", false, process_string));
  TRY_STATUS(ctx.process_obj_field("response_format", false, [](Ctx &ctx) {
    TRY_RESULT(value, ctx.get_string());
    if (value != "json") {
      return td::Status::Error(ton::ErrorCode::error, "response_format must be 'json'");
    }
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  TRY_STATUS(ctx.process_obj_field("timestamp_granularities", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));

  auto &obj = *ctx.obj();

  if (has_stream) {
    obj["stream_options"]["include_usage"] = true;
  } else {
    obj.erase("stream_options");
  }

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }

  obj["max_tokens"] = max_completion_tokens;
  obj["max_completion_tokens"] = max_completion_tokens;
  ctx.max_tokens = max_completion_tokens;
  ctx.model = model;

  return td::Status::OK();
}

td::Result<td::Bits256> parse_bits256_from_json(td::Slice val) {
  td::Bits256 res;
  if (val.size() == 32) {
    res.as_slice().copy_from(val);
  } else if (val.size() == 64) {
    TRY_RESULT(v, td::hex_decode(val));
    res.as_slice().copy_from(v);
  } else if (val.size() == 44) {
    TRY_RESULT(v, td::base64_decode(val));
    res.as_slice().copy_from(v);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "public_key bad length");
  }
  return res;
}

td::Result<td::BufferSlice> validate_decrypt_request(std::string url, td::BufferSlice request, std::string *model,
                                                     td::int64 *max_tokens, const td::Bits256 &private_key,
                                                     td::Bits256 *client_public_key) {
  auto p = url.find('/');
  if (p != std::string::npos) {
    url = url.substr(p);
  }

  TRY_RESULT(b, parse_json(request.as_slice()));
  TRY_STATUS(decrypt_json(b, private_key, *client_public_key, false, true));

  Ctx ctx(&b);
  for (const auto &s : json_encryption_related_str_fields) {
    ctx.set_field_as_processed(s);
  }

  ctx.default_max_tokens = max_tokens ? *max_tokens : 0;

  if (url == "/v1/chat/completions") {
    TRY_STATUS(process_chat_completions(ctx));
  } else if (url == "/v1/completions") {
    TRY_STATUS(process_completions(ctx));
  } else if (url == "/v1/audio/transcriptions") {
    TRY_STATUS(process_create_audio_transcription(ctx));
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "unsupported method");
  }

  TRY_STATUS(ctx.check_unprocessed_fields());

  if (model) {
    *model = ctx.model;
  }
  if (max_tokens) {
    *max_tokens = ctx.max_tokens;
  }
  return td::BufferSlice(b.dump());
}

static td::int64 get_json_value(nlohmann::json &json, const std::vector<std::string> &sub) {
  auto *ptr = &json;
  for (const auto &f : sub) {
    if (!ptr->is_object()) {
      return 0;
    }
    if (!ptr->contains(f)) {
      return 0;
    }
    ptr = &(*ptr)[f];
  }
  if (!ptr->is_number_unsigned()) {
    return 0;
  }
  return ptr->get<td::int64>();
}

std::string AnswerPostprocessor::add_next_answer_slice(td::Slice event) {
  last_ += event.str();

  td::StringBuilder sb;
  std::stringstream ss(last_);
  size_t pos = 0;
  bool is_end = false;
  while (!is_end) {
    try {
      nlohmann::json v;
      ss >> v;
      pos = ss.tellg();

      bool updated = false;

      {
        auto val = get_json_value(v, {"usage", "prompt_tokens"});
        if (val > prompt_tokens_) {
          prompt_tokens_ = val;
          updated = true;
        }
      }
      {
        auto val = get_json_value(v, {"usage", "prompt_tokens_details", "cached_tokens"});
        if (val > cached_tokens_) {
          cached_tokens_ = val;
          updated = true;
        }
      }
      {
        auto val = get_json_value(v, {"usage", "completion_tokens"});
        if (val > completion_tokens_) {
          completion_tokens_ = val;
          updated = true;
        }
      }
      {
        auto val = get_json_value(v, {"usage", "completion_tokens_details", "reasoning_tokens"});
        if (val > reasoning_tokens_) {
          reasoning_tokens_ = val;
          updated = true;
        }
      }
      {
        auto val = get_json_value(v, {"usage", "reasoning_tokens"});
        if (val > reasoning_tokens_) {
          reasoning_tokens_ = val;
          updated = true;
        }
      }

      if (updated) {
        auto prompt_tokens_adj = adjust_tokens(prompt_tokens_ - cached_tokens_, coef_, prompt_tokens_mult_);
        auto cached_tokens_adj = adjust_tokens(cached_tokens_, coef_, cached_tokens_mult_);
        auto completion_tokens_adj =
            adjust_tokens(completion_tokens_ - reasoning_tokens_, coef_, completion_tokens_mult_);
        auto reasoning_tokens_adj = adjust_tokens(reasoning_tokens_, coef_, reasoning_tokens_mult_);

        v["usage"]["prompt_total_cost"] = (prompt_tokens_adj + cached_tokens_adj) * price_per_token_;
        v["usage"]["completion_total_cost"] = (completion_tokens_adj + reasoning_tokens_adj) * price_per_token_;
        v["usage"]["total_cost"] =
            (prompt_tokens_adj + cached_tokens_adj + completion_tokens_adj + reasoning_tokens_adj) * price_per_token_;
      }

      if (!sender_private_key_.is_zero()) {
        encrypt_json(v, sender_private_key_, receiver_public_key_, false);
      }

      sb << v.dump() << "\n";
    } catch (...) {
      is_end = true;
    }
  }
  last_ = last_.substr(pos);
  return sb.as_cslice().str();
}

ton::tl_object_ptr<cocoon_api::tokensUsed> AnswerPostprocessor::usage() {
  auto prompt_tokens_adj = adjust_tokens(prompt_tokens_ - cached_tokens_, coef_, prompt_tokens_mult_);
  auto cached_tokens_adj = adjust_tokens(cached_tokens_, coef_, cached_tokens_mult_);
  auto completion_tokens_adj = adjust_tokens(completion_tokens_ - reasoning_tokens_, coef_, completion_tokens_mult_);
  auto reasoning_tokens_adj = adjust_tokens(reasoning_tokens_, coef_, reasoning_tokens_mult_);
  return ton::create_tl_object<cocoon_api::tokensUsed>(
      prompt_tokens_adj, cached_tokens_adj, completion_tokens_adj, reasoning_tokens_adj,
      prompt_tokens_adj + cached_tokens_adj + completion_tokens_adj + reasoning_tokens_adj);
}

std::string AnswerPostprocessor::finalize() {
  if (last_.size() > 0) {
    // do something?
  }
  return "";
}

void encrypt_json(nlohmann::json &v, const td::Bits256 &private_key, const td::Bits256 &public_key,
                  bool client_to_worker) {
  v["is_encrypted"] = "v1";

  td::Ed25519::PrivateKey pk(td::SecureString{private_key.as_slice()});
  td::Bits256 pub;
  pub.as_slice().copy_from(pk.get_public_key().move_as_ok().as_octet_string().as_slice());
  v["sender_public_key"] = td::hex_encode(pub.as_slice());
  v["receiver_public_key"] = td::hex_encode(public_key.as_slice());

  char buf[32];
  td::Random::secure_bytes(td::MutableSlice(buf, 32));
  auto encryption_nonce = td::base64_encode(td::Slice(buf, 32));
  v["encryption_nonce"] = encryption_nonce;

  auto shared_secret =
      generate_shared_secret(private_key, public_key, pub, encryption_nonce, client_to_worker).move_as_ok();
  encrypt_all_strings(v, shared_secret.as_slice());
}

td::Status decrypt_json(nlohmann::json &v, const td::Bits256 &private_key, td::Bits256 &public_key,
                        bool check_public_key, bool client_to_worker) {
  bool is_encrypted = v.contains("is_encrypted");
  if (!is_encrypted) {
    if (!private_key.is_zero()) {
      return td::Status::Error(ton::ErrorCode::error, "encryption key is provided, but request is unencrypted");
    } else {
      if (check_public_key) {
        if (!public_key.is_zero()) {
          return td::Status::Error(ton::ErrorCode::error, "public key is provided, but request is unencrypted");
        }
      } else {
        public_key = td::Bits256::zero();
      }
    }
    return td::Status::OK();
  }

  for (const auto &s : json_encryption_related_str_fields) {
    if (!v.contains(s) || !v[s].is_string()) {
      return td::Status::Error(ton::ErrorCode::error, "not all encryption-related fields are present");
    }
  }

  TRY_RESULT(sender_public_key, parse_bits256_from_json(v["sender_public_key"].get<std::string>()));
  TRY_RESULT(receiver_public_key, parse_bits256_from_json(v["receiver_public_key"].get<std::string>()));
  auto encryption_nonce = v["encryption_nonce"].get<std::string>();

  if (private_key.is_zero()) {
    return td::Status::Error(ton::ErrorCode::error, "cannot find private key for an encrypted request");
  }
  if (check_public_key) {
    if (public_key != sender_public_key) {
      return td::Status::Error(ton::ErrorCode::error, "sender public key mismatch");
    }
  } else {
    public_key = sender_public_key;
  }
  TRY_RESULT(shared_secret, generate_shared_secret(private_key, sender_public_key, receiver_public_key,
                                                   encryption_nonce, client_to_worker));
  TRY_STATUS(decrypt_all_strings(v, shared_secret.as_slice()));
  return td::Status::OK();
}

}  // namespace cocoon
