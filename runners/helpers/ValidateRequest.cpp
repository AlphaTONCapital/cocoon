#include "ValidateRequest.h"
#include "Ed25519.h"
#include "checksum.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "nlohmann/detail/input/json_sax.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Status.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/misc.h"
#include "tdport/td/e2e/MessageEncryption.h"

#include <memory>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <set>

namespace cocoon {

static td::Result<td::SecureString> generate_shared_secret(const td::Bits256 &pk_b256, const td::Bits256 &pub_b256,
                                                           td::Slice nonce, bool is_outbound) {
  td::Ed25519::PrivateKey pk(td::SecureString{pk_b256.as_slice()});
  td::Ed25519::PublicKey pub(td::SecureString{pub_b256.as_slice()});
  TRY_RESULT(shared_secret, td::Ed25519::compute_shared_secret(pub, pk));

  td::SecureString tmp(32 + nonce.size() + 1);

  tmp.as_mutable_slice().copy_from(shared_secret.as_slice());
  tmp.as_mutable_slice().remove_prefix(32).copy_from(nonce);
  tmp.as_mutable_slice().remove_prefix(32 + nonce.size()).copy_from(is_outbound ? "o" : "i");
  auto val = td::sha256_bits256(tmp.as_slice());
  return td::SecureString(val.as_slice());
}

static bool string_is_encrypted(td::Slice S) {
  return S.size() >= 8 && S[0] == '\x01' && S[1] == '\x02' && S[2] == '\x04' && S[3] == '\x03';
}

static td::Result<std::string> decrypt_string(td::Slice S, td::Slice secret) {
  CHECK(string_is_encrypted(S));
  S.remove_prefix(4);
  auto encryption_type = S.copy().truncate(4);
  S.remove_prefix(4);

  if (encryption_type == "SIMP") {
    TRY_RESULT(res, tde2e_core::MessageEncryption::decrypt_data(S, secret));
    if (string_is_encrypted(res)) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "nested encryption");
    }
    return res.as_slice().str();
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "bad encryption method");
  }
}

static td::Status decrypt_all_strings(nlohmann::json &b, td::Slice shared_secret) {
  for (auto &[key, value] : b.items()) {
    if (value.is_string()) {
      auto v = value.get<std::string>();
      if (string_is_encrypted(v)) {
        TRY_RESULT(nv, decrypt_string(v, shared_secret));
        value = v;
      }
    } else if (value.is_structured()) {
      decrypt_all_strings(value, shared_secret);
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

  td::SecureString shared_secret_;
  bool client_mode = false;

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
  TRY_STATUS(ctx.process_obj_field("response_format", false, process_string));
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

td::Result<td::BufferSlice> validate_modify_request(std::string url, td::BufferSlice request, std::string *model,
                                                    td::int64 *max_tokens, const td::Bits256 *private_key,
                                                    bool client_mode) {
  auto p = url.find('/');
  if (p != std::string::npos) {
    url = url.substr(p);
  }

  TRY_RESULT(b, parse_json(request.as_slice()));
  Ctx ctx(&b);

  bool is_encrypted = false;
  TRY_STATUS(ctx.process_obj_field("is_encrypted", false, [&](Ctx &ctx) {
    if (!ctx.obj()->is_boolean()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "is_encrypted must be boolean");
    }
    is_encrypted = ctx.obj()->get<bool>();
    return td::Status::OK();
  }));

  td::Bits256 sender_public_key = td::Bits256::zero();
  std::string encryption_nonce;
  if (is_encrypted) {
    TRY_STATUS(ctx.process_obj_field("sender_public_key", true, [&](Ctx &ctx) {
      TRY_RESULT(val, ctx.get_string());
      if (val.size() == 32) {
        sender_public_key.as_slice().copy_from(val);
      } else if (val.size() == 64) {
        TRY_RESULT(v, td::hex_decode(val));
        sender_public_key.as_slice().copy_from(v);
      } else if (val.size() == 44) {
        TRY_RESULT(v, td::base64_decode(val));
        sender_public_key.as_slice().copy_from(v);
      } else {
        return td::Status::Error(ton::ErrorCode::protoviolation, "sender_public_key bad length");
      }
      return td::Status::OK();
    }));
    TRY_STATUS(ctx.process_obj_field("encryption_nonce", true, [&](Ctx &ctx) {
      TRY_RESULT_ASSIGN(encryption_nonce, ctx.get_string());
      return td::Status::OK();
    }));

    if (!client_mode) {
      if (!private_key) {
        return td::Status::Error(ton::ErrorCode::error, "cannot find private key for an encrypted request");
      }
      TRY_RESULT(shared_secret, generate_shared_secret(*private_key, sender_public_key, encryption_nonce, false));
      decrypt_all_strings(*ctx.obj(), shared_secret.as_slice());
    }
  }

  ctx.default_max_tokens = max_tokens ? *max_tokens : 0;
  ctx.client_mode = client_mode;

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

}  // namespace cocoon
