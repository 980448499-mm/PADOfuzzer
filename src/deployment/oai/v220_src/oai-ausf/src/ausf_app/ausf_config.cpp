/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include "ausf_config.hpp"

#include <arpa/inet.h>

#include "ausf.h"
#include "ausf_sbi_helper.hpp"
#include "common_defs.h"
#include "config.hpp"
#include "if.hpp"
#include "logger.hpp"
#include "string.hpp"

using namespace oai::ausf::api;

namespace oai::config {

//------------------------------------------------------------------------------
ausf_config::ausf_config() : sbi(), ausf_name(), pid_dir(), instance() {
  udm_addr.ipv4_addr.s_addr = INADDR_ANY;
  udm_addr.port             = 8080;  // HTTP/2 by default
  udm_addr.api_version      = "v1";
  http_version              = 2;  // HTTP/2 by default
  log_level                 = spdlog::level::debug;
  register_nrf              = false;
  http_request_timeout =
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT_DEFAULT_VALUE;
}

//------------------------------------------------------------------------------
ausf_config::~ausf_config() {}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_api_root() const {
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version);
}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_generate_auth_data_uri(
    const std::string& supi) const {
  std::string fmr_format_str = {};
  ausf_sbi_helper::get_fmt_format_form(
      ausf_sbi_helper::UdmUeAuPathGenerateAuthData, fmr_format_str);
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version +
      fmt::format(fmr_format_str, supi));
}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_confirm_auth_uri(
    const std::string& supi) const {
  std::string fmr_format_str = {};
  ausf_sbi_helper::get_fmt_format_form(
      ausf_sbi_helper::UdmUeAuPathConfirmAuth, fmr_format_str);
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version +
      fmt::format(fmr_format_str, supi));
}
}  // namespace oai::config
