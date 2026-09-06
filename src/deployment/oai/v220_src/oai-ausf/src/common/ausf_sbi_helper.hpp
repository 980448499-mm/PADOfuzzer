/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
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

#pragma once

#include <nlohmann/json.hpp>

#include "ausf_config.hpp"
#include "sbi_helper.hpp"

using namespace oai::config;
using namespace oai::common::sbi;

extern ausf_config ausf_cfg;

namespace oai::ausf::api {

class ausf_sbi_helper : public sbi_helper {
 public:
  static inline const std::string UEAuthenticationServiceBase =
      sbi_helper::AusfAuthBase +
      ausf_cfg.sbi.api_version.value_or(kDefaultSbiApiVersion);

  static void set_problem_details(
      nlohmann::json& json_data, const std::string& detail);
};

}  // namespace oai::ausf::api
