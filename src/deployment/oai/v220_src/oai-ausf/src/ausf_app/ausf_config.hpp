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

#ifndef _AUSF_CONFIG_H_
#define _AUSF_CONFIG_H_

#include "ausf.h"
#include "logger.hpp"

using namespace oai::common::sbi;

namespace oai::config {

class ausf_config {
 public:
  ausf_config();
  ~ausf_config();

  /*
   * Get the root URI of UDM UE Authentication API
   * @param void
   * @return URI in string format
   */
  std::string get_udm_ueau_api_root() const;

  /*
   * Get the URI of UDM to generate authentication data for the UE
   * @param [const std::string&] supi: UE SUPI
   * @return URI in string format
   */
  std::string get_udm_ueau_generate_auth_data_uri(
      const std::string& supi) const;

  /*
   * Get the URI of UDM to create a new confirmation event
   * @param [const std::string&] supi: UE SUPI
   * @return URI in string format
   */
  std::string get_udm_ueau_confirm_auth_uri(const std::string& supi) const;

  unsigned int instance;
  std::string pid_dir;
  std::string ausf_name;
  spdlog::level::level_enum log_level;

  interface_cfg_t sbi;
  nf_addr_t udm_addr;
  nf_addr_t nrf_addr;

  bool register_nrf;
  uint8_t http_version;
  uint32_t http_request_timeout;
};

}  // namespace oai::config

#endif
