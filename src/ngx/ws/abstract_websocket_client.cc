/**
 * @file abstract_websocket_client.cc
 *
 * Copyright (c) 2011-2018 Cloudware S.A. All rights reserved.
 *
 * This file is part of casper-ngx-websocket.
 *
 * casper-ngx-websocket is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * casper-ngx-websocket is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with casper-ngx-websocket.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ngx/ws/abstract_websocket_client.h"

#include <vector>
#include <algorithm>   // std::remove_if

// public static data
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_protocol_header_key_lc_       = "sec-websocket-protocol";
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_protocol_remote_ip_key_lc_    = "remote-ip";
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_resources_root_key_lc_        = "resources-root";
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_logs_root_key_lc_             = "logs-root";
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_http_file_server_host_key_lc_ = "http_file_server_host";
const char* const ngx::ws::AbstractWebsocketClient::k_websocket_http_file_server_port_key_lc_ = "http_file_server_port";
const char* const ngx::ws::AbstractWebsocketClient::k_http_json_content_type_                 = "application/json; charset=utf-8";
const char* const ngx::ws::AbstractWebsocketClient::k_redis_ip_address_key_lc_                = "redis_ip_address";
const char* const ngx::ws::AbstractWebsocketClient::k_redis_port_number_key_lc_               = "redis_port_number";
const char* const ngx::ws::AbstractWebsocketClient::k_redis_database_key_lc_                  = "redis_database";
const char* const ngx::ws::AbstractWebsocketClient::k_redis_max_conn_per_worker_lc_           = "redis_max_conn_per_worker";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_conn_str_key_lc_             = "postgresql_conn_str";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_statement_timeout_lc_        = "postgresql_statement_timeout";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_post_connect_queries_lc_     = "postgresql_post_connect_queries";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_max_conn_per_worker_lc_      = "postgresql_max_conn_per_worker";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_min_queries_per_conn_lc_     = "postgresql_min_queries_per_conn";
const char* const ngx::ws::AbstractWebsocketClient::k_postgresql_max_queries_per_conn_lc_     = "postgresql_max_queries_per_conn";
const char* const ngx::ws::AbstractWebsocketClient::k_curl_max_conn_per_worker_lc_            = "curl_max_conn_per_worker";

const char* const ngx::ws::AbstractWebsocketClient::k_json_api_url_key_lc_                    = "json_api_url";
const char* const ngx::ws::AbstractWebsocketClient::k_jrxml_base_directory_key_lc_            = "jrxml_base_directory";

const char* const ngx::ws::AbstractWebsocketClient::k_service_id_lc_                          = "service_id";

const char* const ngx::ws::AbstractWebsocketClient::k_beanstalkd_host_key_lc_                 = "beanstalkd_host";
const char* const ngx::ws::AbstractWebsocketClient::k_beanstalkd_port_key_lc_                 = "beanstalkd_port";
const char* const ngx::ws::AbstractWebsocketClient::k_beanstalkd_timeout_key_lc_              = "beanstalkd_timeout";
const char* const ngx::ws::AbstractWebsocketClient::k_beanstalkd_sessionless_tubes_key_lc_    = "beanstalkd_sessionless_tubes";
const char* const ngx::ws::AbstractWebsocketClient::k_beanstalkd_action_tubes_key_lc_         = "beanstalkd_action_tubes";
const char* const ngx::ws::AbstractWebsocketClient::k_logger_register_tokens_key_lc_          = "logger_register_tokens";
const char* const ngx::ws::AbstractWebsocketClient::k_data_source_overridable_sys_vars_lc_    = "data_source_overridable_sys_vars";

const char* const ngx::ws::AbstractWebsocketClient::k_http_base_url_map_key_lc_               = "http_base_url_map";

const char* const ngx::ws::AbstractWebsocketClient::k_session_fields_key_lc_                  = "session_fields";
const char* const ngx::ws::AbstractWebsocketClient::k_session_extension_amount_key_lc_        = "session_extension_amount";

const char* const ngx::ws::AbstractWebsocketClient::k_gatekeeper_config_file_uri_key_lc_      = "gatekeeper_config_file_uri";

#ifdef __APPLE__
#pragma mark - AbstractWebsocketClient: Registry
#endif

// protected static data
ngx::ws::ClientRegistry* ngx::ws::AbstractWebsocketClient::g_registry_ = nullptr;

void ngx::ws::AbstractWebsocketClient::RegisterFactory (const char* a_protocol, ClientFactory a_factory)
{
    if ( nullptr == g_registry_ ) {
        g_registry_ = new ngx::ws::ClientRegistry();
    }
    (*g_registry_)[a_protocol] = a_factory;
}

void ngx::ws::AbstractWebsocketClient::UnregisterFactory (const char* a_protocol)
{
    if ( nullptr != g_registry_ ) {
        if ( nullptr != a_protocol ) {
            auto it = g_registry_->find(a_protocol);
            if ( g_registry_->end() != it ) {
                g_registry_->erase(it);
            }
        } else {
            g_registry_->clear();
            delete g_registry_;
            g_registry_ = nullptr;
        }
    }
}

/**
 * @brief Create a client handler for the specified protocol
 *
 * @param a_ws_context pointer to the context that received the connection
 * @param a_config
 * @param a_resources_path
 *
 * @return New instance of the client or NULL if the request can't not be honoured
 */
ngx::ws::AbstractWebsocketClient* ngx::ws::AbstractWebsocketClient::Factory (ngx::ws::Context* a_ws_context,
                                                                             const std::map<std::string, std::string>& a_config)
{
    //
    std::string                       token;
    std::vector<std::string>          tokens;
    std::string::size_type            start = 0;
    std::string::size_type            end   = std::string::npos;
    ngx::ws::AbstractWebsocketClient* rv    = nullptr;
    //
    if ( g_registry_ == nullptr ) {
        // not ready
        return rv;
    }
    // get websocket protocol header value
    auto pit = a_config.find(ngx::ws::AbstractWebsocketClient::k_websocket_protocol_header_key_lc_);
    if ( a_config.end() == pit ) {
        // could not find it
        return rv;
    }
    std::string protocol = pit->second;
    // split list into tokens
    for ( ; ; ) {
        end = protocol.find(',', start);
        // collect token and strip white chars
        token = protocol.substr(start, end - start);
        token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
        tokens.push_back(token);
        // no more tokens?
        if ( std::string::npos == end ) {
            break;
        }
        start = end + sizeof(char);
    }
    // search for the first match
    for ( auto it = tokens.begin() ; tokens.end() != it ; ++it ) {
        auto it2 = g_registry_->find(*it);
        if ( it2 == g_registry_->end() ) {
            continue;
        }
        rv = (*it2->second)(a_ws_context, a_config);
        if ( nullptr != rv ) {
            break;
        }
    }
    // nullptr if not found
    return rv;
}
