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
const char* const ngx::ws::AbstractWebsocketClient::k_http_json_content_type_                 = "application/json; charset=utf-8";

const char* const ngx::ws::AbstractWebsocketClient::k_json_api_url_key_lc_                    = "json_api_url";
const char* const ngx::ws::AbstractWebsocketClient::k_jrxml_base_directory_key_lc_            = "jrxml_base_directory";

const char* const ngx::ws::AbstractWebsocketClient::k_service_id_lc_                          = "service_id";

const char* const ngx::ws::AbstractWebsocketClient::k_data_source_overridable_sys_vars_lc_    = "data_source_overridable_sys_vars";

const char* const ngx::ws::AbstractWebsocketClient::k_http_acceptable_base_urls_key_lc_       = "http_base_url_map";

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
