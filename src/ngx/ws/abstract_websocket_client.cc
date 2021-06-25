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
 * @brief Create a client handler for a specific protocol
 *
 * @param a_ws_context             pointer to the context that received the connection
 * @param a_sec_websocket_protocol websocket protocol
 * @param a_ip_address             client's ip address
 *
 * @return New instance of the client or NULL if the request can't not be honoured
 */
ngx::ws::AbstractWebsocketClient* ngx::ws::AbstractWebsocketClient::Factory (ngx::ws::Context* a_ws_context,
                                                                             const std::string& a_sec_websocket_protocol, const std::string& a_ip_address)
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
    std::string protocol = a_sec_websocket_protocol;
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
        rv = (*it2->second)(a_ws_context, *it, a_ip_address);
        if ( nullptr != rv ) {
            break;
        }
    }
    // nullptr if not found
    return rv;
}
