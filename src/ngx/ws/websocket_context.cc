/**
 * @file websocket_context.cc
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

#include "ngx/ws/websocket_context.h"
#include "ngx/ws/abstract_websocket_client.h"

#ifdef __APPLE__
#pragma mark - ngx::ws::Context
#endif

/**
 * @brief Default constructor.
 */
ngx::ws::Context::Context (ngx_module_t& a_module, ngx_http_request_t* a_http_request,
                           const std::string& a_service_id,
                           const std::map<std::string, std::string>& a_config,
                           ngx::ws::Context::Writer* a_writer,
                           ngx::ws::Context::TimerManager* a_timer_manager)
    : module_(a_module), http_request_(a_http_request), service_id_(a_service_id), config_(a_config)
{
    writer_ptr_           = a_writer;
    timer_manager_ptr_    = a_timer_manager;
    client_               = ngx::ws::AbstractWebsocketClient::Factory(this, a_config);
}

/**
 * @brief Destructor.
 */
ngx::ws::Context::~Context ()
{
    delete client_;
}
