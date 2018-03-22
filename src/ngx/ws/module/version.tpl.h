/**
 * @file version.h
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

#pragma once
#ifndef NRS_NGX_WEBSOCKET_VERSION_H_
#define NRS_NGX_WEBSOCKET_VERSION_H_

#include "core/nginx.h"

#ifndef NGX_WEBSOCKET_MODULE_NAME
    #define NGX_WEBSOCKET_MODULE_NAME "casper-ngx-websocket"
#endif

#ifndef NGX_WEBSOCKET_MODULE_VERSION
    #define NGX_WEBSOCKET_MODULE_VERSION "@MODULE_VERSION@"
#endif

#endif // NRS_NGX_WEBSOCKET_VERSION_H_
