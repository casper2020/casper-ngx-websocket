/**
 * @file websocket_protocol.cc
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

#include "ngx/ws/websocket_protocol.h"


#ifdef __APPLE__
#pragma mark - ngx::ws::ServerHandshake
#endif

const ngx::ws::ServerHandshake::in_header_s ngx::ws::ServerHandshake::kRequiredInHeadersTable [] = {
    { ngx::ws::ServerHandshake::ProtocolHeaders::ESecWebSocketKey       , "sec-websocket-key"       , "Sec-WebSocket-Key"       , 17 },
    { ngx::ws::ServerHandshake::ProtocolHeaders::ESecWebSocketExtensions, "sec-websocket-extensions", "Sec-WebSocket-Extensions", 24 },
    { ngx::ws::ServerHandshake::ProtocolHeaders::ESecWebSocketAccept    , "sec-websocket-accept"    , "Sec-WebSocket-Accept"    , 20 },
    { ngx::ws::ServerHandshake::ProtocolHeaders::ESecWebSocketProtocol  , "sec-websocket-protocol"  , "Sec-WebSocket-Protocol"  , 22 },
    { ngx::ws::ServerHandshake::ProtocolHeaders::ESecWebSocketVersion   , "sec-websocket-version"   , "Sec-WebSocket-Version"   , 21 },
    { ngx::ws::ServerHandshake::ProtocolHeaders::EInvalid               , ""                        , ""                        ,  0 }
};

const ngx::ws::ServerHandshake::out_header_s ngx::ws::ServerHandshake::kRequiredOutHeadersTable [] = {
    { ngx::ws::ServerHandshake::ConnectionHeaders::EUpgrade             , "upgrade"                 , "Upgrade"                 ,  7 },
    { ngx::ws::ServerHandshake::ConnectionHeaders::EConnection          , "connection"              , "Connection"              , 10 },
    { ngx::ws::ServerHandshake::ConnectionHeaders::EInvalid             , ""                        , ""                        ,  0 }
};

//
