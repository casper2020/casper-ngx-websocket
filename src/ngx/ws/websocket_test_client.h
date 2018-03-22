/**
 * @file websocket_test_client.h
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
#ifndef NRS_NGX_WS_WEBSOCKET_TEST_CLIENT_H_
#define NRS_NGX_WS_WEBSOCKET_TEST_CLIENT_H_

#include "ngx/ws/abstract_websocket_client.h"
#include "ngx/ws/websocket_context.h"

#include <string>
#include <queue>

namespace ngx
{

    namespace ws
    {

        /**
         * @brief
         */
        class WebsocketTestClient : public ngx::ws::AbstractWebsocketClient
        {

        protected: // data

            std::queue<ngx::ws::WebsocketBufferChain*> queue_;

        protected: //

            ngx::ws::Context&                          websocket_;

        public: // Methods

                     WebsocketTestClient (ngx::ws::Context& a_context);
            virtual ~WebsocketTestClient ();

        public: // Methods called by the context

            virtual const char*                          Protocol                        ();
            virtual bool                                 UseChains                       ();

            virtual void                                 OnBinaryMessage                 (const Context* a_ws_context, const void* a_data, size_t a_size);
            virtual void                                 OnTextMessage                   (const Context* a_ws_context, const char* a_data, size_t a_size);
            virtual void                                 OnChainedMessage                (const Context* a_ws_context, const ngx::ws::WebsocketBufferChain* a_chain);
            virtual const ngx::ws::WebsocketBufferChain* OnMessageSent                   (const Context* a_ws_context);
            virtual void                                 OnConnectionClosed              (const Context* a_ws_context);
            virtual void                                 OnExceptionCaught               (const ngx::ws::Context* a_ws_context, const std::exception& a_exception);
            virtual void                                 OnErrorCaught                   (const ::ngx::ws::Context* a_ws_context, const std::runtime_error& a_error);

        public: // Simple tansmission API where a basic queue is used

            virtual void                                 PostBinaryMessage  (const void* a_data, size_t a_size);
            virtual void                                 PostTextMessage    (const void* a_data, size_t a_size);
            virtual void                                 PostChainedMessage (ngx::ws::WebsocketBufferChain* a_chain);

        public: //

            void                                         Send               ();

        private: //

            ngx::ws::WebsocketBufferChain*               NewBufferChain     (const std::string& a_data);
            ngx::ws::WebsocketBufferChain*               NewBufferChain     (const std::string& a_data, uint16_t a_multiplier);

        }; // end of class 'WebsocketTestClient'

    } // end of namespace 'ws'

} // end of namespace 'ngx'

#endif // NRS_NGX_WS_WEBSOCKET_TEST_CLIENT_H_
