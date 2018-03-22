/**
 * @file websocket_buffer_chain.h
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
#ifndef NRS_NGX_WS_WEBSOCKET_BUFFER_CHAIN_H_
#define NRS_NGX_WS_WEBSOCKET_BUFFER_CHAIN_H_

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

namespace ngx
{

    namespace ws
    {

        /**
         * @brief Simple chainable data buffer
         */
        class WebsocketBufferChain
        {

        public: // Const Data

            const size_t size_;

        public: // Data

            size_t                fill_count_;     //!< the buffer fill count
            WebsocketBufferChain* next_;           //!< the next link in chain
            bool                  binary_;         //!< true if data_ is binary, false it will be considered text.
            char                  data_[1];        //!< the data - TODO change type when binary mode is supported

        public: // Constructor / Destructor

            WebsocketBufferChain (size_t a_capacity)
                : size_(a_capacity)
            {
                fill_count_ = 0;
                next_       = NULL;
                binary_     = false;
            }

            virtual ~WebsocketBufferChain ()
            {
                /* empty */
            }

        public: // Operator(s) Overload

            void* operator new (size_t, size_t a_capacity)
            {
                return (WebsocketBufferChain*) malloc(a_capacity + sizeof(WebsocketBufferChain) - sizeof(data_));
            }

            void operator delete (void* a_obj)
            {
                WebsocketBufferChain* p = ((WebsocketBufferChain*) a_obj)->next_;
                while ( NULL != p ) {
                    WebsocketBufferChain* c = p;
                    p = p->next_;
                    free(c);
                }
                free(a_obj);
            }

        public: // Static Method(s) / Function(s)

            static WebsocketBufferChain* New (size_t a_capacity)
            {
                return new (a_capacity) ngx::ws::WebsocketBufferChain(a_capacity);
            }

        }; /// end of class 'WebsocketBufferChain'

    } // end of namespace 'ws'

} // end of namespace 'ngx'

#endif // NRS_NGX_WS_WEBSOCKET_BUFFER_CHAIN_H_
