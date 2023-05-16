/**
 * @file websocket_context.h
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
#ifndef NRS_NGX_WS_WEBSOCKET_CONTEXT_H_
#define NRS_NGX_WS_WEBSOCKET_CONTEXT_H_

extern "C" {
    #include <sys/types.h> // ssize_t // etc
    #include <stdint.h>    // uint8_t // uint32_t // etc
    #include <string.h>    // NULL    // etc
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
    #include <ngx_errno.h>
    #include <ngx_http_request.h>
}

#pragma GCC diagnostic pop

#include "ngx/ws/websocket_protocol.h"
#include "ngx/ws/abstract_websocket_client.h"

#include <functional> // std::function

namespace ngx
{

    namespace ws
    {

#ifdef __APPLE__
#pragma mark - Context
#endif

        /**
         * @brief A WebSocket context.
         */
        class Context
        {

        public: // nested class(es)

            /**
             * @brief An exception class that carries a user message of the fault origin.
             */
            class Exception : public std::exception
            {

            private: // data

                char reason_ [512];

            public: // constructor / destructor

                /**
                 * @brief A constructor that provides the reason of the fault origin.
                 *
                 * @param a_format printf like format followed by a variable number of arguments
                 */
                Exception (const char* a_format, ...) throw ()
                {
                    va_list args;
                    va_start(args, a_format);
                    vsnprintf(reason_, sizeof(reason_) / sizeof(reason_[0]), a_format, args);
                    va_end(args);
                }

            public: // overrides

                /**
                 * @@return The explanatory string.
                 */
                virtual const char* what() const throw()
                {
                    return reason_;
                }

            }; // end of class 'Exception'

           /**
            * A class that defines an interface to send messages using WebSockets protocol.
            */
            class Writer {

            public: // constructor(s) / destructor

                /**
                 * @brief Destructor.
                 */
                virtual ~Writer ()
                {
                    /* empty */
                }

            public: // pure virtual method(s) / function(s) - declaration

                /**
                 * @brief Send a websocket message.
                 *
                 * @param a_chain The buffer chain that contains the message payload.
                 *
                 * @return
                 *         @li True on success
                 *         @li False on failure
                 */
                virtual bool SendMessage (const ngx::ws::WebsocketBufferChain* a_chain) = 0;

            };

            /**
             * A class that defines an interface to perform register timer events.
             */
            class TimerManager
            {

            public: // data types

                class Event
                {

                public: // const data

                    const unsigned one_shot_ : 1;

                public: // data

                    size_t                      timeout_;
                    const std::function<void()> callback_;

                public: // constructor(s) / destructor

                    /**
                     * @brief Default constructor.
                     *
                     * @param a_one_shot
                     * @param a_timeout
                     * @param a_callback
                     */
                    Event (bool a_one_shot, size_t a_timeout, const std::function<void()> a_callback)
                    : one_shot_(true == a_one_shot ? 1 : 0), timeout_(a_timeout), callback_(a_callback)
                    {
                        /* empty */
                    }

                    /**
                     * @brief Destructor.
                     */
                    virtual ~Event ()
                    {
                        /* empty */
                    }

                };

                class OneShotEvent : public Event
                {

                public: // constructor(s) / destructor

                    /**
                     * @brief Default constructor.
                     *
                     * @param a_timeout
                     * @param a_callback
                     */
                    OneShotEvent (size_t a_timeout, const std::function<void()> a_callback)
                        : Event(true, a_timeout, a_callback)
                    {
                        /* empty */
                    }

                    /**
                     * @brief Destructor.
                     */
                    virtual ~OneShotEvent ()
                    {
                        /* empty */
                    }

                };

                class RecurrentEvent : public Event
                {

                public: // constructor(s) / destructor

                    /**
                     * @brief Default constructor.
                     *
                     * @param a_timeout
                     * @param a_callback
                     */
                    RecurrentEvent (size_t a_timeout, const std::function<void()> a_callback)
                        : Event(false, a_timeout, a_callback)
                    {
                        /* empty */
                    }

                    /**
                     * @brief Destructor.
                     */
                    virtual ~RecurrentEvent ()
                    {
                        /* empty */
                    }

                };

            public: // constructor(s) / destructor

                /**
                 * @brief Destructor.
                 */
                virtual ~TimerManager ()
                {
                    /* empty */
                }

            public: // pure virtual method(s) / function(s) - declaration

                /**
                 * @brief Schedule a one shot event.
                 *
                 * @param a_timeout_ms
                 * @param a_callback
                 */
                virtual OneShotEvent*   ScheduleOneShot   (size_t a_timeout_ms, const std::function<void()> a_callback) = 0;

                /**
                 * @brief Schedule a recurrent shot event.
                 *
                 * @param a_timeout_ms
                 * @param a_callback
                 */
                virtual RecurrentEvent* ScheduleRecurrent (size_t a_timeout_ms, const std::function<void()> a_callback) = 0;

                /**
                 * @brief Cancel a previously registered event.
                 *
                 * @param a_event
                 */
                virtual void            Cancel            (Event* a_event)                                              = 0;

            };

        public:

            ngx_module_t&       module_;
            ngx_http_request_t* http_request_;

        public: // pointers
            //
            ngx::ws::Context::Writer*               writer_ptr_;
            ngx::ws::Context::TimerManager*         timer_manager_ptr_;

        public: // Martelada

            ngx::ws::AbstractWebsocketClient*        client_;

        public: // Methods

            Context (ngx_module_t& a_module, ngx_http_request_t* a_http_request);
            virtual ~Context ();

        public: // Methods

            Context& Setup       (const std::string& a_sec_websocket_protocol, const std::string& a_client_ip_address);
            void     Hold        (ngx::ws::Context::Writer* a_writer, ngx::ws::Context::TimerManager* a_timer_manager);
            bool     SendMessage (const ngx::ws::WebsocketBufferChain* a_message);

        }; // end of class 'Context'

        /**
         * @brief On-shot setup.
         *
         * @param a_sec_websocket_protocol Client protocol list ( ',' separated ).
         * @param a_client_ip_address      Client IP address.
         */
        inline ngx::ws::Context& ngx::ws::Context::Setup (const std::string& a_sec_websocket_protocol, const std::string& a_client_ip_address)
        {
            // ... sanity check ...
            if ( nullptr != client_ ) {
                throw ngx::ws::Context::Exception("%s already called!", __FUNCTION__);
            }
            // ... create new client ...
            client_ = ngx::ws::AbstractWebsocketClient::Factory(this, a_sec_websocket_protocol, a_client_ip_address);
            if ( nullptr == client_ ) {
                throw ngx::ws::Context::Exception("Factory did not return a valid client for '%s' protocol!", a_sec_websocket_protocol.c_str());
            }
            // ... setup ...
            try {
                client_->Setup();
            } catch (const ngx::ws::Context::Exception& a_exception) {
                delete client_;
                client_ = nullptr;
                throw a_exception;
            }
            // ... done ...
            return *this;
        }
        
        /**
         * @brief Seal setup transfering ownership of a writer and a timer manager.
         *
         * @param a_writer        Websocket messages writer.
         * @param a_timer_manager Websocket timer manager.
         */
        inline void ngx::ws::Context::Hold (ngx::ws::Context::Writer* a_writer, ngx::ws::Context::TimerManager* a_timer_manager)
        {
            // ... sanity check ...
            if ( nullptr != writer_ptr_ || nullptr != timer_manager_ptr_ ) {
                throw ngx::ws::Context::Exception("%s already called!", __FUNCTION__);
            }
            writer_ptr_        = a_writer;
            timer_manager_ptr_ = a_timer_manager;
        }
        
        /**
         * @return Starts a send a message request.
         *
         * @param a_message
         *
         * @return True on success, false on error.
         */
        inline bool ngx::ws::Context::SendMessage (const ngx::ws::WebsocketBufferChain* a_message)
        {
            return writer_ptr_->SendMessage(a_message);
        }

    } // end of namespace 'ws'

} // end of namespace 'ngx'

#endif // NRS_NGX_WS_WEBSOCKET_CONTEXT_H_
