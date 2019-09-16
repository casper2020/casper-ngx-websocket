/**
 * @file abstract_websocket_client.h
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
#ifndef NRS_NGX_WS_ABSTRACT_WEBSOCKET_CLIENT_H_
#define NRS_NGX_WS_ABSTRACT_WEBSOCKET_CLIENT_H_

#include <sys/types.h>  // size_t
#include <string.h>     // NULL
#include <stdlib.h>     // malloc // free
#include <string>       //
#include <map>          //

#include "ngx/ws/websocket_buffer_chain.h"

namespace ngx
{
    namespace ws
    {

        class Context;

        class AbstractWebsocketClient;

        typedef AbstractWebsocketClient* (*ClientFactory)(Context* a_ws_context,
							  const std::map<std::string, std::string>& a_config);
        typedef std::map<std::string, ClientFactory> ClientRegistry;

        /**
         * @brief Interface that websocket clients must implement
         */
        class AbstractWebsocketClient
        {
        public: // Static Data

            static const char* const k_websocket_protocol_header_key_lc_;
            static const char* const k_websocket_protocol_remote_ip_key_lc_;
            static const char* const k_websocket_resources_root_key_lc_;
            static const char* const k_websocket_logs_root_key_lc_;
            static const char* const k_websocket_http_file_server_host_key_lc_;
            static const char* const k_websocket_http_file_server_port_key_lc_;
            static const char* const k_http_json_content_type_;
            static const char* const k_redis_ip_address_key_lc_;
            static const char* const k_redis_port_number_key_lc_;
            static const char* const k_redis_database_key_lc_;
            static const char* const k_redis_max_conn_per_worker_lc_;
            static const char* const k_postgresql_conn_str_key_lc_;
            static const char* const k_postgresql_statement_timeout_lc_;
            static const char* const k_postgresql_post_connect_queries_lc_;
            static const char* const k_postgresql_max_conn_per_worker_lc_;
            static const char* const k_postgresql_min_queries_per_conn_lc_;
            static const char* const k_postgresql_max_queries_per_conn_lc_;
            static const char* const k_curl_max_conn_per_worker_lc_;
            static const char* const k_json_api_url_key_lc_;
            static const char* const k_jrxml_base_directory_key_lc_;
            static const char* const k_service_id_lc_;
            static const char* const k_beanstalkd_host_key_lc_;
            static const char* const k_beanstalkd_port_key_lc_;
            static const char* const k_beanstalkd_timeout_key_lc_;
            static const char* const k_beanstalkd_sessionless_tubes_key_lc_;
            static const char* const k_beanstalkd_action_tubes_key_lc_;
            static const char* const k_logger_register_tokens_key_lc_;
            static const char* const k_data_source_overridable_sys_vars_lc_;
            static const char* const k_http_base_url_map_key_lc_;
            static const char* const k_session_fields_key_lc_;
            static const char* const k_session_extension_amount_key_lc_;

        protected: // Data

            static ClientRegistry* g_registry_;

        protected: // Data

            bool close_connection_;

        public: // Methods

            AbstractWebsocketClient ()
            {
                close_connection_ = false;
            }

            virtual ~AbstractWebsocketClient ();

            /**
             * @brief Register a client factory for the specified protocol
             *
             * @param a_protocol The protocol understood by the client.
             * @param a_factory  The protocol factory.
             */
            static void RegisterFactory   (const char* a_protocol, ClientFactory a_factory);

            /**
             * @brief Unegister a client factory for the specified protocol
             *
             * @param a_protocol The protocol understood by the client.
             */
            static void UnregisterFactory (const char* a_protocol);

            /**
             * @brief Create a client handler for the specified protocol
             *
             * @param a_ws_context pointer to the context that received the connection
             * @param a_config
	         * @param a_resources_path
             *
             * @return New instance of the client or NULL if the request can't not be honoured
             */
            static AbstractWebsocketClient* Factory (Context* a_ws_context,
						     const std::map<std::string, std::string>& a_config);

        public: // Methods called by the context

            /**
             * @brief Called by the context to retrieve the protocol implemented by the client
             */
            virtual const char* Protocol () = 0;

            /**
             * @brief Called by context to select message delivery API
             *
             * @return @li true if the clients supports chained buffer, context always calls #OnChainedMessage
             *         @li false if the clients needs data in contigous memory, context calls #OnBinaryMessage and/or #OnTextMessage
             */
            virtual bool UseChains () = 0;

            /**
             * @brief Called by context when a new binary message is received
             *
             * @param a_ws_context pointer to the context that received the message
             * @param a_data pointer to the message payload
             * @param a_size size of the messsage payload
             *
             * @note  The message memory is released by the context after this method returns
             */
            virtual void OnBinaryMessage (const Context* a_ws_context, const void* a_data, size_t a_size) = 0;

            /**
             * @brief Called by context when a new text message is received
             *
             * @param a_ws_context pointer to the context that received the message
             * @param a_data pointer to the message text payload
             * @param a_size size of the messsage payload
             *
             * @note  The message memory is released by the context after this method returns
             */
            virtual void OnTextMessage (const Context* a_ws_context, const char* a_data, size_t a_size) = 0;

            /**
             * @brief Called by context when a chained message is received
             *
             * @param a_ws_context pointer to the context that received the message
             * @param a_chain pointer to the message text payload
             *
             * @note  The message memory is released by the context after this method returns
             */
            virtual void OnChainedMessage (const Context* a_ws_context, const ngx::ws::WebsocketBufferChain* a_chain) = 0;

            /**
             * @brief Called by the context to pull the next queued message
             *
             * @param a_ws_context pointer to the context that transmitted the message
             *
             * @return @li pointer to next message to transmit
             *         @li NULL there are no more messages to send, context should idle the transmitter
             */
            virtual const ngx::ws::WebsocketBufferChain* OnMessageSent (const Context* a_ws_context) = 0;

            /**
             * @brief Called by context to inform the client that the websocket connection was terminated
             *
             * @param a_ws_context pointer to the context that was terminated
             */
            virtual void OnConnectionClosed (const Context* a_ws_context) = 0;

            /**
             * @brief This method will be called when an exception was caught.
             *
             * @param a_exception
             */
            virtual void OnExceptionCaught (const Context* a_ws_context, const std::exception& a_exception) = 0;

            /**
             * @brief This method will be called when an error was caught.
             *
             * @param a_error
             */
            virtual void OnErrorCaught (const ::ngx::ws::Context* a_ws_context, const std::runtime_error& a_error) = 0;


        public: // Transmission API where the client implemented it specfic queueing and priority strategies

            /**
             * @brief Client calls this internal method to send a binary message
             *
             * Queuing logic will eventually call the context #SendBinaryMessage
             *
             * @param a_data pointer to the message payload
             * @param a_size size of the messsage payload
             *
             * @note The client is responsible for managing the message memory lifecycle
             */
            virtual void PostBinaryMessage (const void* a_data, size_t a_size) = 0;

            /**
             * @brief Client calls this internal method to send a text message
             *
             * Queuing logic will eventually call the context #SendTextMessage
             *
             * @param a_data pointer to the message text payload
             * @param a_size size of the messsage payload
             *
             * @note The client is responsible for managing the message memory lifecycle
             */
            virtual void PostTextMessage (const void* a_data, size_t a_size) = 0;

            /**
             * @brief Client calls this internal method to send a binary message
             *
             * Queueing logic will eventually call the context's #SendChainedMessage
             *
             * @param a_chain Buffer chain to transmit
             *
             * @note The client is responsible for managing the message memory lifecycle
             */
            virtual void PostChainedMessage (ngx::ws::WebsocketBufferChain* a_chain) = 0;

        public:

            bool CloseConnection ();

        };

        inline AbstractWebsocketClient::~AbstractWebsocketClient ()
        {
            /* empty */
        }

        inline bool AbstractWebsocketClient::CloseConnection ()
        {
            return close_connection_;
        }


    } // namespace ws
} // namespace nginx

#endif // NRS_NGX_WS_ABSTRACT_WEBSOCKET_CLIENT_H_
