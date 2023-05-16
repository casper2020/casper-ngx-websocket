/**
 * @file ngx_http_websocket_module.cc
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

#include "ngx/ws/module/ngx_http_websocket_module.h"
#include "ngx/ws/abstract_websocket_client.h"

#ifdef DEBUG
    #include "ngx/ws/websocket_test_client.h"
#endif

#include <algorithm>

#ifdef __APPLE__
#pragma mark -
#pragma mark - NGINX WebSocket Module - Forward declarations
#pragma mark -
#endif

static void*                ngx_http_websocket_module_create_loc_conf    (ngx_conf_t* a_cf);
static char*                ngx_http_websocket_module_merge_loc_conf     (ngx_conf_t* a_cf, void* a_parent, void* a_child);

static ngx_int_t            ngx_http_websocket_module_filter_init        (ngx_conf_t* a_cf);

static void                 ngx_http_websocket_module_read_handler       (ngx_http_request_t* a_r);
static void                 ngx_http_websocket_module_write_handler      (ngx_http_request_t* a_r);
static void                 ngx_http_websocket_module_idle_handler       (ngx_event_t* a_ev);
static void                 ngx_http_websocket_module_timer_handler      (ngx_event_t* a_ev);

static void                 ngx_http_websocket_module_cleanup_handler    (void*);
static ngx::ws::NGXContext* ngx_http_websocket_module_context_setup      (ngx_http_request_t* a_r,
                                                                          const std::string& a_sec_websocket_protocol, const std::string& a_client_ip_address,
                                                                          const ngx_http_websocket_module_loc_conf_t* a_loc_conf);
static ngx_int_t            ngx_http_websocket_module_handshake          (ngx_http_request_t* a_r, const std::string& a_sec_websocket_protocol, std::map<std::string, std::string>& a_in_headers);

static time_t               ngx_http_websocket_module_time_utc            ();
static bool                 ngx_http_websocket_module_base_64_encode      (const unsigned char* a_buffer, size_t a_buffer_size, std::string& o_buffer);
static bool                 ngx_http_websocket_module_sha1                (const void* a_data, size_t a_data_len, unsigned char* o_data);

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - Static Data
#endif

static ngx_err_t  k_ngx_http_websocket_module_default_error_code = 0;
static const char k_ngx_http_websocket_module_basis_64        [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - Macros
#endif

#undef ngx_http_websocket_module_log_msg
#define ngx_http_websocket_module_log_msg(a_r, a_level, ...) \
    ngx_log_error(a_level, a_r->connection->log, k_ngx_http_websocket_module_default_error_code, __VA_ARGS__);     \

#ifdef DEBUG
    // #define NGX_HTTP_WEBSOCKET_MODULE_SOCKET_WRITE_BUFFER_LIMIT 10 // bytes
    // #define NGX_HTTP_WEBSOCKET_MODULE_SOCKET_READ_BUFFER_LIMIT  10 // bytes
    // #define NGX_HTTP_WEBSOCKET_MODULE_SOCKET_USE_TEST_CLIENT    1
#else
    #undef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_WRITE_BUFFER_LIMIT
    #undef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_READ_BUFFER_LIMIT
    #undef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_USE_TEST_CLIENT
#endif

/**
 * @brief This struct defines the configuration command handlers
 */
static ngx_command_t ngx_http_websocket_module_commands[] = {
    /*
     * nginx_websocket module config
     */
    {
        ngx_string("nginx_websocket"),                              /* directive name */
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,                          /* legal on location context and takes a boolean ("on" or "off") */
        ngx_conf_set_flag_slot,                                     /* translates "on" or "off" to 1 or 0 */
        NGX_HTTP_LOC_CONF_OFFSET,                                   /* value saved on the location struct configuration ... */
        offsetof(ngx_http_websocket_module_loc_conf_t, enable),      /* ... on the 'enable' element */
        NULL
    },
    {
        ngx_string("nginx_websocket_ping_period"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websocket_module_loc_conf_t, ping_period),
        NULL
    },
    {
        ngx_string("nginx_websocket_idle_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websocket_module_loc_conf_t, idle_timeout),
        NULL
    },
    /* closure */
    ngx_null_command
};

/**
 * @brief The WebSocket module context setup data.
 */
static ngx_http_module_t ngx_http_websocket_module_ctx = {
    NULL,                                       /* preconfiguration              */
    ngx_http_websocket_module_filter_init,      /* postconfiguration             */
    NULL,                                       /* create main configuration     */
    NULL,                                       /* init main configuration       */
    NULL,                                       /* create server configuration   */
    NULL,                                       /* merge server configuration    */
    ngx_http_websocket_module_create_loc_conf,  /* create location configuration */
    ngx_http_websocket_module_merge_loc_conf    /* merge location configuration  */
};

/**
 * @brief The WebSocket module setup data.
 */
ngx_module_t ngx_http_websocket_module = {
    NGX_MODULE_V1,
    &ngx_http_websocket_module_ctx,     /* module context    */
    ngx_http_websocket_module_commands, /* module directives */
    NGX_HTTP_MODULE,                    /* module type       */
    NULL,                               /* init master       */
    NULL,                               /* init module       */
    NULL,                               /* init process      */
    NULL,                               /* init thread       */
    NULL,                               /* exit thread       */
    NULL,                               /* exit process      */
    NULL,                               /* exit master       */
    NGX_MODULE_V1_PADDING
};

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - function(s) / method(s)
#endif

/**
 * @brief Alocate the module configuration structure
 */
static void* ngx_http_websocket_module_create_loc_conf (ngx_conf_t* a_cf)
{
    ngx_http_websocket_module_loc_conf_t* conf;

    conf = (ngx_http_websocket_module_loc_conf_t*) ngx_pcalloc(a_cf->pool, sizeof(ngx_http_websocket_module_loc_conf_t));
    if (NULL == conf) {
        return NGX_CONF_ERROR;
    }
    /* websocket */
    conf->enable       = NGX_CONF_UNSET;
    conf->ping_period  = NGX_CONF_UNSET;
    conf->idle_timeout = NGX_CONF_UNSET;
    // ... done ...
    return conf;
}

/**
 * @brief The merge 'loc' conf callback...
 */
static char* ngx_http_websocket_module_merge_loc_conf (ngx_conf_t* /* a_cf */, void* a_parent, void* a_child)
{
    ngx_http_websocket_module_loc_conf_t* prev = (ngx_http_websocket_module_loc_conf_t*) a_parent;
    ngx_http_websocket_module_loc_conf_t* conf = (ngx_http_websocket_module_loc_conf_t*) a_child;
    /* websocket */
    ngx_conf_merge_value (conf->enable      , prev->enable      ,       0 ); //       0 - disabled
    ngx_conf_merge_value (conf->ping_period , prev->ping_period ,      30 ); //      30 - 30s
    ngx_conf_merge_value (conf->idle_timeout, prev->idle_timeout, 15 * 60 ); // 15 * 60 - 15m
    // ... done ...
    return (char*) NGX_CONF_OK;
}

/**
 * @brief Filter module boiler plate installation
 */
static ngx_int_t ngx_http_websocket_module_filter_init (ngx_conf_t* a_cf)
{
    ngx_http_core_main_conf_t* cmcf = (ngx_http_core_main_conf_t*) ngx_http_conf_get_module_main_conf(a_cf, ngx_http_core_module);
    ngx_http_handler_pt* h;

    /*
     * Install the content handler
     */
    h = (ngx_http_handler_pt*) ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_websocket_module_content_handler;
    return NGX_OK;
}

/**
 * @brief Content phase handler, sends the stashed response or if does not exist passes to next handler
 *
 * @param  a_r The http request
 * @return @li NGX_DECLINED if the content is not produced here, pass to next
 *         @li the return of the content sender function
 */
ngx_int_t ngx_http_websocket_module_content_handler (ngx_http_request_t* a_r)
{
    ngx_int_t                             rc        = NGX_ERROR;
    ngx_http_websocket_module_loc_conf_t* loc_conf ;
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : %s",
                                      a_r, "enter");

    /* bail out if handling a subrequest/redirect */
    if ( ( 1 == a_r->internal ) && ( a_r == a_r->main ) ) {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : %s, redirect/subrequest... skipping...",
                                          a_r, "leaving");
        // decline request
        rc = NGX_DECLINED;
        return rc;
    }
    // grab local conf
    loc_conf = (ngx_http_websocket_module_loc_conf_t*) ngx_http_get_module_loc_conf(a_r, ngx_http_websocket_module);

    /* bail out if the module is not enabled */
    if ( 1 != loc_conf->enable ) {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : %s, not enabled... skipping...",
                                          a_r, "leaving");
        // decline request
        rc = NGX_DECLINED;
        return rc;
    }
    /*
     * This module is enabled.
     */
    std::map<std::string, std::string> in_headers;
    std::string                        sec_websocket_protocol;
    std::string                        client_ip_address;
    {
        // load received headers
        ngx_list_part_t* list_part = &a_r->headers_in.headers.part;
        while ( NULL != list_part ) {
            //
            ngx_table_elt_t* header = (ngx_table_elt_t*)list_part->elts;
            for ( ngx_uint_t index = 0 ; list_part->nelts > index ; ++index ) {
                //
                if ( 0 < header[index].key.len && 0 < header[index].value.len ) {
                    //
                    std::string key   = std::string(reinterpret_cast<char const*>(header[index].key.data), header[index].key.len);
                    std::string value = std::string(reinterpret_cast<char const*>(header[index].value.data), header[index].value.len);
                    //
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    in_headers[key] = value;
                }
            }
            // next...
            list_part = list_part->next;
        }
        // ... grab protocol(s) ....
        const auto protocols_it = in_headers.find(ngx::ws::AbstractWebsocketClient::k_websocket_protocol_header_key_lc_);
        if ( protocols_it != in_headers.end() ) {
            sec_websocket_protocol = protocols_it->second;
        }
        // ... grab client ip address ...
        const auto ip_address_it = in_headers.find("x-remote-ip");
        if ( ip_address_it != in_headers.end() ) {
            client_ip_address = ip_address_it->second;
        } else {
            client_ip_address = std::string(reinterpret_cast<char const*>(a_r->connection->addr_text.data), a_r->connection->addr_text.len);
        }
    }
    
    ngx::ws::NGXContext* context = NULL;
    ngx_http_cleanup_t*  cleanup = NULL;
    //
    context = ngx_http_websocket_module_context_setup(a_r, sec_websocket_protocol, client_ip_address, loc_conf);
    if ( NULL == context ) {
        rc = NGX_ERROR;
        goto leave;
    }
    /*
     * send handshake response to client
     */
    rc = ngx_http_websocket_module_handshake(a_r, context->client_->Protocol(), in_headers);
    if ( NGX_OK != rc ) {
        goto leave;
    }
    /*
     * setup cleanup handler
     */
    cleanup = ngx_http_cleanup_add(a_r, 0);
    if ( NULL == cleanup ) {
        rc = NGX_ERROR;
        goto leave;
    }
    cleanup->handler = ngx_http_websocket_module_cleanup_handler;
    cleanup->data    = a_r;
    /*
     * setup context
     */
    ngx_http_set_ctx(a_r, context, ngx_http_websocket_module);
    /*
     * setup websocket module specific read / write handlers
     */
    a_r->read_event_handler  = ngx_http_websocket_module_read_handler;
    a_r->write_event_handler = ngx_http_websocket_module_write_handler;
    // setup websocket module specific flags
    a_r->websocket_request    = 1;

    /*
     * schedule idle event
     */
    {
        ngx::ws::NGXWriter* writer = (ngx::ws::NGXWriter*)(context->writer_ptr_);
        if ( NULL != writer ) {
            writer->ScheduleIdleEvent();
        }
    }

#ifdef DEBUG

    #ifdef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_READ_BUFFER_LIMIT
        {
            const int  buffer_size = NGX_HTTP_WEBSOCKET_MODULE_SOCKET_READ_BUFFER_LIMIT; // in bytes
            const bool success     = 0 == setsockopt(a_r->connection->fd, SOL_SOCKET, SO_RCVBUF, (const void *) &buffer_size, sizeof(int));
            (void)success;
            // log
            ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : socket read buffer limit: %s to %d bytes",
                                              a_r, true == success ? "set" : "unable to set", buffer_size);
        }
    #endif

    #ifdef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_WRITE_BUFFER_LIMIT
        {
            const int  buffer_size = NGX_HTTP_WEBSOCKET_MODULE_SOCKET_WRITE_BUFFER_LIMIT; // in bytes
            const bool success     = 0 == setsockopt(a_r->connection->fd, SOL_SOCKET, SO_SNDBUF, (const void *) &buffer_size, sizeof(int));
            (void)success;
            // log
            ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : socket write buffer limit: %s to %d bytes",
                                              a_r, true == success ? "set" : "unable to set", buffer_size);
        }
    #endif

#endif

leave:
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CH] : %s, rc=%d",
                                      a_r, "leaving", rc);
    //
    if ( NGX_OK != rc && NULL != context ) {
        delete context;
    }
    //
    return rc;
}

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - Read / Write handlers
#endif

/**
 * @brief This method will be called when it's possible to read data from client.
 *
 * @param a_r The request to whom was granted the access to read data from client.
 */
static void ngx_http_websocket_module_read_handler (ngx_http_request_t* a_r)
{
    unsigned char buffer[10000];
    bool          frame_complete        = false;
    bool          message_fragmented    = false;
    ssize_t       read_bytes            = 0;
    size_t        total_read_bytes      = 0;
    size_t        number_of_dm_received = 0;

    ngx_connection_t*    connection  = a_r->connection;
    ngx::ws::NGXContext* context     = (ngx::ws::NGXContext*) ngx_http_get_module_ctx(a_r, ngx_http_websocket_module);
    if ( nullptr == context ) {
        return;
    }
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s",
                                      a_r, "enter");
    for ( ; ; ) {
        // read from current connection
        read_bytes = connection->recv(connection, buffer, sizeof(buffer));
        //
        if ( 0 == read_bytes ) {
            // log
            ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, %z byte(s)",
                                              a_r, "read", 0);
            // nothing to read
            break;
        } else if ( NGX_ERROR == read_bytes || 1 == connection->error ) {
            //
            if ( 1 == connection->error ) {
                // log
                ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, RH] : %s, connection error",
                                                  a_r, "error");
            } else {
                // log
                ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, RH] : %s, %z",
                                                  a_r, "error", read_bytes);
            }
            // got an error!
            goto terminate_connection;
        } else if ( 0 > read_bytes ) { // -2 == NGX_AGAIN
            // error
            if ( NGX_AGAIN == read_bytes ) {
                // log
                ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, NGX_AGAIN",
                                                  a_r, "error");
                //
                break;
            } else {
                // got an error!
                goto terminate_connection;
            }
        }
        if ( read_bytes > 0 ) {
            total_read_bytes += static_cast<size_t>(read_bytes);
        }
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, %z byte(s)",
                                          a_r, "read", read_bytes);
        // process all complete messages in buffer
        unsigned char*              buffer_ptr                 = buffer;
        ssize_t                     decoding_remaining_bytes   = read_bytes;
        ssize_t                     consumed_bytes             = 0;
        size_t                      decoded_bytes              = 0;
        ngx::ws::IncomingMessage*   rx_message                 = context->rx_active_message_;

        while ( 0 <= decoding_remaining_bytes ) {
            /*
             * I   ) A sender MAY create fragments of any size for non-control messages.
             * II  ) Clients and servers MUST support receiving both fragmented and unfragmented messages.
             * III ) Control frames cannot be fragmented,
             * IV  ) Control frames MAY be injected in the middle of a fragmented message.
             *
             *     As a consequence of these rules, all fragments of a message are of the same type, as set by the first fragment's opcode.
             */
            if ( false == rx_message->IsInUse() || true == rx_message->IsCurrentFrameComplete() ) {
                //
                uint8_t next_opcode = (uint8_t)ngx::ws::IncomingFrame::Opcodes::EInvalid;
                if ( true == ngx::ws::IncomingFrame::PeekOpcode(buffer_ptr, decoding_remaining_bytes, rx_message->IsCurrentFrameFragmented(), next_opcode) ) {
                    if ( true == ngx::ws::IncomingFrame::IsControlOpcode(next_opcode) ) {
                        context->rx_active_message_ = &context->rx_control_message_;
                        rx_message                  = &context->rx_control_message_;
                    } else {
                        context->rx_active_message_ = &context->rx_data_message_;
                        rx_message                  = &context->rx_data_message_;
                    }
                } else {
                    // protocol error
                    rx_message = NULL;
                }
            } /* else { } // keep using previous selected receiving frame */
            //
            if ( NULL == rx_message ) {
                // protocol error
                goto terminate_connection;
            }
            //
            decoding_remaining_bytes = ngx::ws::IncomingMessage::Decode(*rx_message, buffer_ptr, decoding_remaining_bytes, frame_complete, message_fragmented, decoded_bytes);
            // got a complete frame?
            if ( true == frame_complete && false == message_fragmented ) {
                //
                size_t payload_len;
                const unsigned char* payload_data = ( true == rx_message->IsFragmented() ? rx_message->UnchainPayload(payload_len) : rx_message->PayloadData(payload_len) );
                //
                switch ((ngx::ws::IncomingFrame::Opcodes)rx_message->Opcode()) {

                    case ngx::ws::IncomingFrame::Opcodes::EPing:
                    {
                        // log
                        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, 'PING', P @ 0x%p, %uz byte(s)",
                                                          a_r, "frame", payload_data, payload_len);
                    }
                        break;

                    case ngx::ws::IncomingFrame::Opcodes::EPong:
                    {
                        // log
                        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, 'PONG', P @ 0x%p, %uz byte(s)",
                                                          a_r, "frame", payload_data, payload_len);

#ifdef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_USE_TEST_CLIENT
                        if ( context->client_ != NULL ) {
                            ngx::ws::WebsocketTestClient* test_client = dynamic_cast<ngx::ws::WebsocketTestClient*>(context->client_);
                            if ( NULL != test_client ) {
                                test_client->Send();
                            }
                        }
#endif

                    }
                        break;

                    case ngx::ws::IncomingFrame::Opcodes::EClose:
                    {
                        // log
                        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, 'CLOSE', P @ 0x%p, %uz byte(s)",
                                                          a_r, "frame", payload_data, payload_len);
                    }
                        goto terminate_connection;

                    case ngx::ws::IncomingFrame::Opcodes::EText:
                    {
                        // log
                        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, 'TEXT', P @ 0x%p, %uz byte(s)",
                                                          a_r, "frame", payload_data, payload_len);
                        //
                        if ( context->client_ != NULL ) {
                            try {
                                context->client_->OnTextMessage(context, (const char*) payload_data, payload_len);
                                if ( true == context->error_ ) {
                                    goto terminate_connection;
                                }
                            } catch (ngx::ws::Context::Exception& a_exception) {
                                // log
                                ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, RH] : %s",
                                                                  a_r, a_exception.what());
                            }
                        }
                        //
                        number_of_dm_received++;
                    }
                        break;

                    case ngx::ws::IncomingFrame::Opcodes::EBinary:
                    {
                        // log
                        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, 'BINARY', P @ 0x%p, %uz byte(s)",
                                                          a_r, "frame", payload_data, payload_len);
                        //
                        number_of_dm_received++;
                    }
                        break;

                    default:
                    {
                        // nop
                    }
                        break;
                }
                // prepare for next frame
                rx_message->Reset();
            }
            // point to next frame
            consumed_bytes += decoded_bytes;
            buffer_ptr      = buffer + consumed_bytes;
            // no more frames
            if ( decoding_remaining_bytes <= 0 ) {
                break;
            }
        }
        //
        if ( decoding_remaining_bytes < 0 ) {
            // log
            ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, %s",
                                              a_r, "leaving", "protocol error");
            // protocol error!
            goto terminate_connection;
        } else if ( decoding_remaining_bytes == 0 ) {
            // nothing to process here - we will try to read again
            continue;
        }
    }
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, %z byte(s)",
                                      a_r, "leaving", total_read_bytes);
    // reset last data message exchanged timestamp?
    if ( 0 < number_of_dm_received ) {
        context->dm_last_exchanged_ts_ = ngx_http_websocket_module_time_utc();
    }
    //
    return;

terminate_connection:
    //
    a_r->websocket_request     = 0;
    a_r->connection->read->eof = 1;
    ngx_http_finalize_request(a_r, NGX_HTTP_CLOSE);
    // log
  //  ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, RH] : %s, %z byte(s) & finalize request",
  //                                    a_r, "leaving", total_read_bytes);
}

/**
 * @brief This method will be called when it's possible to send data to client.
 *
 * @param a_r The request to whom was granted the access to send data to client.
 */
static void ngx_http_websocket_module_write_handler (ngx_http_request_t* a_r)
{
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, WH] : %s",
                                      a_r, "enter");
    //
    ngx::ws::NGXContext* context;
    ngx::ws::NGXWriter*  writer;
    size_t               total_bytes_sent  = 0;
    size_t               number_of_dm_sent = 0;
    //
    context = (ngx::ws::NGXContext*) ngx_http_get_module_ctx(a_r, ngx_http_websocket_module);
    if ( NULL == context || true == context->error_ ) {
        return;
    }
    writer = (ngx::ws::NGXWriter*)(context->writer_ptr_);
    if ( NULL == writer ) {
        // we refuse to work without a writer
        goto terminate_connection;
    }
    // any message to send?
    if ( NULL == writer->next_message_ptr_ && NULL == writer->cm_ptr_ ) {
        // no messages to send
        goto leave;
    }
    // send current and all other messages requested by client
    while ( NULL != writer->next_message_ptr_ && a_r->connection->write->ready ) {
        //
        size_t       start_tx   = static_cast<size_t>(a_r->connection->sent);
        // send chain
        ngx_chain_t* rv         = ngx_writev_chain(a_r->connection, writer->next_message_ptr_->chain_ptr_, 0);
        // calculate the number of bytes sent
        size_t       bytes_sent = static_cast<size_t>(a_r->connection->sent) - start_tx;
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, WH] : msg chunk sent - %d byte(s) [ already sent %d byte(s) of %d byte(s), remaining %d byte(s), 0x%p ]",
                                          a_r, bytes_sent,
                                          writer->next_message_ptr_->bytes_sent_ + bytes_sent,
                                          writer->next_message_ptr_->total_bytes_,
                                          writer->next_message_ptr_->total_bytes_ - ( writer->next_message_ptr_->bytes_sent_ + bytes_sent ),
                                          rv);
        // end of chain?
        if ( NULL == rv ) {
            // no, we did send all chain, no need in keeping track of it
            writer->next_message_ptr_->chain_ptr_ = NULL;
            // ( keep track of the ones already sent )
            writer->next_message_ptr_->bytes_sent_ += bytes_sent;
            // notify client?
            if ( writer->next_message_ptr_ != writer->cm_ptr_ ) {
                // yes
                const ngx::ws::WebsocketBufferChain* next_bc = context->client_->OnMessageSent(context);

                if ( true == context->client_->CloseConnection() ) {
                    goto terminate_connection;
                }

                if ( NULL != next_bc ) {
                    // encode new writer->next_message_ptr_ ( previous one will be reset )
                    writer->next_message_ptr_ = writer->next_message_ptr_->Encode(next_bc);
                } else {
                    // forget this one
                    writer->next_message_ptr_ = writer->next_message_ptr_->Reset();
                }
                // keep track of the number of data messages sent
                number_of_dm_sent++;
            } else {
                // forget this one
                writer->next_message_ptr_ = writer->next_message_ptr_->Reset();
            }
            // log
            ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, WH] : nxt msg %d byte(s)",
                                              a_r, NULL != writer->next_message_ptr_ ? writer->next_message_ptr_->total_bytes_ : 0);
        } else if ( NGX_CHAIN_ERROR == rv ) {
            // protocol error
            goto terminate_connection;
        } else {
            // no, we did not send all chain, keep track of the last one sent
            writer->next_message_ptr_->chain_ptr_ = rv;
            // no, still have more bytes to send
            // ( keep track of the ones already sent )
            writer->next_message_ptr_->bytes_sent_ += bytes_sent;
        }
        total_bytes_sent += bytes_sent;
        // next...
    }

    // still have content to sent?
    if ( NULL != writer->next_message_ptr_ ) {
        if ( !a_r->connection->write->delayed ) {
            ngx_add_timer(a_r->connection->write, (ngx_msec_t)5);
        }
        // keep write event set
        if (ngx_handle_write_event(a_r->connection->write, 0) != NGX_OK) {
            goto terminate_connection;
        }
    } else {
        // schedule next idle event
        writer->ScheduleIdleEvent();
    }

leave:
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, WH] : %s, %d byte(s) sent - success",
                                      a_r, "leaving", total_bytes_sent);

    // reset last data message exchanged timestamp?
    if ( 0 < number_of_dm_sent ) {
        context->dm_last_exchanged_ts_ = ngx_http_websocket_module_time_utc();
    }
    return;

terminate_connection:
    context->error_ = true;
    if ( true == context->client_->CloseConnection() ) {
        //
        a_r->websocket_request      = 0;
        a_r->connection->read->eof  = 1;
        a_r->connection->write->eof = 1;
        a_r->write_event_handler    = nullptr;
        ngx_http_finalize_request(a_r, NGX_HTTP_CLOSE);
    }
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, WH] : %s, %z byte(s) & finalize request",
                                      a_r, "leaving", total_bytes_sent);
}

/**
 * @brief This method will be called when we need to keep connection alive.
 *
 * @param a_ev The event that was scheduled so we send a 'Ping' control message to keep the connection alive.
 */
void ngx_http_websocket_module_idle_handler (ngx_event_t* a_ev)
{
    ngx_http_request_t* request = (ngx_http_request_t*) a_ev->data;
    //
    if ( 1 == ngx_exiting || NULL == a_ev || NULL == request ) {
        // can't proceed
        return;
    }
    //
    std::string exception_msg = "";
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                      request, "enter");
    //
    try {
        //
        ngx::ws::NGXContext* context  = (ngx::ws::NGXContext*) ngx_http_get_module_ctx(request, ngx_http_websocket_module);
        ngx::ws::NGXWriter*  writer   = (ngx::ws::NGXWriter*)(context->writer_ptr_);
        const time_t         now      = ngx_http_websocket_module_time_utc();
        const time_t         elapsed  = context->dm_last_exchanged_ts_ > 0 ? ( now - context->dm_last_exchanged_ts_ ) : 0;
        // close message or ping?
        if ( context->dm_timeout_ <= elapsed ) {
            // log
            ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                              request, "timeout, CLOSE control message sent...");
            // cancel idle event
            writer->CancelIdleEvent();
            // cancel all other events
            ngx::ws::NGXTimerManager* timer_event_issuer = dynamic_cast<ngx::ws::NGXTimerManager*>(context->timer_manager_ptr_);
            if ( NULL != timer_event_issuer ) {
                timer_event_issuer->CancelAll();
            }
            // send 'close' control message
            writer->Close();
            // client should send 'CLOSE' message
            // exception_msg = "timeout";
            // goto terminate_connection;
        } else {
            // log
            ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                              request, "idle, PING control message sent...");
            // send 'ping' control message
            writer->Ping();
        }
        //
    } catch (ngx::ws::NGXException& a_exception) {
        //
        exception_msg = a_exception.what();
        //
        goto exception_caught;
    } catch (...) {
        //
        exception_msg = "C++ Generic Exception: " + ngx::ws::NGXException::What(std::current_exception(), __FILE__, __LINE__);
        //
        goto exception_caught;
    }
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                      request, "leaving");
    //
    return;

exception_caught:
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, IH] : *** EXCEPTION, %s",
                                      request, exception_msg.c_str());
terminate_connection:
    //
    request->websocket_request     = 0;
    request->connection->read->eof = 1;
    ngx_http_finalize_request(request, NGX_HTTP_CLOSE);
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s, %s, finalize request",
                                      request, "leaving", exception_msg.c_str());
}

/**
 * @brief This method will be called when a previously registered timer event needs to be processed.
 *
 * @param a_ev The event that was scheduled.
 */
static void ngx_http_websocket_module_timer_handler (ngx_event_t* a_ev)
{
    // can't proceed?
    if ( 1 == ngx_exiting || NULL == a_ev || NULL == a_ev->data ) {
        return;
    }
    // can't proceed?
    ngx::ws::NGXTimerEvent::Data* data = (ngx::ws::NGXTimerEvent::Data*)a_ev->data;
    if ( NULL == data->request_ptr_ ) {
        return;
    }

    std::string exception_msg = "";
    // log
    ngx_http_websocket_module_log_msg(data->request_ptr_, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                      data->request_ptr_, "enter");
    // process event
    try {
        ngx::ws::NGXContext* context  = (ngx::ws::NGXContext*) ngx_http_get_module_ctx(data->request_ptr_, ngx_http_websocket_module);
        if ( NULL == context ) {
            throw ngx::ws::NGXException("~ngx_http_websocket_module_timer_handler~ - context not ready!");
        } else {
            try {
                context->timer_callback_ = 1;
                (*data->internal_handler_ptr_)(a_ev, context->timer_manager_ptr_);
                context->timer_callback_ = 0;
            } catch (ngx::ws::NGXException& a_exception) {
                context->timer_callback_ = 0;
                throw a_exception;
            }
        }
    } catch (ngx::ws::NGXException& a_exception) {
        exception_msg = a_exception.what();
        // log
        ngx_http_websocket_module_log_msg(data->request_ptr_, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, IH] : *** EXCEPTION, %s",
                                          data->request_ptr_, exception_msg.c_str());
    } catch (...) {
        //
        exception_msg = "C++ Generic Exception: " + ngx::ws::NGXException::What(std::current_exception(), __FILE__, __LINE__);
        // log
        ngx_http_websocket_module_log_msg(data->request_ptr_, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, IH] : *** EXCEPTION, %s",
                                          data->request_ptr_, exception_msg.c_str());
    }
    // log
    ngx_http_websocket_module_log_msg(data->request_ptr_, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, IH] : %s",
                                      data->request_ptr_, "leaving");
}

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - Cleanup handler
#endif

/**
 * @brief This method will be called when nginx is about to finalize a connection.
 *
 * @param a_data In this module, is the pointer to the request it self.
 */
static void ngx_http_websocket_module_cleanup_handler (void* a_data)
{
    ngx_http_request_t*  request = (ngx_http_request_t*) a_data;
    ngx::ws::NGXContext* context = (ngx::ws::NGXContext*) ngx_http_get_module_ctx(request, ngx_http_websocket_module);
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, FH] : %s",
                                      request, "enter");
    //
    if ( context != NULL ) {
        // log
        ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, FH] : delete context 0x%p",
                                          request, context);
        // release previous allocated memory @ ngx_http_websocket_module_context_setup
        ngx::ws::NGXWriter* writer = dynamic_cast<ngx::ws::NGXWriter*>(context->writer_ptr_);
        if ( NULL != writer ) {
            delete writer;
        }
        ngx::ws::NGXTimerManager* timer_event_issuer = dynamic_cast<ngx::ws::NGXTimerManager*>(context->timer_manager_ptr_);
        if ( NULL != timer_event_issuer ) {
            delete timer_event_issuer;
        }
        // notify client
        context->client_->OnConnectionClosed(context);
        //
        delete context;
        ngx_http_set_ctx(request, NULL, ngx_http_websocket_module);
    }
    // log
    ngx_http_websocket_module_log_msg(request, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, FH] : %s",
                                      request, "leaving");
}

#ifdef __APPLE__
#pragma mark - NGINX WebSocket Module - helper method(s) / function(s)
#endif

/*
 * @brief Creates a C++ context for an HTTP connection.
 *
 * @param a_r                      The nginx http request.
 * @param a_sec_websocket_protocol The client protocol list ( ',' separated ).
 * @param a_client_ip_address      The client IP address.
 * @param a_loc_conf               Pointer to the module local configuration.
 *
 * @return A new instance of a \link ngx::ws::NGXContext \link.
 */
ngx::ws::NGXContext* ngx_http_websocket_module_context_setup (ngx_http_request_t* a_r,
                                                              const std::string& a_sec_websocket_protocol,
                                                              const std::string& a_client_ip_address,
                                                              const ngx_http_websocket_module_loc_conf_t* a_loc_conf)
{
    ngx::ws::NGXWriter*               writer                 = NULL;
    ngx::ws::NGXContext*              context                = NULL;
    ngx::ws::NGXTimerManager*         timer_event_manager     = NULL;

    std::string                       exception_message;
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CS] : %s",
                                      a_r, "enter");
    //
    try {
        // create writer
        writer              = new ngx::ws::NGXWriter(a_r);
        writer->SetWriteHandler(ngx_http_websocket_module_write_handler);
        writer->SetIdleHandler (ngx_http_websocket_module_idle_handler, a_loc_conf->ping_period);
        // create timer manager
        timer_event_manager = new ngx::ws::NGXTimerManager(a_r, ngx_http_websocket_module_timer_handler);
        // create context
        context = new ngx::ws::NGXContext(ngx_http_websocket_module, a_r);
        // setup context
        context->Setup(a_sec_websocket_protocol, a_client_ip_address)
            .Hold(writer, timer_event_manager);
        context->dm_last_exchanged_ts_ = ngx_http_websocket_module_time_utc();
        context->dm_timeout_           = a_loc_conf->idle_timeout;
    } catch (ngx::ws::NGXException& a_exception) {
        // log
        exception_message = a_exception.what();
        //
        goto exception_caught;
    } catch (...) {
        //
        exception_message = "~Context::Setup~ - C++ Generic Exception: " + ngx::ws::NGXException::What(std::current_exception(), __FILE__, __LINE__);
        //
        goto exception_caught;
    }
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CS] : %s",
                                      a_r, "leaving");
    //
    return context;

exception_caught:

    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, CS] : *** EXCEPTION, %s",
                                      a_r, exception_message.c_str());
    if ( NULL != writer ) {
        delete writer;
    }
    if ( NULL != timer_event_manager ) {
        delete timer_event_manager;
    }
    if ( NULL != context ) {
        delete context;
    }

    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, CS] : %s",
                                      a_r, "leaving");

    return NULL;
}

/*
 * @brief Send an HTTP response for the websocket connection upgrade response.
 *
 * @param a_r                      The nginx http request.
 * @param a_sec_websocket_protocol The client selected protocol.
 * @param a_in_headers             The received HTTP headers.
 *
 * @return An nginx status code.
 *
 */
ngx_int_t ngx_http_websocket_module_handshake (ngx_http_request_t* a_r, const std::string& a_sec_websocket_protocol, std::map<std::string, std::string>& a_in_headers)
{
    //
    static const char                   k_welcome_message [] = "{\"action\":\"ping\"}";
    static const char                   k_content_type    [] = "application/json; charset=utf-8";
    //
    std::map<std::string, std::string>  out_headers;
    ngx_uint_t                          handshake_status_code = NGX_HTTP_BAD_REQUEST;
    ngx::ws::OutgoingMessage            message;

    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, HF] : enter",
                                      a_r, handshake_status_code);

    /*
     * validate params
     */
    if ( 0 == a_sec_websocket_protocol.length() ) {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, HF] : leaving, %s='%s' is invalid!",
                                          a_r, ngx::ws::AbstractWebsocketClient::k_websocket_protocol_header_key_lc_, a_sec_websocket_protocol.c_str());
        // a_sec_websocket_protocol needs to be set
        return NGX_ERROR;
    }
    /*
     * setup handshake
     */
    {
        ngx::ws::NGXServerHandshake handshake(a_sec_websocket_protocol.c_str(), ngx_http_websocket_module_sha1, ngx_http_websocket_module_base_64_encode);
        if ( true == handshake.Handshake(a_in_headers, out_headers) ) {
            handshake_status_code = NGX_HTTP_SWITCHING_PROTOCOLS;
        } else {
            handshake_status_code = NGX_HTTP_UNAUTHORIZED;
        }
    }
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, HF] : handskake: %d",
                                      a_r, handshake_status_code);
    //
    ngx_str_t out_data;
    // did switch protocols?
    if ( handshake_status_code == NGX_HTTP_SWITCHING_PROTOCOLS ) {
        ngx::ws::OutgoingMessage::Ping(message, (const unsigned char*)k_welcome_message, strlen(k_welcome_message), NULL);
        out_data.data = const_cast<u_char*>(message.FrameBuffer(out_data.len));
    } else {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, HF] : leaving, http_status_code =%d, rc=%d",
                                          a_r, handshake_status_code, NGX_ERROR);
        // did not, cannot continue
        return NGX_ERROR;
    }
    // allocate response buffer
    ngx_buf_t* b = (ngx_buf_t*) ngx_pcalloc(a_r->pool, sizeof(ngx_buf_t));
    if ( b == NULL ) {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, HF] : leaving, failed to allocate response buffer",
                                          a_r);
        //
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // allocate response chain
    ngx_chain_t* c = (ngx_chain_t*) ngx_pcalloc(a_r->pool, sizeof(ngx_chain_t));
    if ( c == NULL ) {
        // log
        ngx_http_websocket_module_log_msg(a_r, NGX_LOG_ERR, "[ngx_ws_module, 0x%p, HF] : leaving, failed to allocate response chain",
                                          a_r);
        //
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    //
    b->pos = b->last = (u_char*) out_data.data;     // first position in memory of the data
    b->last         += out_data.len;                // last position
    b->memory        = 1;                           // content is in read-only memory filters must copy to modify,
    b->last_buf      = 1;                           // there will be no more buffers in the request
    b->last_in_chain = 1;
    //
    c->buf           = b;
    c->next          = NULL;
    /*
     * Adjust response headers
     */
    a_r->headers_out.status            = handshake_status_code;
    a_r->headers_out.content_length_n  = static_cast<off_t>(out_data.len);
    a_r->headers_out.content_type.len  = sizeof(k_content_type) - 1;
    a_r->headers_out.content_type.data = (u_char *)k_content_type;
    /*
     * Append additional response headers
     */
    if ( 0 != out_headers.size() ) {
        //
        for ( std::map<std::string, std::string>::const_iterator it = out_headers.begin(); out_headers.end() != it ; ++it ) {
            //
            const size_t k_l = it->first.length()  + 1;
            const size_t v_l = it->second.length() + 1;
            //
            if ( 1 == k_l || 1 == v_l ) {
                continue;
            }
            //
            ngx_table_elt_t* header = (ngx_table_elt_t*) ngx_list_push(&a_r->headers_out.headers);
            if ( header == NULL ) {
                return NGX_ERROR;
            }
            //
            header->key.data  = (u_char*) ngx_pcalloc(a_r->pool, k_l);
            if ( NULL == header->key.data ) {
                return NGX_ERROR;
            }
            const char* k_v  = it->first.c_str();
            const auto  k_r = snprintf((char*)header->key.data, k_l, "%s", k_v);
            if ( k_r < 0 ) {
                return NGX_ERROR;
            }
            header->key.len = static_cast<size_t>(k_r);
            //
            header->value.data = (u_char*) ngx_pcalloc(a_r->pool,  v_l);
            if ( NULL == header->value.data ) {
                return NGX_ERROR;
            }
            const char* v_v = it->second.c_str();
            const auto  v_r = snprintf((char*)header->value.data, v_l, "%s", v_v);
            if ( v_r < 0 ) {
                return NGX_ERROR;
            }
            header->value.len = static_cast<size_t>(v_r);
            //
            header->hash = 1;
        }
    }
    // send headers
    ngx_int_t rc = ngx_http_send_header(a_r);
    if ( rc == NGX_ERROR || rc > NGX_OK || a_r->header_only ) {
        goto leave;
    }
    /*
     * Next step...
     */
    rc = ngx_http_output_filter(a_r, c);
leave:
    // log
    ngx_http_websocket_module_log_msg(a_r, NGX_LOG_DEBUG, "[ngx_ws_module, 0x%p, HF] : leaving, rc=%d",
                                      a_r, rc);
    //
    return rc;
}

#ifdef __APPLE__
#pragma mark -
#endif

/**
 * Encode a string to base 64.
 *
 * @param o_encoded The output buffer.
 * @param a_string  The string to be encoded.
 * @param a_len     The length of string to be encoded.
 *
 * @return The encoded message length.
 */
static int ngx_http_websocket_module_base_64_encoder (char* o_encoded, const char* a_string, const int a_len)
{
    int i;
    char *p;

    p = o_encoded;
    for (i = 0; i < a_len - 2; i += 3) {
        *p++ = k_ngx_http_websocket_module_basis_64[(a_string[i] >> 2) & 0x3F];
        *p++ = k_ngx_http_websocket_module_basis_64[((a_string[i] & 0x3) << 4) |
                        ((int) (a_string[i + 1] & 0xF0) >> 4)];
        *p++ = k_ngx_http_websocket_module_basis_64[((a_string[i + 1] & 0xF) << 2) |
                        ((int) (a_string[i + 2] & 0xC0) >> 6)];
        *p++ = k_ngx_http_websocket_module_basis_64[a_string[i + 2] & 0x3F];
    }
    if (i < a_len) {
        *p++ = k_ngx_http_websocket_module_basis_64[(a_string[i] >> 2) & 0x3F];
        if (i == (a_len - 1)) {
            *p++ = k_ngx_http_websocket_module_basis_64[((a_string[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else {
            *p++ = k_ngx_http_websocket_module_basis_64[((a_string[i] & 0x3) << 4) |
                            ((int) (a_string[i + 1] & 0xF0) >> 4)];
            *p++ = k_ngx_http_websocket_module_basis_64[((a_string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    *p++ = '\0';
    return static_cast<int>(p - o_encoded);
}

/**
 * @brief Calculates the time of day ( UTC ).
 *
 * @return The unixepoch ( UTC ).
 */
time_t ngx_http_websocket_module_time_utc ()
{
    struct timeval tv;
    struct tm      tm;
    if ( gettimeofday(&tv, NULL) == 0 ) {
        if ( gmtime_r(&tv.tv_sec, &tm) == &tm ) {
            return mktime(&tm);
        }
    }
    return 0;
}

/**
 * Encode a buffer to base 64.
 *
 * @param a_buffer      The buffer to be encoded.
 * @param a_buffer_size The length of buffer to be encoded.
 * @param o_buffer      The output buffer.
 *
 * @return
 *         @li True on success,
 *         @li False on failure
 */
bool ngx_http_websocket_module_base_64_encode (const unsigned char* a_buffer, size_t a_buffer_size, std::string& o_buffer)
{
    const size_t b64_buffer_len = ((a_buffer_size + 2) / 3 * 4) + 1;
    //
    char* b64_buffer = new char[b64_buffer_len];
    if ( NULL == b64_buffer ) {
        // out of memory
        return false;
    }
    //
    b64_buffer[0] = '\0';
    //
    const int rv = ngx_http_websocket_module_base_64_encoder(b64_buffer, reinterpret_cast<char const*>(a_buffer), static_cast<int>(a_buffer_size));
    if ( b64_buffer_len == static_cast<size_t>(rv) ) {
        o_buffer = b64_buffer;
    } else {
        o_buffer = "";
    }
    //
    delete [] b64_buffer;
    //
    return 0 < o_buffer.length();
}

#include <openssl/sha.h>

/**
 * Calulate SHA1.
 *
 * @param a_data     The input buffer.
 * @param a_data_len The length of the input buffer.
 * @param o_data     The output buffer.
 *
 * @return
 *         @li True on success,
 *         @li False on failure
 */
bool ngx_http_websocket_module_sha1 (const void* a_data, size_t a_data_len, unsigned char* o_data)
{
    //
    if ( NULL == a_data || 0 == a_data_len || NULL == o_data ) {
        // can't calculate
        return false;
    }
    //
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    //
    SHA1_Update(&ctx, a_data, a_data_len);
    SHA1_Final(o_data, &ctx);
    //
    return true;
}

// endof ngx_http_websocket_module.cc
