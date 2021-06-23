/**
 * @file ngx_http_websocket_module.h
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
#ifndef NRS_NGX_HTTP_WEBSOCKET_MODULE_H_
#define NRS_NGX_HTTP_WEBSOCKET_MODULE_H_

extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
    #include <ngx_errno.h>
}

#include "ngx/ws/websocket_context.h"

#include <queue>
#include <exception>
#include <stack>

#ifdef __APPLE__
#pragma mark - NGINX websocket module loc_conf_t
#endif

#include "ngx/ws/config.h"

/**
 * @brief Module 'srv' configuration structure, applicable to a location scope
 */
typedef nginx_epaper_service_conf_t ngx_http_websocket_module_main_conf_t;

/**
 * @brief Module 'local' configuration structure, applicable to a location scope
 */
typedef struct {
    ngx_flag_t                             enable;                           //!< flag that enables the module
    ngx_int_t                              ping_period;                      //!< the number of seconds between pings
    ngx_int_t                              idle_timeout;                     //!< the maximum number of seconds without exchanging data messages
    
    nginx_epaper_casper_editor_conf_t      editor;    
} ngx_http_websocket_module_loc_conf_t;

extern ngx_module_t ngx_http_websocket_module;
extern ngx_int_t    ngx_http_websocket_module_content_handler (ngx_http_request_t* a_r);

#ifdef __APPLE__
#pragma mark - C++ Classes
#endif

namespace ngx {

    namespace ws {

#ifdef __APPLE__
#pragma mark - NGXConfigurationException
#endif
        /**
         * @brief An exception class that carries a user message of the fault origin.
         */
        class NGXException: public std::exception
        {

        private: // data

            char reason_ [512];

        public: // constructor / destructor

            /**
             * @brief A constructor that provides the reason of the fault origin.
             *
             * @param a_format printf like format followed by a variable number of arguments
             */
            NGXException (const char* a_format, ...) throw ()
            {
                va_list args;
                va_start(args, a_format);
                vsnprintf(reason_, sizeof(reason_) / sizeof(reason_[0]), a_format, args);
                va_end(args);
            }

        public: // overrides

            virtual const char* what() const throw()
            {
                return reason_;
            }
            
        public: // Static Method(s) / Function(s)
            
            static std::string What (const std::exception_ptr& a_ptr, const char* const a_file, int a_line)
            {
                std::string exception_message = std::string(a_file) + ':' + std::to_string(a_line) + ' ';
                if ( a_ptr ) {
#ifdef __APPLE__
                    try {
                        std::rethrow_exception(a_ptr);
                    } catch(const std::exception& e) {
                        exception_message += std::string(e.what());
                    } catch (...) {
                        exception_message += "???";
                    }
#else
                    exception_message += std::string(a_ptr.__cxa_exception_type()->name());
#endif
                } else {
                    exception_message += "std::exception_ptr is nullptr";
                }
                return exception_message;
            }

        };

#ifdef __APPLE__
#pragma mark - NGXServerHandshake Class
#endif

        /**
         * A class that implements the server side handshake as part of nginx websocket module.
         */
        class NGXServerHandshake : public ngx::ws::ServerHandshake
        {

        public: // typedefs

            typedef bool(*sha1)(const void* a_data, size_t a_data_len, unsigned char* o_data);
            typedef bool(*b64e)(const unsigned char* a_buffer, size_t a_buffer_size, std::string& o_buffer);

        private: // data

            sha1 sha1_ptr_;     //!< sha1 function pointer
            b64e b64e_ptr_;     //!< base 64 encoder function pointer

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            NGXServerHandshake (char const* a_protocol, sha1 a_sha1, b64e a_b64e) : ngx::ws::ServerHandshake(a_protocol)
            {
                sha1_ptr_ = a_sha1;
                b64e_ptr_ = a_b64e;
            }

            /**
             * @brief Destructor.
             */
            virtual ~NGXServerHandshake ()
            {
                sha1_ptr_ = NULL;
                b64e_ptr_ = NULL;
            }

        public: // pure virtual method(s) / function(s) - declaration

            /**
             * @brief This function MUST calculate SHA1 with the provided params.
             *
             * @param a_data     The input data.
             * @param a_data_len The input data length.
             * @param o_data     The output data ( 20 bytes long ).
             *
             * @return
             *          @li True on sucess.
             *          @li False on failure.
             */
            virtual bool SHA1 (const void* a_data, size_t a_data_len, unsigned char* o_data)
            {
                return sha1_ptr_(a_data, a_data_len, o_data);
            }

            /**
             * @brief This function MUST encode data into a BASE 64 string with the provided params.
             *
             * @param a_data     The input data.
             * @param a_data_len The input data length.
             * @param o_data     The output data.
             *
             * @return
             *          @li True on sucess.
             *          @li False on failure.
             */
            virtual bool B64E (const unsigned char* a_data, size_t a_data_len, std::string& o_data)
            {
                return b64e_ptr_(a_data, a_data_len, o_data);
            }

        };

#ifdef __APPLE__
#pragma mark - NGXOutgoingMessage Class
#endif

        /**
         * @brief A wrapper class that contains nginx specific data
         *        to send an outgoing message.
         */
        class NGXOutgoingMessage {

        private: // data

            unsigned char   header_buffer_ [10] ; //   and links to other chains that contain the message payload
            ngx_chain_t*    head_chain_;          //!< an instance of nginx chain type that contains the message header

        public: // data

            ngx_chain_t*    chain_ptr_;         //!< pointer to the current chain that is being processed
            size_t          bytes_sent_;        //!< the number of bytes already sent
            size_t          total_bytes_;       //!< the total number of bytes to send

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            NGXOutgoingMessage ()
            {
                header_buffer_[0] = 0;
                head_chain_  = NewChain(header_buffer_, sizeof(header_buffer_) / sizeof(header_buffer_[0]));
                chain_ptr_   = NULL;
                bytes_sent_  = 0;
                total_bytes_ = 0;
            }

            /**
             * @brief Destructor.
             */
            virtual ~NGXOutgoingMessage ()
            {
                ReleaseWrappedChain(&head_chain_);
            }

        public: // method(s) / function(s)

            NGXOutgoingMessage* Encode    (const ngx::ws::WebsocketBufferChain* a_chain, uint8_t a_opcode);
            NGXOutgoingMessage* Reset     ();

        private: // method(s) / function(s)

            ngx_chain_t*     NewChain            (const u_char* a_data, size_t a_size);
            ngx_chain_t*     NewWrappedChain     (ngx_chain_t* a_header_chain, const unsigned char* a_header_data, size_t a_header_size,
                                                  const ngx::ws::WebsocketBufferChain* a_payload_chain);
            void             ReleaseWrappedChain (ngx_chain_t** a_chain);

        }; // end of class 'NGXOutgoingMessage'

        /**
         * @brief Encodes a websocket message for the provided payload data.
         *
         * @param a_chain  The \link ngx::ws::WebsocketBufferChain \link that contains a websocket message payload.
         * @param a_opcode One of \link ngx::ws::BaseFrame::Opcodes \link.
         *
         * @return
         */
        inline NGXOutgoingMessage* NGXOutgoingMessage::Encode (const ngx::ws::WebsocketBufferChain* a_chain, uint8_t a_opcode = 0x0)
        {
            // release previous content ( if any )
            Reset();
            // calculate payload size
            size_t                         payload_size = a_chain->fill_count_;
            ngx::ws::WebsocketBufferChain* chain_ptr    = a_chain->next_;
            while ( NULL != chain_ptr ) {
                payload_size += chain_ptr->fill_count_;
                chain_ptr     = chain_ptr->next_;
            }
            //
            size_t extended_payload_bytes;
            if ( 125 >= payload_size ) {
                extended_payload_bytes = 0;
            } else if ( 126 <= payload_size && 65535 >= payload_size ) {
                extended_payload_bytes = sizeof(unsigned char) * 2;
            } else {
                extended_payload_bytes = sizeof(unsigned char) * 8;
            }
            //
            const size_t opcode = 0x0 != a_opcode ? a_opcode : a_chain->binary_ ? (uint8_t)ngx::ws::BaseFrame::Opcodes::EBinary : (uint8_t)ngx::ws::BaseFrame::Opcodes::EText;
            // fin ( 1 bit ) + rsv's ( 3 bits ) + opcode ( 4 bits ) = 8 bits // 0x8F -> rsv1, rsv3, rsv3 - must be 0 unless an extension is negotiated
            header_buffer_[0] = ( ( 1 << 7 ) | ( opcode & 0xF ) ) & 0x8F;
            //
            if ( extended_payload_bytes == 0 ) {
                // mask ( 1 bit ) + payload len ( 7 bits  )     = 8 bits
                header_buffer_[1] = ( payload_size & 0x7F );
            } else if ( extended_payload_bytes == 2 ) {
                // mask ( 1 bit ) + 0x7F ( 7 bits  )            = 8 bits
                header_buffer_[1] = 0x7E;
                // extended payload len                         = 16 bits
                header_buffer_[2] = ( payload_size >> 8 ) & 0xFF;
                header_buffer_[3] = ( payload_size      ) & 0xFF;
            } else /* if ( extended_payload_bytes == 8 ) */ {
                // mask ( 1 bit ) +  0x7F ( 7 bits )            = 8 bits
                header_buffer_[1] = 0x7F;
                // current_frame_ payload len                   = 64 bits
                header_buffer_[2] = ( payload_size >> 56 ) & 0xFF;
                header_buffer_[3] = ( payload_size >> 48 ) & 0xFF;
                header_buffer_[4] = ( payload_size >> 40 ) & 0xFF;
                header_buffer_[5] = ( payload_size >> 32 ) & 0xFF;
                header_buffer_[6] = ( payload_size >> 24 ) & 0xFF;
                header_buffer_[7] = ( payload_size >> 16 ) & 0xFF;
                header_buffer_[8] = ( payload_size >>  8 ) & 0xFF;
                header_buffer_[9] = ( payload_size       ) & 0xFF;
            }
            // create new ngx chain for new data
            chain_ptr_ = NewWrappedChain(head_chain_, header_buffer_, (sizeof(unsigned char)*2) + extended_payload_bytes, a_chain);
            //
            return this;
        }

        /**
         * @brief Resets state machine and releases all data.
         */
        inline NGXOutgoingMessage* NGXOutgoingMessage::Reset ()
        {
            // delete current header_chain_
            ReleaseWrappedChain(&head_chain_->next);
            // reset control vars
            chain_ptr_   = NULL;
            bytes_sent_  = 0;
            total_bytes_ = 0;
            //
            return NULL;
        }

        /**
         * Allocates a new \link ngx_chain_t \link.
         *
         * @param a_data the data the chain buffer points to
         * @param a_size the data size
         *
         * @return a new \link ngx_chain_t \link with the buffers content pointing to the provided data.
         *
         * @note The buffer contents is not copied!
         */
        inline ngx_chain_t* NGXOutgoingMessage::NewChain (const u_char* a_data, size_t a_size)
        {
            // allocate response buffer
            ngx_buf_t* b = (ngx_buf_t*)malloc(sizeof(ngx_buf_t));
            if ( b == NULL ) {
                // out of memory
                return NULL;
            }
            // allocate response chain
            ngx_chain_t* c = (ngx_chain_t*)malloc(sizeof(ngx_chain_t));
            if ( c == NULL ) {
                //
                free(b);
                // out of memory
                return NULL;
            }
            // just keeping the same behavior as in ngx_pcalloc
            ngx_memzero(b, sizeof(ngx_buf_t));
            ngx_memzero(c, sizeof(ngx_chain_t));
            //
            b->start         = const_cast<u_char*>(a_data); // first position in memory of the data
            b->pos           = b->last = b->start;
            b->last         += a_size;                      // last position
            b->memory        = 1;                           // content is in read-only memory filters must copy to modify,
            b->last_buf      = 1;                           // there will be no more buffers in the request
            b->last_in_chain = 1;                           // last in chain
            //
            c->buf  = b;
            c->next = NULL;
            //
            return c;
        }

        /**
         * @brief Allocates a new \link ngx_chain_t \link based on provided data.
         *
         * @param a_header_chain  the preallocated header chain
         * @param a_header_data   the first chain buffer contents
         * @param a_header_size   the first chain buffer size
         * @param a_payload_chain the message payload chain
         *
         * @return a new \link ngx_chain_t \link with the buffers content pointing to the provided data.
         */
        inline ngx_chain_t* NGXOutgoingMessage::NewWrappedChain (ngx_chain_t* a_header_chain, const unsigned char* a_header_data, size_t a_header_size,
                                                                          const ngx::ws::WebsocketBufferChain* a_payload_chain)
        {
            // just keeping the same behavior as in ngx_pcalloc
            ngx_buf_t* buffer = a_header_chain->buf;
            ngx_memzero(a_header_chain->buf, sizeof(ngx_buf_t));
            ngx_memzero(a_header_chain, sizeof(ngx_chain_t));
            //
            a_header_chain->buf                = buffer;
            a_header_chain->buf->start         = const_cast<u_char*>(a_header_data);
            a_header_chain->buf->pos           = a_header_chain->buf->last = a_header_chain->buf->start;
            a_header_chain->buf->last         += a_header_size;
            a_header_chain->buf->memory        = 1;
            a_header_chain->buf->last_buf      = 0;
            a_header_chain->buf->last_in_chain = 0;
            //
            total_bytes_                        = a_header_size;
            //
            bool                           error         = false;
            ngx_chain_t*                   ngx_chain_ptr = a_header_chain;
            ngx::ws::WebsocketBufferChain* buffer_chain  = (ngx::ws::WebsocketBufferChain*)a_payload_chain;
            while ( NULL != buffer_chain ) {
                // try to allocate a new ngx chain
                ngx_chain_t* ngx_new_chain = NewChain((const u_char*)buffer_chain->data_, buffer_chain->fill_count_);
                if ( NULL == ngx_new_chain ) {
                    error = true;
                    break;
                }
                ngx_new_chain->buf->last_buf      = 0;
                ngx_new_chain->buf->last_in_chain = 0;
                // keep track of new allocated ngx chain
                ngx_chain_ptr->next = ngx_new_chain;
                ngx_chain_ptr       = ngx_new_chain;
                //
                total_bytes_       += buffer_chain->fill_count_;
                // next buffer chain...
                buffer_chain  = buffer_chain->next_;
            }
            // got an error?
            if ( true == error ) {
                // release previous allocated chain(s)
                ReleaseWrappedChain(&a_header_chain->next);
                //
                total_bytes_ = 0;
                //
                return NULL;
            }
            //
            ngx_chain_ptr->buf->last_buf      = 1;
            ngx_chain_ptr->buf->last_in_chain = 1;
            // we're good to go
            return a_header_chain;
        }

        /**
         * @brief Releases a previous allocated \link ngx_chain_t \link that MUST have been allocated
         *        with a call to \link NewWrappedChain \link
         *
         * @param a_chain the chain to be released
         */
        inline void NGXOutgoingMessage::ReleaseWrappedChain (ngx_chain_t** a_chain)
        {
            // nothing to release
            if ( NULL == (*a_chain) ) {
                return;
            }
            //
            ngx_chain_t* current = (*a_chain)->next;
            ngx_chain_t* next;
            while ( NULL != current ) {
                next = current->next;
                if ( NULL != current->buf ) {
                    free(current->buf);
                }
                free(current);
                current = next;
            }
            if ( NULL != (*a_chain)->buf ) {
                free((*a_chain)->buf);
            }
            free(*a_chain);
            (*a_chain) = NULL;
        }

#ifdef __APPLE__
#pragma mark -  NGXWriter Class
#endif

        /**
         * A class that implements an interface to send messages
         * using WebSockets protocol.
         */
        class NGXWriter : public ngx::ws::Context::Writer
        {

        public: // data

            NGXOutgoingMessage*             next_message_ptr_;     //!< pointer to the next message ( NULL if not or current_message_ if encoded )
            NGXOutgoingMessage*             cm_ptr_;               //!< pointer to the next control message ( NULL if not or current_message_ if encoded )

        private: // pointers

            ngx_http_request_t*              request_ptr_;          //!< a pointer to the request
            ngx_http_event_handler_pt        write_handler_ptr_;    //!< a pointer to the write handler

        private: // data

            NGXOutgoingMessage              data_message_;         //!< the ( encoded ) data message

        private: // data - pcm: ping control message

            NGXOutgoingMessage              cm_;                   //!< the ( encoded ) control message
            WebsocketBufferChain*           cm_bc_;                //!< the control message payload
            ngx_event_t*                    cm_event_;             //!< the control message event
            ngx_msec_t                      cm_period_ms_;         //!< the milliseconds of seconds between control messages

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            NGXWriter (ngx_http_request_t* a_request)
            {
                next_message_ptr_    = NULL;
                request_ptr_         = a_request;
                write_handler_ptr_   = NULL;
                // ping control message
                cm_ptr_              = NULL;
                cm_bc_               = NULL;
                cm_event_            = NULL;
                cm_period_ms_        = 0;
            }

            /**
             * @brief Destructor.
             */
            virtual ~NGXWriter ()
            {
                // can't delete pointers - not managed by this class
                next_message_ptr_    = NULL;
                cm_ptr_              = NULL;
                request_ptr_         = NULL;
                write_handler_ptr_   = NULL;
                //
                if ( NULL != cm_event_ ) {
                    CancelIdleEvent();
                    free(cm_event_);
                }
                //
                if ( cm_bc_ != NULL ) {
                    delete cm_bc_;
                }
            }

        public: // inherited virtual method(s) / function(s) - implemetation

            /**
             * @brief Send a websocket message.
             *
             * @param a_chain The buffer chain that contains the message payload.
             *
             * @return
             *         @li True on success
             *         @li False on failure
             */
            virtual bool SendMessage (const ngx::ws::WebsocketBufferChain* a_chain)
            {
                // check if we're busy
                if ( nullptr != next_message_ptr_ ) {
                    // message will be recalled and sent later on
                    return true;
                }
                // cancel idle event
                CancelIdleEvent();
                // reset pointers
                cm_ptr_ = NULL;
                // encode message
                next_message_ptr_ = data_message_.Encode(a_chain, a_chain->binary_ ? (uint8_t)ngx::ws::BaseFrame::Opcodes::EBinary : (uint8_t)ngx::ws::BaseFrame::Opcodes::EText);
                if ( NULL == next_message_ptr_) {
                    // could not encode this message
                    return false;
                }
                // ( try to ) write message
                (write_handler_ptr_)(request_ptr_);
                //
                return true;
            }

        public: // method(s) / function(s) - declaration

            void SetWriteHandler   (ngx_http_event_handler_pt a_handler);

            void SetIdleHandler    (ngx_event_handler_pt a_handler, ngx_int_t a_period);
            void ScheduleIdleEvent ();
            void CancelIdleEvent   ();

            void Ping              ();
            void Close             ();

        }; // end of class 'NGXWriter'

        /**
         * Set the write handler.
         *
         * @param a_handler The callback to call when it's time to write some bytes.
         *
         * @return
         *         @li True on success
         *         @li False on failure
         */
        inline void NGXWriter::SetWriteHandler (ngx_http_event_handler_pt a_handler)
        {
            // check for invalid params
            if ( NULL == a_handler ) {
                // we really need this handler
                throw NGXException("::NGXWriter::SetWriteHandler(%p) - invalid handler!",
                                   a_handler);
            }
            // keep track of this handler
            write_handler_ptr_ = a_handler;
        }

        /**
         * Set the idle handler.
         *
         * @param a_handler The callback to call when we've been in idle mode for too long.
         * @param a_period  The number of seconds between control messages.
         */
        inline void NGXWriter::SetIdleHandler (ngx_event_handler_pt a_handler, ngx_int_t a_period)
        {
            // check for invalid params
            if ( NULL == a_handler ) {
                // we really need this handler
                throw NGXException("::NGXWriter::SetIdleHandler(%p, %d) - invalid handler!",
                                   a_handler, a_period);
            }
            //
            cm_event_ = (ngx_event_t*)malloc(sizeof(ngx_event_t));
            if ( NULL == cm_event_ ) {
                // we refuse to work without this event
                throw NGXException("::NGXWriter::SetIdleHandler(%p, %d) - out of memory ( cm_event_ )!",
                                   a_handler, a_period);
            }
            // just keeping the same behavior as in ngx_pcalloc
            ngx_memzero(cm_event_, sizeof(ngx_event_t));
            //
            cm_event_->log     = request_ptr_->connection->log;
            cm_event_->data    = request_ptr_;
            cm_event_->handler = a_handler;
            //
            const char*  pldc    = "wsp";
            const size_t plds    = sizeof(char) * 3;
            //
            cm_bc_ = new (plds) ngx::ws::WebsocketBufferChain(plds);
            if ( NULL == cm_bc_ ) {
                // we refuse to work without this buffer
                throw NGXException("::NGXWriter::SetIdleHandler(%p, %d) - out of memory ( cm_bc_ )!",
                                   a_handler, a_period);
            }
            //
            cm_bc_->binary_     = false;
            cm_bc_->fill_count_ = plds;
            cm_bc_->next_       = NULL;
            memcpy(cm_bc_->data_, pldc, cm_bc_->fill_count_);
            //
            cm_period_ms_   = (ngx_msec_t)(a_period * 1000);
        }

        /**
         * @brief Schedule the idle event.
         */
        inline void NGXWriter::ScheduleIdleEvent ()
        {
            if ( 0 == cm_event_->timer_set ) {
                ngx_add_timer(cm_event_, cm_period_ms_);
            }
        }

        /**
         * @brief Cancel a previously scheduled idle event.
         */
        inline void NGXWriter::CancelIdleEvent ()
        {
            if ( 1 == cm_event_->timer_set ) {
                ngx_del_timer(cm_event_);
            }
        }

        /**
         * Send a 'ping' control message.
         */
        inline void NGXWriter::Ping ()
        {
            // check if we're busy
            if ( nullptr != next_message_ptr_ ) {
                // we're busy, this control message is sent when idle
                // reject this call
                return;
            }
            // encode message
            next_message_ptr_ = cm_ptr_ = cm_.Encode(cm_bc_, (uint8_t)ngx::ws::BaseFrame::Opcodes::EPing);
            if ( NULL == cm_ptr_) {
                // we refuse to work if we can't encode control messages
                throw NGXException("::NGXWriter::Ping - unable to encode ping message!");
            }
            // ( try to ) write message
            (write_handler_ptr_)(request_ptr_);
        }

        /**
         * Send a 'close' control message.
         */
        inline void NGXWriter::Close ()
        {
            // check if we're busy
            if ( nullptr != next_message_ptr_ ) {
                // we're busy, this control message is sent when idle
                // reject this call
                return;
            }
            // encode message
            next_message_ptr_ = cm_ptr_ = cm_.Encode(cm_bc_, (uint8_t)ngx::ws::BaseFrame::Opcodes::EClose);
            if ( NULL == cm_ptr_) {
                // we refuse to work if we can't encode control messages
                throw NGXException("::NGXWriter::Ping - unable to encode close message!");
            }
            // ( try to ) write message
            (write_handler_ptr_)(request_ptr_);
        }

        /**
         * A class that implements an interface to write HTTP content.
         */
        class NGXTimerEvent
        {

        public: // data types

            typedef void(*internal_handler_t)(void*, void*);
            typedef void* internal_handler_owner_t;
            typedef void* internal_handler_param_t;

            typedef struct _Data {
                ngx_http_request_t*      request_ptr_;                      //!< a pointer to the request
                internal_handler_t       internal_handler_ptr_;             //!<
                internal_handler_owner_t internal_handler_owner_ptr_;       //!<
                internal_handler_param_t internal_handler_param_ptr_;       //!<
            } Data;

        public: // data

            ngx_event_handler_pt handler_;                                  //!<
            ngx_msec_t           timeout_ms_;                               //!< the timeout in milliseconds
            ngx_event_t*         event_;                                    //!< timer event
            Data                 data_;                                     //!<

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             *
             * @param a_r
             * @param a_handler
             * @param a_timeout
             */
            NGXTimerEvent (ngx_http_request_t* a_r, ngx_event_handler_pt a_handler, ngx_msec_t a_timeout,
                           internal_handler_t a_internal_handler, internal_handler_owner_t a_internal_handler_owner)
            {
                handler_    = a_handler;
                timeout_ms_ = a_timeout;
                event_      = NULL;
                data_       = { a_r, a_internal_handler, a_internal_handler_owner, NULL };
            }

            /**
             * @brief Destructor.
             */
            virtual ~NGXTimerEvent ()
            {
                if ( NULL != event_ ) {
                    CancelEvent();
                    free(event_);
                }
            }

        public: // method(s) / function(s) - declararion

            void ScheduleEvent (ngx_msec_t a_timeout, internal_handler_param_t a_param);
            void CancelEvent   ();

        private: // method(s) / function(s) - declararion

            void EnsureEvent   (ngx_msec_t a_timeout, internal_handler_param_t a_param);

        };

        /**
         * @brief Schedule event.
         *
         * @param a_timeout
         */
        inline void NGXTimerEvent::ScheduleEvent (ngx_msec_t a_timeout, internal_handler_param_t a_param)
        {
            EnsureEvent(a_timeout, a_param);
            if ( 0 == event_->timer_set ) {
                ngx_add_timer(event_, timeout_ms_);
                event_->timer_set = 1;
            }
        }

        /**
         * @brief Cancel a previously scheduled event.
         */
        inline void NGXTimerEvent::CancelEvent ()
        {
            if ( NULL != event_ && event_->timer_set ) {
                ngx_del_timer(event_);
                event_->timer_set = 0;
            }
        }

        /**
         * @brief Ensure that an event is ready to use.
         *
         * @param a_timeout
         * @param a_handler
         */
        inline void NGXTimerEvent::EnsureEvent (ngx_msec_t a_timeout, internal_handler_param_t a_param)
        {
            CancelEvent();
            // can't reuse previous event?
            if ( (ngx_msec_t)a_timeout != timeout_ms_ ) {
                free(event_);
                event_ = NULL;
            }
            // new event?
            if ( NULL == event_ ) {
                // check for invalid params
                if ( NULL == handler_ ) {
                    // we really need this handler
                    throw NGXException("::NGXTimerEvent::EnsureEvent(%d) - invalid handler!",
                                       a_timeout);
                }
                // create event
                event_ = (ngx_event_t*)malloc(sizeof(ngx_event_t));
                if ( NULL == event_ ) {
                    // we refuse to work without this event
                    throw NGXException("::NGXTimerEvent::EnsureEvent(%d) - out of memory ( event_ )!",
                                       a_timeout);
                }
                // just keeping the same behavior as in ngx_pcalloc
                ngx_memzero(event_, sizeof(ngx_event_t));
                // set event info
                event_->log     = data_.request_ptr_->connection->log;
                event_->data    = &data_;
                event_->handler = handler_;
                // keep track if event params
                timeout_ms_                       = a_timeout;
                data_.internal_handler_param_ptr_ = a_param;
            } else {
                data_.internal_handler_param_ptr_ = a_param;
            }
        }

        /**
         * A class that implements an interface to a basic timer manager.
         */
        class NGXTimerManager : public ngx::ws::Context::TimerManager
        {

        protected: // data

            ngx_http_request_t*              request_ptr_;
            ngx_event_handler_pt             handler_ptr_;
            std::map<Event*, NGXTimerEvent*> in_use_;
            std::stack<NGXTimerEvent*>       stashed_;

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             *
             * @param a_request
             * @param a_handler
             */
            NGXTimerManager (ngx_http_request_t* a_request, ngx_event_handler_pt a_handler)
            {
                request_ptr_ = a_request;
                handler_ptr_ = a_handler;
            }

            /**
             * @brief Destructor.
             */
            virtual ~NGXTimerManager ()
            {
                request_ptr_ = NULL;
                handler_ptr_ = NULL;
                CancelAll();
                for ( auto e_it : in_use_ ) {
                    delete e_it.first;
                }
                in_use_.clear();
                while ( false == stashed_.empty() ) {
                    delete stashed_.top();
                    stashed_.pop();
                }
            }

        public: // inherited virtual method(s) / function(s) - implemetation

            /**
             * @brief Schedule a one shot event.
             *
             * @param a_timeout_ms
             * @param a_callback
             */
            virtual OneShotEvent* ScheduleOneShot (size_t a_timeout_ms, const std::function<void()> a_callback)
            {
                NGXTimerEvent* event;
                if ( true == stashed_.empty() ) {
                    event = new NGXTimerEvent(request_ptr_, handler_ptr_, static_cast<ngx_msec_t>(a_timeout_ms), NGXTimerManager::InternalHandler, (void*)this);
                    if ( NULL == event ) {
                        throw NGXException("::NGXTimerManager::ScheduleOneShot(...) - out of memory!");
                    }
                } else {
                    event = stashed_.top();
                    stashed_.pop();
                }
                OneShotEvent* one_shot_event = new OneShotEvent(a_timeout_ms, a_callback);
                if ( NULL == one_shot_event ) {
                    stashed_.push(event);
                    throw NGXException("::NGXTimerManager::ScheduleOneShot(...) - out of memory!");
                }
                in_use_[one_shot_event] = event;
                event->ScheduleEvent(static_cast<ngx_msec_t>(a_timeout_ms), one_shot_event);

                return one_shot_event;
            }

            /**
             * @brief Schedule a recurrent event.
             *
             * @param a_timeout_ms
             * @param a_callback
             */
            virtual RecurrentEvent* ScheduleRecurrent (size_t a_timeout_ms, const std::function<void()> a_callback)
            {
                NGXTimerEvent* event;
                if ( true == stashed_.empty() ) {
                    event = new NGXTimerEvent(request_ptr_, handler_ptr_, static_cast<ngx_msec_t>(a_timeout_ms), NGXTimerManager::InternalHandler, (void*)this);
                    if ( NULL == event ) {
                        throw NGXException("::NGXTimerManager::ScheduleRecurrent(...) - out of memory!");
                    }
                } else {
                    event = stashed_.top();
                    stashed_.pop();
                }
                RecurrentEvent* recurrent_event = new RecurrentEvent(a_timeout_ms, a_callback);
                if ( NULL == recurrent_event ) {
                    stashed_.push(event);
                    throw NGXException("::NGXTimerManager::ScheduleRecurrent(...) - out of memory!");
                }
                in_use_[recurrent_event] = event;
                event->ScheduleEvent(static_cast<ngx_msec_t>(a_timeout_ms), recurrent_event);

                return recurrent_event;
            }

            /**
             * @brief Cancel a previously registered event.
             *
             * @param a_event
             */
            virtual void Cancel (Event* a_event)
            {
                const auto it = in_use_.find(a_event);
                if ( in_use_.end() == it ) {
                    return;
                }
                delete it->first;

                it->second->CancelEvent();
                stashed_.push(it->second);
                in_use_.erase(it);
            }

            /**
             * @brief Cancel all in-use events.
             */
            virtual void CancelAll ()
            {
                for ( auto e_it : in_use_ ) {
                    e_it.second->CancelEvent();
                }
            }

        protected:

            /**
             * @brief 'C' style callback.
             *
             * @param a_event
             * @param a_self
             */
            static void InternalHandler (void* a_event, void* a_self)
            {
                if ( NULL == a_event || NULL == a_self ) {
                    throw NGXException("::NGXTimerManager::InternalHandler(...) - invalid arguments!");
                }

                NGXTimerManager* issuer = (NGXTimerManager*)a_self;
                Event*           event  = NULL;

                for ( auto it : issuer->in_use_ ) {
                    if ( it.second->event_ != a_event ) {
                        continue;
                    }
                    event = (OneShotEvent*) it.first;
                    break;
                }

                if ( NULL == event ) {
                    throw NGXException("::NGXTimerManager::InternalHandler(...) - event not found!");
                }

                const auto e_it = issuer->in_use_.find(event);

                NGXTimerEvent* ngx_event = e_it->second;

                if ( 1 == event->one_shot_ ) {
                    e_it->second->CancelEvent();
                    issuer->stashed_.push(ngx_event);
                    issuer->in_use_.erase(e_it);
                }

                event->callback_();

                if ( 1 == event->one_shot_ ) {
                    delete event;
                } else {
                    ngx_event->ScheduleEvent(static_cast<ngx_msec_t>(event->timeout_), event);
                }
            }

        };

#ifdef ___APPLE__
#pragma mark - NGXContext Class
#endif

        /**
         * @brief NGINX WebSocket context.
         */
        class NGXContext : public ngx::ws::Context
        {

        public: // data

            // rx
            ngx::ws::IncomingMessage*         rx_active_message_;
            ngx::ws::IncomingMessage          rx_control_message_;
            ngx::ws::IncomingMessage          rx_data_message_;
            // tx
            ngx::ws::OutgoingMessage*         tx_active_message_;
            ngx::ws::OutgoingMessage          tx_control_message_;
            ngx::ws::OutgoingMessage          tx_data_message_;

            time_t                            dm_timeout_;           //!< the maximum number of seconds without exchanging data messages
            time_t                            dm_last_exchanged_ts_; //!< the time stamp of the last exchanged data message

            bool                              error_;
            unsigned                          timer_callback_ : 1;

        public: // constructor / destructor

            NGXContext (ngx_module_t& a_module, ngx_http_request_t* a_http_request,
                        const std::map<std::string, std::string>& a_config,
                        ngx::ws::Context::Writer* a_writer,
                        ngx::ws::NGXTimerManager* a_timer_manager_issuer)
            : ngx::ws::Context(a_module, a_http_request,
                               a_config,
                               a_writer,
                               a_timer_manager_issuer)
            {
                rx_active_message_    = &rx_data_message_;
                tx_active_message_    = &tx_data_message_;
                dm_timeout_           = 0;
                dm_last_exchanged_ts_ = 0;
                error_                = false;
                timer_callback_       = 0;
            }

            virtual ~NGXContext ()
            {
                // nop
            }

        }; // end of class 'NGXContext'

    } // end of namespace 'ws'

} // end of namespace 'ngx'

#endif // NRS_NGX_HTTP_WEBSOCKET_MODULE_H_
