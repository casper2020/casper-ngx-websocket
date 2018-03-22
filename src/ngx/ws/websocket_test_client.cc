/**
 * @file websocket_test_client.cc
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

#include "ngx/ws/websocket_test_client.h"

#include <string>

#ifdef __APPLE__
#pragma mark - WebsocketTestClient
#endif

ngx::ws::WebsocketTestClient::WebsocketTestClient (ngx::ws::Context& a_context) : websocket_(a_context)
{
    //
    // EXTENDED PAYLOAD LENGTH
    //
    // 1 ) <= 125               ( no extended payload field             )
    // 2 ) >= 126 && <= 65535   ( + 2 bytes for extendend payload field )
    // 3 ) > 65535              ( + 8 bytes for extendend payload field )
    //

    // 1)
    //      1 byte -> 125 bytes ( payload only )
    for ( uint16_t i = 1 ; i <= 125 ; ++i ) {
        queue_.push(NewBufferChain(">", i));
    }

    // 2 )
    //    126 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOP<"));
    //  127 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQ<"));
    //  128 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQR<"));
    //  129 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRSTUVWXYZ,ABCDEFGHIJKLMNOPQRS<"));
    // 65535 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLM<", 4369));

    // 3)
    // 65550 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLM<", 4370));
    // 75600 bytes ( payload only )
    queue_.push(NewBufferChain(">ABCDEFGHIJKLMNOPQRSTUVWXYZ<", 2700));
}

/**
 * @brief Destructor.
 */
ngx::ws::WebsocketTestClient::~WebsocketTestClient ()
{
    while ( 0 < queue_.size() ) {
        delete queue_.front();
        queue_.pop();
    }
}

#ifdef __APPLE__
#pragma mark - Properties / Config
#endif

/**
 * @brief Called by the context to retrieve the protocol implemented by the client
 */
const char* ngx::ws::WebsocketTestClient::Protocol ()
{
    return "skunk-epaper";
}

/**
 * @brief Called by context to select message delivery API
 *
 * @return @li true if the clients supports chained buffer, context always calls #OnChainedMessage
 *         @li false if the clients needs data in contigous memory, context calls #OnBinaryMessage and/or #OnTextMessage
 */
bool ngx::ws::WebsocketTestClient::UseChains ()
{
    return false;
}

#ifdef __APPLE__
#pragma mark - Callbacks
#endif

/**
 * @brief Called by context when a new binary message is received
 *
 * @param a_ws_context pointer to the context that received the message
 * @param a_data pointer to the message payload
 * @param a_size size of the messsage payload
 *
 * @note  The message memory is released by the context after this method returns
 */
void ngx::ws::WebsocketTestClient::OnBinaryMessage (const ngx::ws::Context* a_ws_context, const void* a_data, size_t a_size)
{
    (void)a_ws_context;
}

/**
 * @brief Called by context when a new text message is received
 *
 * @param a_ws_context pointer to the context that received the message
 * @param a_data pointer to the message text payload
 * @param a_size size of the messsage payload
 *
 * @note  The message memory is released by the context after this method returns
 */
void ngx::ws::WebsocketTestClient::OnTextMessage (const ngx::ws::Context* a_ws_context, const char* a_data, size_t a_size)
{
    (void)a_ws_context;
}

/**
 * @brief Called by context when a chained message is received
 *
 * @param a_ws_context pointer to the context that received the message
 * @param a_chain pointer to the message text payload
 *
 * @note  The message memory is released by the context after this method returns
 */
void ngx::ws::WebsocketTestClient::OnChainedMessage (const ngx::ws::Context* a_ws_context, const ngx::ws::WebsocketBufferChain* a_chain)
{
    (void)a_ws_context;
}

/**
 * @brief Called by the context to pull the next queued message
 *
 * @param a_ws_context pointer to the context that transmitted the message
 *
 * @return @li pointer to next message to transmit
 *         @li NULL there are no more messages to send, context should idle the transmitter
 */
const ngx::ws::WebsocketBufferChain* ngx::ws::WebsocketTestClient::OnMessageSent (const ngx::ws::Context* a_ws_context)
{
    (void)a_ws_context;
    if ( queue_.size() == 0 ) {
        return NULL;
    }

    delete queue_.front();
    queue_.pop();

    if ( queue_.size() > 0 ) {
        return queue_.front();
    } else {
        return NULL;
    }
}

/**
 * @brief Called by context to inform the client that the websocket connection was terminated
 *
 * @param a_ws_context pointer to the context that was terminated
 */
void ngx::ws::WebsocketTestClient::OnConnectionClosed (const ngx::ws::Context* a_ws_context)
{
    (void)a_ws_context;
}

/**
 * @brief This method will be called when an exception was caught.
 *
 * @param a_error
 */
void ngx::ws::WebsocketTestClient::OnExceptionCaught (const ngx::ws::Context* a_ws_context, const std::exception& a_exception)
{
    (void)a_ws_context;
    (void)a_exception;
}

/**
 * @brief This method will be called when an error was caught.
 *
 * @param a_error
 */
void ngx::ws::WebsocketTestClient::OnErrorCaught (const ::ngx::ws::Context* a_ws_context, const std::runtime_error& a_error)
{
    (void)a_ws_context;
    (void)a_error;
}

#ifdef __APPLE__
#pragma mark - POST API's
#endif

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
void ngx::ws::WebsocketTestClient::PostBinaryMessage (const void* a_data, size_t a_size)
{
    ngx::ws::WebsocketBufferChain* msg = new (a_size) ngx::ws::WebsocketBufferChain(a_size);

    msg->binary_     = false;
    msg->fill_count_ = a_size;
    memcpy(msg->data_, a_data, a_size);
    queue_.push(msg);

    websocket_.SendMessage(msg);
}

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
void ngx::ws::WebsocketTestClient::PostTextMessage (const void* a_data, size_t a_size)
{
    ngx::ws::WebsocketBufferChain* msg = new (a_size) ngx::ws::WebsocketBufferChain(a_size);

    msg->binary_     = false;
    msg->fill_count_ = a_size;
    memcpy(msg->data_, a_data, a_size);
    queue_.push(msg);

    websocket_.SendMessage(msg);
}

/**
 * @brief Client calls this internal method to send a binary message
 *
 * Queueing logic will eventually call the context's #SendChainedMessage
 *
 * @param a_chain Buffer chain to transmit
 *
 * @note The client is responsible for managing the message memory lifecycle
 */
void ngx::ws::WebsocketTestClient::PostChainedMessage (ngx::ws::WebsocketBufferChain* a_chain)
{
    queue_.push(a_chain);
    websocket_.SendMessage(a_chain);
}

/**
 * @brief Send the first message at the queue ( all other will be send one by one when #OnMessageSent is called ).
 */
void ngx::ws::WebsocketTestClient::Send ()
{
    if ( 0 < queue_.size() ) {
        websocket_.SendMessage(queue_.front());
    }
}

#ifdef __APPLE__
#pragma mark -
#endif

/**
 * @brief Create a new buffer chain for the provided data.
 *
 * @param a_data The data to be placed @ chain.
 *
 * @return The first link to the created buffer chain.
 */
ngx::ws::WebsocketBufferChain* ngx::ws::WebsocketTestClient::NewBufferChain (const std::string& a_data)
{
    ngx::ws::WebsocketBufferChain* chain = new (a_data.length()) ngx::ws::WebsocketBufferChain(a_data.length());
    if ( NULL != chain ) {
        chain->binary_     = false;
        chain->fill_count_ = a_data.length();
        chain->next_       = NULL;
        memcpy(chain->data_, a_data.c_str(), chain->fill_count_);
    }
    return chain;
}
/**
 * @brief Create a new buffer chain for the provided data.
 *
 * @param a_data        The data to be placed @ chain.
 * @param a_multipler   The number of times the data will be copied in to chains.
 *
 * @return The first link to the created buffer chain.
 */
ngx::ws::WebsocketBufferChain* ngx::ws::WebsocketTestClient::NewBufferChain (const std::string& a_data, uint16_t a_multiplier)
{
    //
    ngx::ws::WebsocketBufferChain* first_chain = new (a_data.length()) ngx::ws::WebsocketBufferChain(a_data.length());

    first_chain->binary_     = false;
    first_chain->fill_count_ = a_data.length();
    first_chain->next_       = NULL;
    //
    memcpy(first_chain->data_, a_data.c_str(), first_chain->fill_count_);
    //
    ngx::ws::WebsocketBufferChain* previous_buffer_chain = first_chain;
    for ( size_t i = 1 ; i < a_multiplier ; ++i ) {
        ngx::ws::WebsocketBufferChain* new_chain = new (a_data.length()) ngx::ws::WebsocketBufferChain(a_data.length());
        //
        new_chain->binary_           = false;
        new_chain->fill_count_       = new_chain->fill_count_;
        new_chain->next_             = NULL;
        //
        memcpy(new_chain->data_, a_data.c_str(), new_chain->fill_count_);
        //
        previous_buffer_chain->next_ = new_chain;
        previous_buffer_chain        = new_chain;
    }
    previous_buffer_chain->next_ = NULL;

    //
    return first_chain;
}

#ifdef NGX_HTTP_WEBSOCKET_MODULE_SOCKET_USE_TEST_CLIENT

/**
 * @brief Create a client handler for the specified protocol
 *
 * @param a_ws_context pointer to the context that received the connection
 * @param a_config
 * @param a_resources_path.
 *
 * @return New instance of the client or NULL if the request can't not be honoured
 */
ngx::ws::AbstractWebsocketClient* ngx::ws::AbstractWebsocketClient::Factory (ngx::ws::Context* a_ws_context,
                                                                             const std::map<std::string, std::string>& a_config, const std::string& a_resources_path)
{
    return new ngx::ws::WebsocketTestClient(*a_ws_context);
}

#endif
