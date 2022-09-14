/**
 * @file websocket_protocol.h
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
#ifndef NRS_NGX_WEBSOCKET_PROTOCOL_H_
#define NRS_NGX_WEBSOCKET_PROTOCOL_H_

// c
extern "C" {
    #include <sys/types.h> // ssize_t // etc
    #include <stdint.h>    // uint8_t // uint32_t // etc
    #include <string.h>    // NULL    // etc
}
// c++ - std lib
#include <string>
#include <map>
#include <sstream>
#include <algorithm> // std::max, std::min

#ifndef NGX_WS_UNUSED_PARAM
#define NGX_WS_UNUSED_PARAM(x) (void)x			//!< This macro can be used to remove the warning about unused function/method parameters
#endif

#ifndef NGX_WS_DO_PRAGMA
#define NGX_WS_DO_PRAGMA(x) _Pragma (#x)
#endif

#ifndef NGX_WS_TODO
#define NGX_WS_TODO(x) NGX_WS_DO_PRAGMA(message ("WARNING: TODO - " #x))
#endif

namespace ngx
{

    namespace ws
    {

#ifdef __APPLE__
#pragma mark -
#pragma mark - Buffer
#endif

        /**
         * A class that contains the buffer memory and properties.
         */
        class Buffer {

        private: // data

            unsigned char* data_;           //!< the buffer data
            size_t         length_;         //!< the buffer length
            size_t         fill_count_;     //!< the buffer fill count

        public: // constructor(s) / destructor

            /**
             * Default constructor.
             */
            Buffer ()
            {
                data_       = NULL;
                length_     = 0;
                fill_count_ = 0;
            }

            /**
             * Constructor with allocation.
             */
            Buffer (size_t a_length)
            {
                data_       = 0 < a_length ? new unsigned char[a_length] : NULL;
                length_     = NULL != data_ ? a_length : 0;
                fill_count_ = 0;
            }


            /**
             * Destructor.
             */
            virtual ~Buffer ()
            {
                if ( NULL != data_ ) {
                    delete [] data_;
                }
            }

        public: // inline method(s) / function(s) - declaration

            unsigned char*       Alloc             (size_t a_length);
            void                 Release           ();

            unsigned char*       Data              ();
            void                 IncreaseFillCount (size_t a_amount);
            void                 ZeroOut           ();

            const unsigned char* Data              (size_t& o_length) const;
            size_t               Length            ()                 const;
            size_t               FillCount         ()                 const;

        };

        /**
         * @brief Allocate the buffer data, previous one will be release ( if any ).
         *
         * @param a_length the new data length
         *
         * @return
         *          The pointer to the buffer data;
         */
        inline unsigned char* Buffer::Alloc (size_t a_length)
        {
            // length changed?
            if ( a_length == length_ ) {
                // no
                return data_;
            }
            // release previous data
            if ( NULL != data_ ) {
                delete [] data_;
            }
            // allocate new data
            data_       = 0 < a_length ? new unsigned char[a_length] : NULL;
            length_     = NULL != data_ ? a_length : 0;
            fill_count_ = 0;
            //
            return data_;
        }

        /**
         * @brief Release the current allocated buffer data ( if any ).
         */
        inline void Buffer::Release ()
        {
            if ( NULL != data_ ) {
                delete [] data_;
                data_   = NULL;
            }
            length_     = 0;
            fill_count_ = 0;
        }

        /**
         * @brief Unrestricted access to buffer data;
         */
        inline unsigned char* Buffer::Data ()
        {
            return data_;
        }

        /**
         * @brief Increase the buffer fill count.
         */
        inline void Buffer::IncreaseFillCount (size_t a_amount)
        {
            if ( NULL != data_ ) {
                fill_count_ += a_amount;
            }
        }

        inline void Buffer::ZeroOut ()
        {
            if ( NULL != data_ ) {
                memset(data_, 0, length_);
            }
        }

        /**
         * Easy access to the buffer data and it's length.
         *
         * @param o_length the buffer length
         *
         * @return The pointer to the buffer data;
         */
        inline const unsigned char* Buffer::Data (size_t& o_length) const
        {
            o_length = length_;
            return data_;
        }

        /**
         * @return The buffer length.
         */
        inline size_t Buffer::Length () const
        {
            return length_;
        }

        /**
         * @return The buffer fill count.
         */
        inline size_t Buffer::FillCount () const
        {
            return fill_count_;
        }

#ifdef __APPLE__
#pragma mark -
#pragma mark - BaseFrame
#endif

        /**
         * @brief A class that describes a base frame.
         *
         * RFC 6455 - Section 5.2 - Base Framing Protocol
         */
        class BaseFrame {

        public: // enum(s)

            /**
             * @brief RFC 6455 - Section 5.5 - Control Frames:
             *
             * Data Frames:
             *
             *        - identified by opcodes where the most significant bit of the opcode is 0
             *        - 0x3-0x7 are reserved for further non-control frames yet to be defined
             *
             * Control Frames:
             *
             *        - identified by opcodes where the most significant bit of the opcode is 1
             *        - 0xB-0xF are reserved for further control frames yet to be defined
             */
            enum class Opcodes : uint8_t {
                // invalid
                EInvalid = 0xFF,
                // fragmented related
                EContinuation = 0x0,
                // data frames
                EText   = 0x1,
                EBinary = 0x2,
                // control frames
                EClose  = 0x8,
                EPing   = 0x9,
                EPong   = 0xA
            };

            /**
             * @brief RFC 6455 - Section 7.4.1. - Defined Status Codes:
             */
            enum class StatusCodes : uint32_t {
                ENormal                     = 1000, //!< the purpose for which the connection was established has been fulfilled
                EGoingAway                  = 1001, //!< a server going down or a browser having navigated away from a page
                EProtocolError              = 1002, //!< an endpoint is terminating the connection due to a protocol error
                EInvalidDataType            = 1003, //!< has received a type of data it cannot accept
                EInconsistenteData          = 1007, //!< has received data within a message that was not consistent with the type of the message
                EPolicyViolation            = 1008, //!< received a message that violates its policy
                EMessageTooBig              = 1009, //!< has received a message that is too big for it to process
                EExtensionNegotiationFailed = 1010, //!< failed to negotiate one or more extension with server ( not used by server )
            };

            /**
             * @brief RFC 6455 - Section 7.4.2. - Reserved Status Code Ranges:
             */
            enum class ReservedStatusCodes : uint32_t {
                EUnusedStart   = 0,
                EUnusedEnd     = 999,
                EReservedStart = 1000,
                EReservedEnd   = 4999,
            };

        public: // protocol data

            uint8_t        fin_  : 1;           //!< Indicates that this is the final fragment in a message
            uint8_t        opcode_;             //!< defines the interpretation of the "Payload data", one of \link Opcodes \link
            uint8_t        mask_ : 1;           //!< defines whether the "Payload data" is masked
            int32_t        masking_key_;        //!< 32-bit value that defined the mask when \link mask_ \link bit is set

        public: // internal data

            bool           fragmented_;         //!< internal variable to mark this message as fragmented or not

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            BaseFrame ()
            {
                fin_                     = 0;
                opcode_                  = (uint8_t)Opcodes::EInvalid;
                mask_                    = 0;
                masking_key_             = 0;
                fragmented_              = false;
            }

            /**
             * @brief Destructor
             */
            virtual ~BaseFrame ()
            {
                // nop
            }

        public: // virtual method(s) / function(s) - declaration

            /**
             * @brief Called to release this frame allocated data and links ( if needed ) and reset all propertis.
             */
            virtual void Reset ()
            {
                fin_         = 0;
                opcode_      = (uint8_t)Opcodes::EInvalid;
                mask_        = 0;
                masking_key_ = 0;
                fragmented_  = false;
            }

        public: // static method(s) / function(s(

            static bool    PeekOpcode        (const unsigned char* a_data, ssize_t a_data_len, bool a_frame_continuation, uint8_t& o_opcode);
            static bool    IsControlOpcode   (uint8_t a_opcode);

        };

        /**
         * @brief Call to check what kind of message will be processed next.
         *
         * @param a_data                The begining of the next message frame.
         * @param a_data_len            The total length of the next message frame.
         * @param a_frame_continuation  True if we're expecting a frame continuation, false otherwise.
         * @param o_opcode              The read opcode value of the next message frame, \link Opcodes::EInvalid \link if not enough data to read.
         *
         * @return
         *          @li True on success
         *          @li False on failure.
         */
        inline bool BaseFrame::PeekOpcode (const unsigned char* a_data, ssize_t a_data_len, bool a_frame_continuation, uint8_t& o_opcode)
        {
            if ( a_data_len > 0 ) {
                o_opcode = ( a_data[0] & 0xF  );
            } else {
                o_opcode = (uint8_t)Opcodes::EInvalid;
            }
            if ( true == a_frame_continuation ) {
                return ( (uint8_t)Opcodes::EContinuation == o_opcode );
            } else {
                return ( (uint8_t)Opcodes::EInvalid != o_opcode );
            }
        }

        /**
         * @brief Call to check if an opcode belongs to a control frame.
         *
         * @param a_opcode The opcode to check.
         *
         * @return
         *          @li True if it's a control opcode
         *          @li False if it's NOT control opcode
         */
        inline bool BaseFrame::IsControlOpcode (uint8_t a_opcode)
        {
            // 0xB-0xF are reserved for further control frames yet to be defined
            return 0x8 <= a_opcode && 0xF >= a_opcode;
        }

#ifdef __APPLE__
#pragma mark -
#pragma mark - IncomingFrame
#endif

        /**
         * @brief A class that describes and decodes an incoming frame.
         */
        class IncomingFrame : public BaseFrame {

        protected: // data types

            typedef struct header_s {

                unsigned char data_ [14];       //!< the buffer data
                size_t        length_;          //!< the buffer length
                size_t        fill_count_;      //!< the buffer fill count

            } header_t;

        public: // data

            IncomingFrame* next_;             //!< the next related frame
            header_t       header_buffer_ ;   //!< the 'header' buffer
            Buffer         payload_buffer_;   //!< the payload buffer

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            IncomingFrame ()
            {
                header_buffer_.length_     = 14;
                header_buffer_.fill_count_ = 0;
                memset(header_buffer_.data_, 0, header_buffer_.length_);
                //
                next_                    = NULL;
            }

            /**
             * @brief Destructor.
             */
            virtual ~IncomingFrame ()
            {
                if ( NULL != next_ ) {
                    delete next_;
                    next_ = NULL;
                }
            }

        public: //

            virtual void Reset ()
            {
                BaseFrame::Reset();
                //
                header_buffer_.fill_count_ = 0;
                memset(header_buffer_.data_, 0, header_buffer_.length_);
                //
                payload_buffer_.Release();
                //
                if ( NULL != next_ ) {
                    delete next_;
                    next_ = NULL;
                }
            }

        };

#ifdef __APPLE__
#pragma mark -
#pragma mark - OutgoingFrame
#endif

        /**
         * @brief A class that describes and encodes an outgoing frame.
         */
        class OutgoingFrame : public BaseFrame {

        public: // data

            Buffer buffer_; //!< the buffer that will contain the encoded frame

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            OutgoingFrame ()
            {

            }

            /**
             * @brief Destructor.
             */
            virtual ~OutgoingFrame ()
            {
                // nop
            }

        public:

            virtual void Reset ()
            {
                BaseFrame::Reset();
                //
                buffer_.Release();
            }

        };

#ifdef __APPLE__
#pragma mark -
#pragma mark - BaseMessage
#endif

        /**
         * @brief A class that describes a base message.
         */
        class BaseMessage {

        protected: // data

            bool in_use_;

        private: // data

            BaseFrame* base_frame_ptr_;

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            BaseMessage (BaseFrame* a_frame)
            {
                in_use_         = false;
                base_frame_ptr_ = a_frame;
            }

            /**
             * @brief Destructor.
             */
            virtual ~BaseMessage ()
            {
                base_frame_ptr_ = NULL;
            }

        public: // method(s) / functions

            bool    IsInUse () const;
            uint8_t Opcode  () const;

        };

        /**
         * @brief Check if this message is in use.
         *
         * @return
         *         @li True if the the message is in use
         *         @li False if the the message is NOT in use
         */
        inline bool BaseMessage::IsInUse () const
        {
            return in_use_;
        }

        /**
         * @brief Allow read-only access to the frame buffer.
         */
        inline uint8_t BaseMessage::Opcode () const
        {
            return base_frame_ptr_->opcode_;
        }

#ifdef __APPLE__
#pragma mark -
#pragma mark - IncomingMessage
#endif

        /**
         * @brief A class that describes and decodes an incoming message.
         */
        class IncomingMessage : public BaseMessage {

        private: // data

            IncomingFrame   main_frame_;
            IncomingFrame*  current_frame_;
            //
            Buffer          unchained_payload_buffer_;

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            IncomingMessage () : BaseMessage(&main_frame_)
            {
                current_frame_ = &main_frame_;
            }

            /**
             * @brief Destructor.
             */
            virtual ~IncomingMessage ()
            {
                // just a ptr to main_frame_ or one of it's links
                // it / they will be deleted when main_frame_
                // destructor is called
                current_frame_ = NULL;
            }

        protected: // method(s) / function(s) - declaration

            bool Decode (const unsigned char* a_data, ssize_t a_data_len, size_t& o_decoded_len, bool& o_complete, bool& o_fragmented);

        public: // method(s) / function(s)

            bool IsCurrentFrameComplete   () const;
            bool IsCurrentFrameFragmented () const;
            bool IsFragmented             () const;
            bool IsComplete               () const;

        public: // read only function(s) - declaration

            const unsigned char* PayloadData (size_t& a_length) const;

        public: //

            const unsigned char* UnchainPayload (size_t& o_length);
            void                 Reset          (bool a_keep_unchained_payload);

        public: // static method(s) / function(s) - decoding - declaration

            static ssize_t Decode (IncomingMessage& o_message , const unsigned char* a_data , ssize_t a_length , bool& o_complete, bool& o_fragmented, size_t& o_decoded_bytes);

        };

        /**
         * @brief Decodes a message: RFC 6455 - Section 5.2 - Base Framing Protocol.
         *
         * @param a_data       The data to be decoded.
         * @param a_data_len   The data length.
         * @param o_complete   Will be set to True if a message is now completely decoded, false otherwise.
         * @param o_fragmented Will be set to True if a message is or will be fragmented, false otherwise.
         *
         * @return
         *          @li True on success
         *          @li False on failure.
         */
        inline bool IncomingMessage::Decode (const unsigned char* a_data, ssize_t a_data_len, size_t& o_decoded_len, bool& o_complete, bool& o_fragmented)
        {
            //
            in_use_ = true;
            //
            const size_t         bytes_missing = current_frame_->payload_buffer_.Length() - current_frame_->payload_buffer_.FillCount();
            const unsigned char* payload_data_ptr;
            //
            uint64_t             available_payload_len = 0;
            // new message // new frame ?
            if ( 0 == bytes_missing ) {

                size_t  min_required_bytes = 2;
                size_t  rx_required_bytes  = 0;
                ssize_t remaining_bytes    = a_data_len;

                o_decoded_len = 0;
                o_complete    = false;
                //
                // detect fragmentation
                //
                const bool new_frame = current_frame_->payload_buffer_.Length() > 0 &&
                ( current_frame_->payload_buffer_.FillCount() == current_frame_->payload_buffer_.Length() );
                if ( true == new_frame  ) {
                    current_frame_->next_ = new IncomingFrame();
                    if ( NULL ==  current_frame_->next_ ) {
                        // out of memory, can't allocate a new frame
                        return false;
                    }
                    current_frame_ = current_frame_->next_;
                }
                //
                // 16 bits is the minumum required to decode a frame 'header'
                //
                if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                    // ...collect bytes...
                    size_t max_bytes_to_read = static_cast<size_t>(std::max<ssize_t>(std::min<ssize_t>(remaining_bytes, 2), 0));
                    for ( size_t i = 0; i < max_bytes_to_read ; ++ i ) {
                        current_frame_->header_buffer_.data_[current_frame_->header_buffer_.fill_count_++] = a_data[i];
                        o_decoded_len++;
                        rx_required_bytes++;
                    }
                    remaining_bytes -= max_bytes_to_read;
                    // still need more bytes?
                    if ( 2 > current_frame_->header_buffer_.fill_count_ ) {
                        // ...yes... keep collecting...
                        return true;
                    }
                }
                //
                current_frame_->fin_        = ( current_frame_->header_buffer_.data_[0] & 0x80 ) >> 7;
                current_frame_->opcode_     = ( current_frame_->header_buffer_.data_[0] & 0xF  );
                current_frame_->mask_       = ( current_frame_->header_buffer_.data_[1] & 0x80 ) >> 7;
                current_frame_->fragmented_ = (
                                               ( 0 == current_frame_->fin_ && (uint8_t)BaseFrame::Opcodes::EContinuation != current_frame_->opcode_ )
                                                ||
                                               ( 0 == current_frame_->fin_ && (uint8_t)BaseFrame::Opcodes::EContinuation == current_frame_->opcode_ )
                                              );

                // ... if it's a unknown or reserved opcode ...
                switch ((BaseFrame::Opcodes)current_frame_->opcode_) {
                    case BaseFrame::Opcodes::EText:
                    case BaseFrame::Opcodes::EBinary:
                    case BaseFrame::Opcodes::EClose:
                    case BaseFrame::Opcodes::EPing:
                    case BaseFrame::Opcodes::EPong:
                    case BaseFrame::Opcodes::EContinuation:
                        break;
                    default:
                        // ... caller must handle with this error ...
                        return false;
                }

                // mark as fragmented or not
                o_fragmented = current_frame_->fragmented_;
                // depending on payload_length, we might need 16 or 64 more bits to decode a frame 'header'
                const uint8_t payload_length = ( current_frame_->header_buffer_.data_[1] & 0x7F );
                if ( 0x7E /* = 126 decimal */ == payload_length ) {
                    // still need more 16 bits
                    min_required_bytes += 2;
                    // collect them
                    if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                        // ...collect bytes...
                        size_t start_byte        = rx_required_bytes;
                        size_t max_bytes_to_read = static_cast<size_t>(std::max<ssize_t>(std::min<ssize_t>(remaining_bytes, 2), 0));
                        for ( size_t i = 0; i < max_bytes_to_read ; ++ i ) {
                            current_frame_->header_buffer_.data_[current_frame_->header_buffer_.fill_count_++] = a_data[start_byte + i];
                            o_decoded_len++;
                            rx_required_bytes++;
                        }
                        remaining_bytes -= max_bytes_to_read;
                        // still need more bytes?
                        if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                            // ...yes... keep collecting...
                            return true;
                        }
                    }
                } else if ( 0x7F /* = 127 decimal */ == payload_length ) {
                    // still need more 64 bits
                    min_required_bytes += 8;
                    // collect them
                    if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                        // ...collect bytes...
                        size_t start_byte        = rx_required_bytes;
                        size_t max_bytes_to_read = static_cast<size_t>(std::max<ssize_t>(std::min<ssize_t>(remaining_bytes, 8), 0));
                        for ( size_t i = 0; i < max_bytes_to_read ; ++ i ) {
                            current_frame_->header_buffer_.data_[current_frame_->header_buffer_.fill_count_++] = a_data[start_byte + i];
                            o_decoded_len++;
                            rx_required_bytes++;
                        }
                        remaining_bytes -= max_bytes_to_read;
                        // still need more bytes?
                        if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                            // ...yes... keep collecting...
                            return true;
                        }
                    } else { // still need more bytes
                        // ...yes... keep collecting...
                        return true;
                    }
                } // else { // we're good to go! }
                //
                // depending on mask, we might need 32 bits more to decode the frame 'payload'
                //
                if ( 1 == current_frame_->mask_ ) {
                    // still need more 32 bits
                    min_required_bytes += 4;
                    // collect them
                    if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                        // ...collect bytes...
                        size_t start_byte        = rx_required_bytes;
                        size_t max_bytes_to_read = static_cast<size_t>(std::max<ssize_t>(std::min<ssize_t>(remaining_bytes, 4), 0));
                        for ( size_t i = 0; i < max_bytes_to_read ; ++ i ) {
                            current_frame_->header_buffer_.data_[current_frame_->header_buffer_.fill_count_++] = a_data[start_byte + i];
                            o_decoded_len++;
                            rx_required_bytes++;
                        }
                        remaining_bytes -= max_bytes_to_read;
                        // still need more bytes?
                        if ( min_required_bytes > current_frame_->header_buffer_.fill_count_ ) {
                            // ...yes... keep collecting...
                            return true;
                        }
                    }
                }
                //
                // insanity check point
                //
                if ( current_frame_->header_buffer_.fill_count_ < min_required_bytes || 0 > remaining_bytes ) {
                    // sanity check failed
                    o_complete    = false;
                    o_decoded_len = rx_required_bytes;
                    // ...oops...
                    return false;
                }
                // adjust the number of decoded bytes
                o_decoded_len = rx_required_bytes;
                //
                // decode real payload length
                //
                uint64_t real_payload_length;
                if ( 0x7E /* = 126 decimal */ == payload_length ) {
                    // following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
                    real_payload_length = static_cast<uint64_t>(current_frame_->header_buffer_.data_[2] << 8 | current_frame_->header_buffer_.data_[3]);
                } else if ( 0x7F /* = 127 decimal */ == payload_length ) {
                    // following 8 bytes interpreted as a 64-bit unsigned integer are the payload length
                    real_payload_length = (uint64_t)current_frame_->header_buffer_.data_[2] << 56 |
                    (uint64_t)current_frame_->header_buffer_.data_[3] << 48 |
                    (uint64_t)current_frame_->header_buffer_.data_[4] << 40 |
                    (uint64_t)current_frame_->header_buffer_.data_[5] << 32 |
                    (uint32_t)current_frame_->header_buffer_.data_[6] << 24 |
                    (uint32_t)current_frame_->header_buffer_.data_[7] << 16 |
                    (uint32_t)current_frame_->header_buffer_.data_[8] << 8  |
                    (uint32_t)current_frame_->header_buffer_.data_[9];
                } else {
                    // already read
                    real_payload_length = (uint64_t)payload_length;
                }
                //
                // allocate new payload buffer
                //
                try {
                    current_frame_->payload_buffer_.Alloc(real_payload_length);
                } catch (...) {
                    // ... caller must handle with this error ...
                    return false;
                }
                //
                // extract masking key
                //
                if ( 1 == current_frame_->mask_ ) {
                    //
                    const unsigned char* data_star_ptr = current_frame_->header_buffer_.data_ + ( min_required_bytes - sizeof(int32_t) );
                    //
                    current_frame_->masking_key_          = data_star_ptr[0] | data_star_ptr[1] << 8 | data_star_ptr[2] << 16 | data_star_ptr[3] << 24;
                } else {
                    current_frame_->masking_key_          = 0;
                }
                //
                // adjust payload : size and data pointer
                //
                if ( 0 >= remaining_bytes ) {
                    payload_data_ptr      = NULL;
                    available_payload_len = 0;
                } else {
                    payload_data_ptr      = a_data + ( a_data_len - remaining_bytes ) ;
                    available_payload_len = std::min<size_t>((uint64_t)remaining_bytes, real_payload_length);
                }
                //
                if ( NULL == payload_data_ptr || 0 == remaining_bytes ) {
                    // it's complete if...
                    o_complete  = IsComplete();
                    // ... but if not, we're ready to receive the missing payload bytes...
                    return true;
                }
            } else {
                // no, it's the remaining payload
                payload_data_ptr      = a_data;
                available_payload_len = static_cast<uint64_t>(std::min<ssize_t>((ssize_t)bytes_missing, a_data_len));
                o_decoded_len         = 0;
            }
            //
            // insanity check point
            //
            if ( 0 == current_frame_->payload_buffer_.Length() ) { // out of memory or unable to decode 'header'
                // out of memory
                o_complete = IsComplete();
                //
                return o_complete;
            }
            //
            // ( unmask and ) copy data
            //
            const uint64_t start_byte = current_frame_->payload_buffer_.FillCount();
            unsigned char* data_ptr   = current_frame_->payload_buffer_.Data() + start_byte;
            if ( 1 == current_frame_->mask_ ) {
                for ( uint64_t i = 0 ; i < available_payload_len ; ++i ) {
                    data_ptr[i] = payload_data_ptr[i] ^ ( ( current_frame_->masking_key_ >> ( 8 * ( ( i + start_byte ) % 4 ) )  ) & 0xFF );
                }
            } else {
                for ( uint64_t i = 0 ; i < available_payload_len ; ++i ) {
                    data_ptr[i] = payload_data_ptr[i];
                }
            }
            current_frame_->payload_buffer_.IncreaseFillCount(available_payload_len);
            //
            o_decoded_len += available_payload_len;
            o_complete     = IsComplete();
            // we're done
            return true;
        }

        /**
         * @brief Check if the message current frame is complete or not.
         *
         * @return
         *          @li True if the current frame is complete,
         *          @li False if the current frame is NOT complete,
         */
        inline bool IncomingMessage::IsCurrentFrameComplete () const
        {
            // we need at least 2 bytes to decode payload size
            if ( current_frame_->header_buffer_.length_ < 2 ) {
                // far for being complete
                return false;
            }

            // 2 bytes to decode frame properties ( including payload size )
            size_t min_required_bytes = 2;
            // depending on payload_length, we might need 16 or 64 more bits to decode a frame 'header'
            const uint8_t payload_length = ( current_frame_->header_buffer_.data_[1] & 0x7F );
            if ( 0x7E /* = 126 decimal */ == payload_length ) {
                // still need more 16 bits
                min_required_bytes += 2;
            } else if ( 0x7F /* = 127 decimal */ == payload_length ) {
                // still need more 64 bits
                min_required_bytes += 8;
            }
            // depending on mask, we might need 32 bits more to decode the frame 'payload'
            if ( 1 == current_frame_->mask_ ) {
                // still need more 32 bits
                min_required_bytes += 4;
            }

            return current_frame_->header_buffer_.fill_count_ >= min_required_bytes && current_frame_->payload_buffer_.FillCount() == current_frame_->payload_buffer_.Length();
        }

        /**
         * @brief Check if this message current frame is fragmented.
         *
         * @return
         *         @li True if the the message fragmented
         *         @li False if the the message is NOT fragmented
         */
        inline bool IncomingMessage::IsCurrentFrameFragmented () const
        {
            return current_frame_->fragmented_;
        }

        /**
         * @brief Check if this message is fragmented.
         *
         * @return
         *         @li True if the the message fragmented
         *         @li False if the the message is NOT fragmented
         */
        inline bool IncomingMessage::IsFragmented () const
        {
            return main_frame_.fragmented_;
        }

        /**
         * @brief Check if this message is complete.
         *
         * @return
         *         @li True if the the message complete
         *         @li False if the the message is NOT complete
         */
        inline bool IncomingMessage::IsComplete () const
        {
            return (
                    ( current_frame_->payload_buffer_.FillCount() == current_frame_->payload_buffer_.Length() )
                        &&
                    ( current_frame_->fragmented_ == false || ( 1 == current_frame_->fin_ && (uint8_t)BaseFrame::Opcodes::EContinuation == current_frame_->opcode_ ) )
            );
        }

        /**
         * @brief Allow read-only access to the payload data buffer.
         *
         * @param o_length         The frame buffer length.
         *
         * @return The pointer to the beginning of the frame buffer.
         */
        inline const unsigned char* IncomingMessage::PayloadData (size_t& o_length) const
        {
            if ( NULL == main_frame_.next_ ) {
                return current_frame_->payload_buffer_.Data(o_length);
            } else {
                return unchained_payload_buffer_.Data(o_length);
            }
        }

        /**
         * @brief Called when the payload should be unchained.
         *
         * @param o_length the unchained payload data length
         *
         * @return the pointer to the unchained payload data, NULL if out of memory of if the message is not complete.
         *
         * @note This message will be reset ( to save memory ), but unchained payload data will be kept.
         */
        inline const unsigned char* IncomingMessage::UnchainPayload (size_t& o_length)
        {
            o_length = 0;
            // we will only unchain payload if the message is complete
            if ( false == IsComplete() ) {
                // message not complete, not pointer for you!
                return NULL;
            }
            //
            IncomingFrame* frame  = &main_frame_;
            size_t frames_count = 0;
            //
            do {
                o_length += frame->payload_buffer_.Length();
                frames_count++;
                frame   = frame->next_;
            } while ( NULL != frame );
            //
            unsigned char* data = unchained_payload_buffer_.Alloc(o_length);
            if ( NULL != data ) {
                size_t copied_bytes = 0;
                frame = &main_frame_;
                do {
                    memcpy(data + copied_bytes, frame->payload_buffer_.Data(), frame->payload_buffer_.Length());
                    copied_bytes += frame->payload_buffer_.Length();
                    frame         = frame->next_;
                } while ( NULL != frame );
            } else {
                o_length = 0;
            }
            //  partial reset : we need to keep opcode and other data
            in_use_ = false;
            // all data will be released and reset, also all links will be released
            if ( NULL != main_frame_.next_ ) {
                delete main_frame_.next_;
                main_frame_.next_ = NULL;
            }
            // just one frame
            current_frame_ = &main_frame_;
            //
            return data;
        }

        /**
         * @brief Called when the contents should be reset.
         */
        inline void IncomingMessage::Reset (bool a_keep_unchained_payload = false)
        {
            in_use_      = false;
            // all data will be released and reset, also all links will be released
            main_frame_.Reset();
            // just one frame
            current_frame_ = &main_frame_;
            //
            if ( false == a_keep_unchained_payload ) {
                unchained_payload_buffer_.Release();
            }
        }

        /**
         * @brief Decodes a message.
         *
         * @param o_message       The message where the frame will be decoded.
         * @param a_data          the buffer that contains the message to be decoded.
         * @param a_length        the buffer length.
         * @param o_complete      true when the message decoding is completed.
         * @param o_fragmented    true when the message is fragmented.
         * @param o_decoded_bytes the number of decoded bytes.
         *
         * @return          @li <  0 on error
         *                  @li == 0 when there's nothing to be decoded.
         *                  @li >  0 the number of bytes left to be decoded
         */
        inline ssize_t IncomingMessage::Decode (IncomingMessage& o_message, const unsigned char* a_data, ssize_t a_length, bool& o_complete, bool& o_fragmented, size_t& o_decoded_bytes)
        {
            if ( true == o_message.Decode(a_data, a_length, o_decoded_bytes, o_complete, o_fragmented) ) {
                return a_length - static_cast<ssize_t>(o_decoded_bytes);
            }
            return -1;
        }

#ifdef __APPLE__
#pragma mark -
#pragma mark - OutgoingMessage
#endif

        /**
         * @brief A class that describes and decodes an outgoing message.
         */
        class OutgoingMessage : public BaseMessage {

        private: // data

            OutgoingFrame outgoing_frame_;

        public: // constructor(s) / destructor

            /**
             * @brief Default constructor.
             */
            OutgoingMessage () : BaseMessage(&outgoing_frame_)
            {
                // nop
            }

            /**
             * @brief Destructor.
             */
            virtual ~OutgoingMessage ()
            {
                // nop
            }

        public: // method(s) function(s) - declaration

            bool Encode(uint8_t a_opcode,
                        const unsigned char* a_application_data, size_t a_application_data_len,
                        const int32_t* a_masking_key);

            void Reset ();

        public: // read only functions - declaration

            const unsigned char* FrameBuffer (size_t& o_length) const;

        public: // static method(s) / function(s) - encoding - declaration

            static bool    Ping            (OutgoingMessage& o_message       , const unsigned char *a_data, ssize_t a_length , const int32_t* a_masking_key);
            static bool    Pong            (IncomingMessage const& a_message , OutgoingMessage& o_message                    , const int32_t* a_masking_key);
            static bool    Close           (OutgoingMessage& o_message                                                       , const int32_t* a_masking_key);

            static bool    Text            (OutgoingMessage& o_message       , const char* a__data                           , const int32_t* a_masking_key);
            static bool    Text            (OutgoingMessage& o_message       , const void* a_data         , size_t a_length  , const int32_t* a_masking_key);
            static bool    Binary          (OutgoingMessage& o_message       , const unsigned char* a_data, size_t a_length  , const int32_t* a_masking_key);

        };

        /**
         * @brief Encode a new ( non-fragmented ) message.
         *
         * @param a_opcode               The opcode of the message to be encoded, one of \link Opcodes \link.
         * @param a_a_application_data   The data to be encoded.
         * @param a_application_data_len The length of the data to be encoded.
         * @param a_masking_key          The key used to mask the application data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Encode(uint8_t a_opcode,
                                            const unsigned char* a_application_data, size_t a_application_data_len,
                                            const int32_t* a_masking_key = NULL)
        {
            //
            // WARNING: THIS FUNCTION DOES NOT SUPPORT ( YET ) FRAGMENTED ENCODING
            //          WHEN IMPLEMENTED: BE AWARE OF UTF-8 AND FRAGMENTATION ISSUES!
            //
            Reset();
            //
            in_use_ = true;
            //
            size_t extended_payload_bytes;
            if ( 125 >= a_application_data_len ) {
                extended_payload_bytes = 0;
            } else if ( 126 <= a_application_data_len && 65535 >= a_application_data_len ) {
                extended_payload_bytes = sizeof(unsigned char) * 2;
            } else {
                extended_payload_bytes = sizeof(unsigned char) * 8;
            }
            //
            const size_t two_bytes                 = sizeof(unsigned char) * 2;
            const size_t pre_padding_bytes         = ( NULL != a_masking_key ? two_bytes + sizeof(int32_t) : two_bytes ) + extended_payload_bytes;
            const size_t required_frame_buffer_len = pre_padding_bytes + a_application_data_len;
            //
            unsigned char* frame_buffer            = outgoing_frame_.buffer_.Alloc(required_frame_buffer_len);
            if ( NULL == frame_buffer ) {
                // out of memory
                return false;
            }
            // fin ( 1 bit ) + rsv's ( 3 bits ) + opcode ( 4 bits ) = 8 bits // 0x8F -> rsv1, rsv3, rsv3 - must be 0 unless an extension is negotiated
            frame_buffer[0] = ( ( 1 << 7 ) | ( a_opcode & 0xF ) ) & 0x8F;
            //
            if ( extended_payload_bytes == 0 ) {
                // mask ( 1 bit ) + payload len ( 7 bits  )             = 8 bits
                frame_buffer[1] = ( ( NULL != a_masking_key ? 1 << 7 : 0 ) | ( a_application_data_len & 0x7F ) );
            } else if ( extended_payload_bytes == 2 ) {
                // mask ( 1 bit ) + 0x7F ( 7 bits  )                    = 8 bits
                frame_buffer[1] = ( ( NULL != a_masking_key ? 1 << 7 : 0 ) | 0x7E );
                // extended payload len                                 = 16 bits
                frame_buffer[2] = ( a_application_data_len >> 8 ) & 0xFF;
                frame_buffer[3] = ( a_application_data_len      ) & 0xFF;
            } else /* if ( extended_payload_bytes == 8 ) */ {
                // mask ( 1 bit ) +  0x7F ( 7 bits )                    = 8 bits
                frame_buffer[1] = ( ( NULL != a_masking_key ? 1 << 7 : 0 ) | 0x7F );
                // current_frame_ payload len                           = 64 bits
                frame_buffer[2] = ( a_application_data_len >> 56 ) & 0xFF;
                frame_buffer[3] = ( a_application_data_len >> 48 ) & 0xFF;
                frame_buffer[4] = ( a_application_data_len >> 40 ) & 0xFF;
                frame_buffer[5] = ( a_application_data_len >> 32 ) & 0xFF;
                frame_buffer[6] = ( a_application_data_len >> 24 ) & 0xFF;
                frame_buffer[7] = ( a_application_data_len >> 16 ) & 0xFF;
                frame_buffer[8] = ( a_application_data_len >>  8 ) & 0xFF;
                frame_buffer[9] = ( a_application_data_len       ) & 0xFF;
            }
            //
            unsigned char* payload_dst = frame_buffer + pre_padding_bytes;
            // set mask bit ( and key if needed ) + payload data
            if ( NULL != a_masking_key ) {
                // copy mask key
                unsigned char* dst_masking_key_ptr = payload_dst - sizeof(int32_t);
                for ( size_t i = 0 ; i < sizeof(int32_t) ; ++i ) {
                    dst_masking_key_ptr[i] = ( (*a_masking_key) >> ( 8 * i ) ) & 0xFF ;
                }
                // transform and copy octect
                for ( size_t i = 0 ; i < a_application_data_len ; ++i ) {
                    payload_dst[i] = a_application_data[i] ^ ( ( (*a_masking_key) >> ( 8 * ( i % 4 ) )  ) & 0xFF );
                }
            } else {
                //
                memcpy(payload_dst, a_application_data, a_application_data_len);
            }
            //
            outgoing_frame_.fin_        = 1;
            outgoing_frame_.opcode_     = a_opcode;
            outgoing_frame_.mask_       = NULL != a_masking_key ? 1 : 0;
            outgoing_frame_.fragmented_ = false;
            //
            return true;
        }

        /**
         * @brief Called when the contents should be reset.
         */
        inline void OutgoingMessage::Reset ()
        {
            in_use_ = false;
            outgoing_frame_.Reset();
        }

        /**
         * @brief Allow read-only access to the frame buffer.
         *
         * @param o_length The frame buffer length.
         *
         * @return The pointer to the beginning of the frame buffer.
         */
        inline const unsigned char* OutgoingMessage::FrameBuffer (size_t& o_length) const
        {
            return outgoing_frame_.buffer_.Data(o_length);
        }

        /**
         * @brief Create a new control 'Pong' message: RFC 6455 - Section 5.5.2 - Ping.
         *        A Ping frame may serve either as a keepalive or as a means to verify that the remote endpoint is still responsive.
         *
         * @param o_message     The message where 'Ping' frame will be encoded ( based on 'Ping' "Application data" ).
         * @param a_data        The "Application data".
         * @param a_length      The "Application data" length ( in bytes ).
         * @param a_masking_key The key used to mask the 'Pong' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Ping (OutgoingMessage& o_message, const unsigned char *a_data, ssize_t a_length, const int32_t* a_masking_key = NULL)
        {
            //
            // * frame contains an opcode of 0x9 - ( \link ngx::ws::BaseFrame::Opcodes::EPing \endlink )
            //
            // * frame MAY include "Application data"
            //
            return o_message.Encode(static_cast<uint8_t>(ngx::ws::BaseFrame::Opcodes::EPing), a_data, static_cast<size_t>(a_length), a_masking_key);
        }

        /**
         * @brief Encodes a new control 'Pong' message: RFC 6455 - Section 5.5.3 - Pong.
         *        A Pong frame MAY be sent unsolicited.
         *        This serves as a unidirectional heartbeat.
         *        A response to an unsolicited Pong frame is not expected.
         *
         * @param a_message       The 'Ping' message.
         * @param o_message       The message where 'Pong' frame will be encoded ( based on 'Ping' "Application data" ).
         * @param a_masking_key The key used to mask the 'Pong' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Pong (IncomingMessage const& a_message, OutgoingMessage& o_message, const int32_t* a_masking_key = NULL)
        {
            size_t               ping_application_data_length = 0;
            const unsigned char* ping_application_data        = a_message.PayloadData(ping_application_data_length);
            //
            // * frame contains an opcode of 0xA - ( \link ngx::ws::BaseFrame::Opcodes::EPong \endlink )
            //
            // * frame sent in response to a Ping frame must have identical "Application data"
            //   as found in the message body of the Ping frame being replied to
            //
            return o_message.Encode(static_cast<uint8_t>(ngx::ws::BaseFrame::Opcodes::EPong),
                                    ping_application_data, ping_application_data_length, a_masking_key);
        }


        /**
         * @brief Encodes a new control 'Close' message: RFC 6455 - Section 5.5.1 - Close.
         *
         * @param o_message     The message where 'Close' frame will be encoded ( based on 'Ping' "Application data" ).
         * @param a_masking_key The key used to mask the 'Pong' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Close (OutgoingMessage& o_message, const int32_t* a_masking_key = NULL)
        {
            //
            // * frame contains an opcode of 0x8 - ( \link ngx::ws::BaseFrame::Opcodes::EClose \endlink )
            // * frame MAY contain a body ( @ application data ) - a reason for closing
            //
            //   * the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order)
            //     representing a status code with value /code/ defined \link ngx::ws::Frame::Opcodes::EClose \endlink.
            //
            //    * the body MAY contain UTF-8-encoded data with value /reason/, the interpretation of which is not defined by
            //      this specification
            //
            return o_message.Encode(static_cast<uint8_t>(ngx::ws::BaseFrame::Opcodes::EClose), NULL, 0, a_masking_key);
        }


        /**
         * @brief Encodes a new 'Text' data message: RFC 6455 - Section 5.6.1 - Data Frames.
         *
         * @param o_message      The message where 'text' frame will be encoded.
         * @param a_data         The 'text' data, UTF-8 encoded.
         * @param a_masking_key  The key used to mask the 'text' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Text (OutgoingMessage& o_message, const char* a_data, const int32_t* a_masking_key = NULL)
        {
            //
            // * "payload data" is text data encoded as UTF-8
            //
            // * note that a particular text frame might include a partial UTF-8 sequence;
            //   however, the whole message MUST contain valid UTF-8
            //
            // * invalid UTF-8 in reassembled messages is handled as described in RFC 6455 - Section 8.1 - Handling Errors in UTF8-Encoded Data
            //
NGX_WS_TODO("implement text data frame - deal with p nº 2 - patial message")
            //
            return o_message.Encode(static_cast<uint8_t>(ngx::ws::BaseFrame::Opcodes::EText),
                                    reinterpret_cast<const unsigned char*>(a_data), strlen(a_data),
                                    a_masking_key);
        }


        /**
         * @brief Encodes a new 'Text' data message: RFC 6455 - Section 5.6.1 - Data Frames.
         *
         * @param o_message      The message where 'text' frame will be encoded.
         * @param a_data         The 'text' data, UTF-8 encoded.
         * @param a_length       The data length.
         * @param a_masking_key  The key used to mask the 'text' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Text (OutgoingMessage& o_message, const void* a_data, size_t a_length, const int32_t* a_masking_key = NULL)
        {
            //
            // * "payload data" is text data encoded as UTF-8
            //
            // * note that a particular text frame might include a partial UTF-8 sequence;
            //   however, the whole message MUST contain valid UTF-8
            //
            // * invalid UTF-8 in reassembled messages is handled as described in RFC 6455 - Section 8.1 - Handling Errors in UTF8-Encoded Data
            //
            return o_message.Encode(static_cast<uint8_t>(ngx::ws::BaseFrame::Opcodes::EText),
                                    reinterpret_cast<const unsigned char*>(a_data), a_length,
                                    a_masking_key);
        }

        /**
         * @brief Encodes a new 'Binary' data message: RFC 6455 - Section 5.6.1 - Data Frames.
         *
         * @param o_message     The messag where 'binary' frame will be encoded.
         * @param a_data        The 'binary' data.
         * @param a_length      The data length
         * @param a_masking_key The key used to mask the 'binary' payload data ( optional ).
         *
         * @return True on success, false on failure.
         */
        inline bool OutgoingMessage::Binary (OutgoingMessage& o_message, const unsigned char* a_data, size_t a_length, const int32_t* a_masking_key = NULL)
        {
            //
            //  * the "payload data" is arbitrary binary data
            //    whose interpretation is solely up to the application layer
            //
            NGX_WS_TODO("implement binary data");
            //
            NGX_WS_UNUSED_PARAM(o_message);
            NGX_WS_UNUSED_PARAM(a_data);
            NGX_WS_UNUSED_PARAM(a_length);
            NGX_WS_UNUSED_PARAM(a_masking_key);
            //
            return false;
        }

#ifdef __APPLE__
#pragma mark -
#pragma mark - Handskake
#endif

        /**
         * A class that defines common field for client / server handshake.
         */
        class Handshake {

        public: // enums

            /**
             * @brief An enumeration of required protocol headers.
             */
            enum class ProtocolHeaders : int8_t {
                EInvalid                = -1,
                ESecWebSocketKey        =  0,   //!< header field with a base64-encoded alue that when decoded, is 16 bytes in length.
                ESecWebSocketExtensions     ,   //!< list of extensions support by the client
                ESecWebSocketAccept         ,   //!< header field, with a list of values indicating which protocols the client would like to speak, ordered by preference
                                                //!< or the server selected protocol
                ESecWebSocketProtocol       ,   //!< subprotocol selector
                ESecWebSocketVersion        ,   //!< header field, with a value of 13
            };

            /**
             * @brief An enumeration of required connection headers.
             */
            enum class ConnectionHeaders : int8_t {
                EInvalid                = -1,
                EUpgrade                = 0,    //!< header field containing the value "websocket"
                EConnection                ,    //!< header field that includes the token "Upgrade"
            };

        public: // types

            /**
             * @brief An struct that defines in headers properties.
             */
            typedef struct in_header_s {
                ProtocolHeaders key_;
                char const*     lower_case_name_;
                char const*     name_;
                size_t          length_;
            } in_header_t;

            /**
             * @brief An struct that defines out headers properties.
             */
            typedef struct out_header_s {
                ConnectionHeaders key_;
                char const*       lower_case_name_;
                char const*       name_;
                size_t            length_;
            } out_header_t;

        };

#ifdef __APPLE__
#pragma mark -
#pragma mark - ServerHandshake
#endif

        /**
         * A class that implements the server side handshake.
         */
        class ServerHandshake : public Handshake {

        public: // static const data

            static const in_header_s    kRequiredInHeadersTable  []; //!< a list of required input headers and their properties
            static const out_header_s   kRequiredOutHeadersTable []; //!< a list of required output headers and their properties

        public: // const data

            char const* accepted_protocol_;                         //!< the acceptable protocol name
            const char* accepted_version_;                          //!< the acceptable protocol version

        public: // constructor(s) / destructor

            ServerHandshake (char const* a_protocol)
            : accepted_protocol_(a_protocol), accepted_version_("13")
            {
                // nop
            }

            virtual ~ServerHandshake ()
            {
                // nop
            }

        public: // method(s) / function(s) - declaration

            bool Handshake (const std::map<std::string, std::string>& a_in_headers, std::map<std::string, std::string>& o_out_headers);

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
            virtual bool SHA1 (const void* a_data, size_t a_data_len, unsigned char* o_data)               = 0;

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
            virtual bool B64E (const unsigned char* a_buffer, size_t a_buffer_size, std::string& o_buffer) = 0;

        };

        /**
         * @brief Based on received headers, validate and calculate client request for an handskake.
         *
         * @param a_in_headers the received client headers.
         * @param a_out_header the required headers to send to the client to complete the handskahe.
         *
         * @return
         *         @li True on success
         *         @li False when rejected ( usually because we're missing data ).
         */
        inline bool ServerHandshake::Handshake(const std::map<std::string, std::string> &a_in_headers, std::map<std::string, std::string>& o_out_headers)
        {

            typedef struct accept_header_s {
                char const* name_;
                char const* value_;
            } accept_header_t;

            std::map<ProtocolHeaders, accept_header_t> accepted_headers;

            /*
             * Collect all required headers.
             */
            std::map<std::string, std::string>::const_iterator it;
            for ( it = a_in_headers.begin(); a_in_headers.end() != it ; ++it ) {
                if ( 0 == strncasecmp(it->first.c_str(), "Sec-WebSocket", 13) && 0 < it->second.length() ) {
                    for ( int8_t index = 0 ; ProtocolHeaders::EInvalid != kRequiredInHeadersTable[index].key_ ; ++index ) {
                        if ( 0 == strncasecmp(it->first.c_str(), kRequiredInHeadersTable[index].name_, kRequiredInHeadersTable[index].length_) ) {
                            accepted_headers[kRequiredInHeadersTable[index].key_] = { kRequiredInHeadersTable[index].name_, it->second.c_str() };
                            break;
                        }
                    }
                }
            }

            /*
             * Check for missing headers
             */
            // missing protocol header?
            if ( accepted_headers.end() == accepted_headers.find(ProtocolHeaders::ESecWebSocketProtocol) ) {
                // yes, it's missing
                return false;
            }
            // missing version header?
            if ( accepted_headers.end() == accepted_headers.find(ProtocolHeaders::ESecWebSocketVersion) ) {
                // yes, it's missing
                return false;
            }
            // missing key header?
            if ( accepted_headers.end() == accepted_headers.find(ProtocolHeaders::ESecWebSocketKey) ) {
                return false;
                // yes, it's missing
            }

            /*
             * Validate protocol and version:
             */
            // did client sent valid / supported 'Sec-WebSocket-Protocol' field?
            const char* client_requested_protocol = accepted_headers[ProtocolHeaders::ESecWebSocketProtocol].value_;
            if ( 0 != strcasecmp(client_requested_protocol, accepted_protocol_) ) {
                // can't accept the requested protocol
                return false;
            }
            // did client sent valid / supported 'Sec-WebSocket-Version' field?
            const char* client_requested_version = accepted_headers[ProtocolHeaders::ESecWebSocketVersion].value_;
            if ( 0 != strcasecmp(client_requested_version, accepted_version_) ) {
                // can't accept the requested version
                return false;
            }

            /*
             * Calculate 'Sec-WebSocket-Accept' value:
             */
            // did client sent valid / supported 'Sec-WebSocket-Accept' field?
            const char* client_accept_value = accepted_headers[ProtocolHeaders::ESecWebSocketKey].value_;
            if ( NULL == client_accept_value ) {
                // can't accept this field!
                return false;
            }
            //
            std::stringstream tmp;
            tmp << client_accept_value << "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            //
            unsigned char hash[20];
            //
            std::string b64_value = "";
            // first calculate sha1
            if ( true == SHA1(tmp.str().c_str(), tmp.str().length(), hash) ) {
                // now convert to base 64
                if ( false == B64E(hash, sizeof(hash)/sizeof(hash[0]), b64_value) ) {
                    // forget b64 buffer content
                    b64_value = "";
                }
            }

            /*
             * Set out headers.
             */
            const char* header_sec_ws_protocol_key    = kRequiredInHeadersTable [static_cast<int8_t>(ProtocolHeaders::ESecWebSocketProtocol)].name_;
            const char* header_sec_ws_accept_key      = kRequiredInHeadersTable [static_cast<int8_t>(ProtocolHeaders::ESecWebSocketAccept)  ].name_;
            const char* header_upgrade_key            = kRequiredOutHeadersTable[static_cast<size_t>(ConnectionHeaders::EUpgrade)           ].name_;
            //
            o_out_headers[header_sec_ws_protocol_key] = accepted_protocol_;
            o_out_headers[header_sec_ws_accept_key]   = b64_value;
            if ( 0 < b64_value.length() ) {
                o_out_headers[header_upgrade_key]     = "WebSocket";
            } else {
                o_out_headers[header_upgrade_key]     = "";
            }
            // success if all required out headers got a valid value
            return 0 < o_out_headers[header_sec_ws_protocol_key].length() &&
                   0 < o_out_headers[header_sec_ws_accept_key].length() &&
                   0 < o_out_headers[header_upgrade_key].length();
        }


    } // end of namespace 'ws'

} // endof namespace 'ngx'

#endif // NRS_NGX_WEBSOCKET_PROTOCOL_H_
