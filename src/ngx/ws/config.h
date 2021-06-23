/**
 * @file config.h
 *
 * Copyright (c) 2011-2021 Cloudware S.A. All rights reserved.
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
#ifndef NRS_NGX_WS_CONFIG_H_
#define NRS_NGX_WS_CONFIG_H_

#include "cc/singleton.h"

#include "ev/ngx/includes.h"

#include "json/json.h"

#include <string>
#include <map>

/* REDIS data types */
typedef struct {
    ngx_str_t ip_address;          //!<
    ngx_int_t port_number;         //!<
    ngx_int_t database;            //!<
    ngx_int_t max_conn_per_worker; //!<
} nginx_epaper_redis_conf_t;

/* BEANSTALKD data types */

typedef struct {
    ngx_str_t  action;         //!<
    ngx_str_t  sessionless;    //!<
} nginx_epaper_beanstalk_tubes_conf_t;

typedef struct {
    ngx_str_t  host;                              //!<
    ngx_uint_t port;                              //!<
    ngx_int_t  timeout;                           //!<
    nginx_epaper_beanstalk_tubes_conf_t tubes; //!<
} nginx_epaper_beanstalk_conf_t;
typedef struct {
    ngx_str_t config_file_uri;
} nginx_epaper_gatekeeper_conf_t;

/* POSTGRESQL data types */
typedef struct {
    ngx_str_t conn_str;              //!<
    ngx_int_t statement_timeout;     //!<
    ngx_int_t max_conn_per_worker;   //!<
    ngx_int_t max_queries_per_conn;  //!<
    ngx_int_t min_queries_per_conn;  //!<
} nginx_epaper_postgresql_conf_t;

/* cURL data types*/
typedef struct {
    ngx_int_t max_conn_per_worker;         //!<
} nginx_epaper_curl_conf_t;

/* JRXML data types*/
typedef struct {
    ngx_str_t  directory;
    ngx_uint_t js_cache_validity;
} nginx_epaper_jrxml_conf_t;

/* SESSION data types */
typedef struct {
    ngx_str_t  fields;
    ngx_uint_t ttl_extension;
    ngx_str_t  return_fields;
} nginx_epaper_casper_session_conf_t;

/* JSONAPI data types */
typedef struct {
    ngx_str_t url;
} nginx_epaper_casper_jsonapi_conf_t;

/* HTTP data types */
typedef struct {
    ngx_str_t acceptable;
} nginx_epaper_casper_http_conf_t;

/* DATA source types */
typedef struct {
    ngx_str_t overridable_sys_vars;
} nginx_epaper_casper_data_source_conf_t;

/* EDITOR data types */
typedef struct {
    ngx_str_t jrxml_directory;
} nginx_epaper_casper_editor_conf_t;

/*
 * EPAPER Config.
 */
typedef struct {
    /* jrxml */
    nginx_epaper_jrxml_conf_t              jrxml;
    /* data source */
    nginx_epaper_casper_data_source_conf_t data_source;
    /* casper session */
    nginx_epaper_casper_session_conf_t     session;
} ngx_http_websocket_epaper_config;

/**
 * @brief Module 'srv' configuration structure, applicable to a location scope
 */
typedef struct {
    /* service */
    ngx_str_t                              service_id;
    /* redis */
    nginx_epaper_redis_conf_t              redis;
    /* postgresql */
    nginx_epaper_postgresql_conf_t         postgresql;
    /* beanstalkd */
    nginx_epaper_beanstalk_conf_t          beanstalkd;
    /* curl */
    nginx_epaper_curl_conf_t               curl;
    /* gatekeeper */
    nginx_epaper_gatekeeper_conf_t         gatekeeper;
    /* jsonapi */
    nginx_epaper_casper_jsonapi_conf_t     jsonapi;
    /* http */
    nginx_epaper_casper_http_conf_t        http;
    /* global epaper 'casper' context config */
    ngx_http_websocket_epaper_config       epaper;
    /* legacy debug trace ( OSAL ) */
    ngx_str_t                               legacy_logger_enabled_debug_tokens;
} nginx_epaper_service_conf_t;

namespace ngx
{

    namespace ws
    {

        // ---- //
        class Config;
        class ConfigOneShotInitializer final : public ::cc::Initializer<ngx::ws::Config>
        {
            
        public: // Constructor(s) / Destructor
            
            ConfigOneShotInitializer (ngx::ws::Config& a_instance);
            virtual ~ConfigOneShotInitializer ();
            
        }; // end of class 'OneShotInitializer'

        // ---- //
        class Config final : public ::cc::Singleton<Config, ConfigOneShotInitializer>
        {

        friend class ConfigOneShotInitializer;
            
        public: // Static Const Data
            
            static const char* const k_redis_ip_address_key_lc_;
            static const char* const k_redis_port_number_key_lc_;
            static const char* const k_redis_database_key_lc_;
            static const char* const k_redis_max_conn_per_worker_lc_;
            
            static const char* const k_beanstalkd_host_key_lc_;
            static const char* const k_beanstalkd_port_key_lc_;
            static const char* const k_beanstalkd_timeout_key_lc_;
            static const char* const k_beanstalkd_sessionless_tubes_key_lc_;
            static const char* const k_beanstalkd_action_tubes_key_lc_;

            static const char* const k_postgresql_conn_str_key_lc_;
            static const char* const k_postgresql_statement_timeout_lc_;
            static const char* const k_postgresql_post_connect_queries_lc_;
            static const char* const k_postgresql_max_conn_per_worker_lc_;
            static const char* const k_postgresql_min_queries_per_conn_lc_;
            static const char* const k_postgresql_max_queries_per_conn_lc_;
            
            static const char* const k_curl_max_conn_per_worker_lc_;

            static const char* const k_gatekeeper_config_file_uri_key_lc_;
            
        public: // Data Type(s)
            
            typedef struct {
                std::string id_;
            } Service;
 
            typedef std::map<std::string, std::string> Map;

        private: // Data
            
            Service service_;
            Map     map_;

        public: // Method(s) / Function(s)
            
            void Load (const nginx_epaper_service_conf_t* a_config);

        public: // Inline Method(s) / Function(s)
            
            /**
             * @return R/O access to \link Service \link.
             */
            inline const Service& service() const { return service_; }
            
            /**
             * @return R/O access to \link Map \link.
             */
            inline const Map& map() const { return map_; }
            
        }; // end of class 'Config'
            
    } // end of namepace 'ws'

} // end of namespace 'ngx'

#endif // NRS_NGX_WS_CONFIG_H_

