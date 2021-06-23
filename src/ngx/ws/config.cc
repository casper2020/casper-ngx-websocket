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

#include "ngx/ws/config.h"

#include "cc/fs/dir.h"

#include "cc/easy/json.h"
#include "cc/exception.h"

// MARK: - OneShotInitializer

ngx::ws::ConfigOneShotInitializer::ConfigOneShotInitializer (ngx::ws::Config& a_instance)
    : ::cc::Initializer<ngx::ws::Config>(a_instance)
{
    /* service */
    a_instance.service_.id_ = "";
}

ngx::ws::ConfigOneShotInitializer::~ConfigOneShotInitializer ()
{
    /* empty */
}

// MARK: - Config

const char* const ngx::ws::Config::k_redis_ip_address_key_lc_                = "redis_ip_address";
const char* const ngx::ws::Config::k_redis_port_number_key_lc_               = "redis_port_number";
const char* const ngx::ws::Config::k_redis_database_key_lc_                  = "redis_database";
const char* const ngx::ws::Config::k_redis_max_conn_per_worker_lc_           = "redis_max_conn_per_worker";

const char* const ngx::ws::Config::k_beanstalkd_host_key_lc_                 = "beanstalkd_host";
const char* const ngx::ws::Config::k_beanstalkd_port_key_lc_                 = "beanstalkd_port";
const char* const ngx::ws::Config::k_beanstalkd_timeout_key_lc_              = "beanstalkd_timeout";
const char* const ngx::ws::Config::k_beanstalkd_sessionless_tubes_key_lc_    = "beanstalkd_sessionless_tubes";
const char* const ngx::ws::Config::k_beanstalkd_action_tubes_key_lc_         = "beanstalkd_action_tubes";

const char* const ngx::ws::Config::k_postgresql_conn_str_key_lc_             = "postgresql_conn_str";
const char* const ngx::ws::Config::k_postgresql_statement_timeout_lc_        = "postgresql_statement_timeout";
const char* const ngx::ws::Config::k_postgresql_post_connect_queries_lc_     = "postgresql_post_connect_queries";
const char* const ngx::ws::Config::k_postgresql_max_conn_per_worker_lc_      = "postgresql_max_conn_per_worker";
const char* const ngx::ws::Config::k_postgresql_min_queries_per_conn_lc_     = "postgresql_min_queries_per_conn";
const char* const ngx::ws::Config::k_postgresql_max_queries_per_conn_lc_     = "postgresql_max_queries_per_conn";

const char* const ngx::ws::Config::k_curl_max_conn_per_worker_lc_            = "curl_max_conn_per_worker";

const char* const ngx::ws::Config::k_gatekeeper_config_file_uri_key_lc_      = "gatekeeper_config_file_uri";

/**
 * @brief Load 'main' config.
 *
 * @param a_config NGX 'main' config, see \link nginx_epaper_service_conf_t \link.
 */
void ngx::ws::Config::Load (const nginx_epaper_service_conf_t* a_config)
{
    const ::cc::easy::JSON<::cc::Exception> json;
    /* service */
    service_.id_ = std::string(reinterpret_cast<char const*>(a_config->service_id.data), a_config->service_id.len);
    /* redis */
    if ( a_config->redis.ip_address.len > 0 ) {
        // ... host ...
        map_[ngx::ws::Config::k_redis_ip_address_key_lc_]
            = std::string(reinterpret_cast<char const*>(a_config->redis.ip_address.data), a_config->redis.ip_address.len);
        // ... port ...
        map_[ngx::ws::Config::k_redis_port_number_key_lc_] = std::to_string(a_config->redis.port_number);
        // ... database ...
        if ( -1 != a_config->redis.database ) {
            map_[ngx::ws::Config::k_redis_database_key_lc_] = std::to_string((a_config->redis.database));
        }
        // ... max con per worker ...
        map_[ngx::ws::Config::k_redis_max_conn_per_worker_lc_] = std::to_string(a_config->redis.max_conn_per_worker);
    }
    /* beanstalkd */
    if ( a_config->beanstalkd.host.len > 0 ) {
        map_[ngx::ws::Config::k_beanstalkd_host_key_lc_]
            = std::string(reinterpret_cast<char const*>(a_config->beanstalkd.host.data), a_config->beanstalkd.host.len);
    }
    map_[ngx::ws::Config::k_beanstalkd_port_key_lc_]    = std::to_string(a_config->beanstalkd.port);
    map_[ngx::ws::Config::k_beanstalkd_timeout_key_lc_] = std::to_string(a_config->beanstalkd.timeout);
    const std::map<const char* const, const ngx_str_t*> beanstalk_conf_strings_map = {
        { ngx::ws::Config::k_beanstalkd_sessionless_tubes_key_lc_, &a_config->beanstalkd.tubes.sessionless },
        { ngx::ws::Config::k_beanstalkd_action_tubes_key_lc_     , &a_config->beanstalkd.tubes.action      }
    };
    for ( auto bcsm_it : beanstalk_conf_strings_map ) {
        if ( bcsm_it.second->len > 0 ) {
            map_[bcsm_it.first] = std::string(reinterpret_cast<char const*>(bcsm_it.second->data), bcsm_it.second->len);
        }
    }
    /* postgresql */
    if ( a_config->postgresql.conn_str.len > 0 ) {
        map_[ngx::ws::Config::k_postgresql_conn_str_key_lc_]
            = std::string(reinterpret_cast<char const*>(a_config->postgresql.conn_str.data), a_config->postgresql.conn_str.len);
    }
    map_[ngx::ws::Config::k_postgresql_statement_timeout_lc_]    = std::to_string(a_config->postgresql.statement_timeout);
    map_[ngx::ws::Config::k_postgresql_max_conn_per_worker_lc_]  = std::to_string(a_config->postgresql.max_conn_per_worker);
    map_[ngx::ws::Config::k_postgresql_min_queries_per_conn_lc_] = std::to_string(a_config->postgresql.min_queries_per_conn);
    map_[ngx::ws::Config::k_postgresql_max_queries_per_conn_lc_] = std::to_string(a_config->postgresql.max_queries_per_conn);
    /* cURL */
    map_[ngx::ws::Config::k_curl_max_conn_per_worker_lc_]        = std::to_string(a_config->curl.max_conn_per_worker);
    /* gatekeeper */
    map_[ngx::ws::Config::k_gatekeeper_config_file_uri_key_lc_]
        = std::string(reinterpret_cast<char const*>(a_config->gatekeeper.config_file_uri.data), a_config->gatekeeper.config_file_uri.len);
}
