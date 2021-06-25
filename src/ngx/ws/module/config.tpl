ngx_addon_name=ngx_http_websocket_module

HTTP_MODULES="$HTTP_MODULES ngx_http_websocket_module"

NGX_ADDON_SRCS="$NGX_ADDON_SRCS                \
$ngx_addon_dir/ngx_http_websocket_module.cc    \
$ngx_addon_dir/../abstract_websocket_client.cc \
$ngx_addon_dir/../websocket_context.cc         \
$ngx_addon_dir/../websocket_protocol.cc"

NGX_ADDON_DEPS="$NGX_ADDON_DEPS               \
$ngx_addon_dir/ngx_http_websocket_module.h    \
$ngx_addon_dir/../abstract_websocket_client.h \
$ngx_addon_dir/../websocket_context.h         \
$ngx_addon_dir/../websocket_protocol.h"

CORE_LIBS="$CORE_LIBS -lstdc++"

