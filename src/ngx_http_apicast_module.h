#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_upstream_secure_connection_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c);
ngx_int_t ngx_http_upstream_should_verified(ngx_http_request_t *r);
