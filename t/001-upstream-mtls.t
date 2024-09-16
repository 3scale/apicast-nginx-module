use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

repeat_each(2);

my $pwd = cwd();

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

log_level 'debug';

# no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: upstream return 400 when no client certificates is sent
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        proxy_ssl_trusted_certificate ../../fixtures/rootCA.pem;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- response_body_like
.+No required SSL certificate was sent.+
--- error_log
client sent no required SSL certificate while reading client request headers
--- error_code: 400
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: send client certificate with apicast-mtls module
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
        }

        proxy_ssl_trusted_certificate /opt/certs/rootCA.pem;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- response_body
yay, API backend
--- error_log
verify:1, error:0, depth:2, subject:"/CN=root.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:1, subject:"/CN=sub.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:0, subject:"/CN=test", issuer:"/CN=sub.ca"
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 3:  repeatedly requests does not leaks memory
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../..//fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../..//fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
        }

        proxy_ssl_trusted_certificate ../../fixtures/rootCA.pem;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request eval
["GET /t", "GET /t"]
--- error_log
verify:1, error:0, depth:2, subject:"/CN=root.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:1, subject:"/CN=sub.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:0, subject:"/CN=test", issuer:"/CN=sub.ca"
--- error_code eval: [200, 200]
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4:  failed with invalid certificate chain
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
        }

        proxy_ssl_trusted_certificate ../../fixtures/subCA.pem;
        proxy_ssl_verify on;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- error_log
upstream SSL certificate verify error: (21:unable to verify the first certificate) while SSL handshaking to upstream
--- error_code: 502
--- no_error_log
[crit]
[alert]



=== TEST 5:  invalid certificate chain failed when certificate verify is enabled via apicast-nginx-module
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
          mtls:set_ssl_verify(true)
        }

        proxy_ssl_trusted_certificate ../../fixtures/subCA.pem;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- error_log
SSL_do_handshake() failed
--- error_code: 502
--- no_error_log
[error]
[alert]



=== TEST 6:  invalid certificate chain with certificate verify enabled via set_ssl_verify
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
          mtls:set_ssl_verify(true)
        }

        proxy_ssl_trusted_certificate ../../fixtures/subCA.pem;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- error_log
SSL_do_handshake() failed
--- error_code: 502
--- no_error_log
[error]
[alert]



=== TEST 7:  invalid certificate chain with certificate verify disabled via set_ssl_verify
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
          mtls:set_ssl_verify(false)
        }

        proxy_ssl_trusted_certificate ../../fixtures/subCA.pem;
        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- response_body_like
yay, API backend
--- error_code: 200
--- no_error_log
[crit]
[alert]
[error]



=== TEST 8: setting valid trusted store with set_ca
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)

          f = assert(io.open("t/fixtures/rootCA.pem"))
          local ca_cert = f:read("*a")
          f:close()

          local ssl_store = require("resty.openssl.x509.store")
          local x509 = require("resty.openssl.x509")

          local store = ssl_store.new()
          store:add(x509.new(ca_cert))
          mtls:set_ca(store)
          mtls:set_ssl_verify(true)
        }

        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_name example.com;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- more_headers
Host: example.com
--- response_body
yay, API backend
--- error_log
verify:1, error:0, depth:2, subject:"/CN=root.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:1, subject:"/CN=sub.ca", issuer:"/CN=root.ca"
verify:1, error:0, depth:0, subject:"/CN=test", issuer:"/CN=sub.ca"
X509_check_host(): match
--- error_code: 200
--- no_error_log
[error]
[crit]
[alert]



=== TEST 9: setting invalid trusted store with set_ca
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;lualib/?.lua;;";

    # to suppress a valgrind false positive in the nginx core:
    proxy_ssl_session_reuse off;


    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   example.com;
        ssl_certificate ../../fixtures/example.com.crt;
        ssl_certificate_key ../../fixtures/example.com.key;
        ssl_client_certificate ../../fixtures/rootCA.pem;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            default_type 'text/plain';
            more_clear_headers Date;
            echo 'yay, API backend';
        }
    }
--- config
    server_tokens off;
    location /t {
        access_by_lua_block {
          mtls = require("resty.mtls")
          local ssl = require("ngx.ssl")
          local f = assert(io.open("t/fixtures/client_chain.crt"))
          local cert = f:read("*a")
          f:close()

          local chain = assert(ssl.parse_pem_cert(cert))

          f = assert(io.open("t/fixtures/client.key"))
          local key = f:read("*a")
          f:close()

          local private_key = assert(ssl.parse_pem_priv_key(key))

          mtls:set_certs(chain, private_key)
          mtls:set_ssl_verify(true)

          f = assert(io.open("t/fixtures/subCA.pem"))
          local ca_cert = f:read("*a")
          f:close()

          local ssl_store = require("resty.openssl.x509.store")
          local x509 = require("resty.openssl.x509")

          local store = ssl_store.new()
          store:add(x509.new(ca_cert))
          mtls:set_ca(store)
        }

        proxy_ssl_name example.com;
        proxy_ssl_session_reuse off;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
        proxy_ssl_server_name on;
    }
--- request
GET /t
--- error_log
SSL_do_handshake() failed
--- error_code: 502
--- no_error_log
[error]
[alert]
