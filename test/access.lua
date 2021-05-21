local ssl = require('ngx.ssl')
local open = io.open
local ffi = require "ffi"
local C = ffi.C
local base = require "resty.core.base"
local get_request = base.get_request

local function set_certs(cert, key)
  ngx.log(ngx.INFO, "Try to set certs")
  ffi.cdef[[
  int ngx_http_apicast_ffi_set_proxy_cert_key(
    ngx_http_request_t *r, void *cdata_chain, void *cdata_key);
  ]]
  local r = get_request()
    if not r then
      ngx.log(ngx.ERR, "No valid request")
      return
    end
   C.ngx_http_apicast_ffi_set_proxy_cert_key(r, cert, key)

end

local function set_ca(cert)
  ngx.log(ngx.INFO, "Try to set CA certs")
  ffi.cdef[[
  int ngx_http_apicast_ffi_set_proxy_ca_cert(
    ngx_http_request_t *r, void *cdata_ca);

  ]]

  -- In apicast we have custom helpers for this.using lua-resty-openssl
  local store = require("resty.openssl.x509.store")
  local x509 = require("resty.openssl.x509")
  local store = store.new()

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end
  store:add(x509.new(cert))

  C.ngx_http_apicast_ffi_set_proxy_ca_cert(r, store.ctx)
end

local function set_ffi_verify()
  ngx.log(ngx.INFO, "Try to set CA certs")
  ffi.cdef[[
  int ngx_http_apicast_ffi_set_ssl_verify(ngx_http_request_t *r, int verify, int verify_deph);
  ]]

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end

  C.ngx_http_apicast_ffi_set_ssl_verify(r, ffi.new("int", 1), ffi.new("int", 1))
end

local function read_file(path)
    local file = open(path, "rb") -- r read mode and b binary mode
    if not file then return nil end
    local content = file:read "*a" -- *a or *all reads the whole file
    file:close()
    return content
end

local cert =  read_file("/opt/certs/client.crt")
local cert_key =  read_file("/opt/certs/client.key")
local ca_cert =  read_file("/opt/certs/rootCA.pem")

local cert_chain, err = ssl.parse_pem_cert(cert)
if err then
  ngx.log(ngx.ERR, "Unable to parse cer")
end

local priv_key, err = ssl.parse_pem_priv_key(cert_key)
if err then
  ngx.log(ngx.ERR, "Unable to parse cer key")
end

set_certs(cert_chain, priv_key)
set_ca(ca_cert)
set_ffi_verify()
