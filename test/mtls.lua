local ssl = require('ngx.ssl')
local open = io.open
local ffi = require "ffi"
local C = ffi.C
local base = require "resty.core.base"
local get_request = base.get_request
local ssl_store = require("resty.openssl.x509.store")
local x509 = require("resty.openssl.x509")

_M = {}

ffi.cdef[[
  int ngx_http_apicast_ffi_set_proxy_cert_key(
    ngx_http_request_t *r, void *cdata_chain, void *cdata_key);

  int ngx_http_apicast_ffi_set_proxy_ca_cert(
    ngx_http_request_t *r, void *cdata_ca);

  int ngx_http_apicast_ffi_set_ssl_verify(
    ngx_http_request_t *r, int verify, int verify_deph);
]]

local function set_certs(cert, key)
  ngx.log(ngx.INFO, "Try to set certs")

  local r = get_request()
    if not r then
      ngx.log(ngx.ERR, "No valid request")
      return
    end
   C.ngx_http_apicast_ffi_set_proxy_cert_key(r, cert, key)

end

local function set_ca(store)
  ngx.log(ngx.INFO, "Try to set CA certs")

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end

  C.ngx_http_apicast_ffi_set_proxy_ca_cert(r, store.ctx)
end

local function set_ffi_verify()
  ngx.log(ngx.INFO, "Try to set verify")

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end

  C.ngx_http_apicast_ffi_set_ssl_verify(r, ffi.new("int", 100), ffi.new("int", 100))
end

local function read_file(path)
    local file = open(path, "rb") -- r read mode and b binary mode
    if not file then return nil end
    local content = file:read "*a" -- *a or *all reads the whole file
    file:close()
    return content
end



function _M:init()
  local err = nil

  local cert =  read_file("/opt/certs/client_bundle.crt")
  local cert_key =  read_file("/opt/certs/client.key")
  local ca_cert =  read_file("/opt/certs/rootCA.pem")

  self.cert_chain, err = ssl.parse_pem_cert(cert)
  if err then
    ngx.log(ngx.ERR, "Unable to parse cer")
  end

  self.priv_key, err = ssl.parse_pem_priv_key(cert_key)
  if err then
    ngx.log(ngx.ERR, "Unable to parse cer key")
  end

  local store = ssl_store.new()

  store:add(x509.new(ca_cert))

  self.ca_store = store
end

function _M:access()
  set_certs(self.cert_chain, self.priv_key)
  set_ca(self.ca_store)
  set_ffi_verify()
end

return _M
