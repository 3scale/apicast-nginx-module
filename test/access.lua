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

local function read_file(path)
    local file = open(path, "rb") -- r read mode and b binary mode
    if not file then return nil end
    local content = file:read "*a" -- *a or *all reads the whole file
    file:close()
    return content
end

local cert =  read_file("/secrets/client.cer")
local cert_key =  read_file("/secrets/client.key")

local cert_chain, err = ssl.parse_pem_cert(cert)
if err then
  ngx.log(ngx.ERR, "Unable to parse cer")
end

local priv_key, err = ssl.parse_pem_priv_key(cert_key)
if err then
  ngx.log(ngx.ERR, "Unable to parse cer key")
end

set_certs(cert_chain, priv_key)
