local ffi = require "ffi"
local C = ffi.C
local base = require "resty.core.base"
local get_request = base.get_request

_M = {}

ffi.cdef[[
  int ngx_http_apicast_ffi_set_proxy_cert_key(
    ngx_http_request_t *r, void *cdata_chain, void *cdata_key);

  int ngx_http_apicast_ffi_set_proxy_ca_cert(
    ngx_http_request_t *r, void *cdata_ca);

  int ngx_http_apicast_ffi_set_ssl_verify(
    ngx_http_request_t *r, int verify, int verify_deph);
]]

function _M:set_certs(cert, key)
  ngx.log(ngx.INFO, "Try to set certs")

  local r = get_request()
    if not r then
      ngx.log(ngx.ERR, "No valid request")
      return
    end
   C.ngx_http_apicast_ffi_set_proxy_cert_key(r, cert, key)

end

function _M:set_ca(store)
  ngx.log(ngx.INFO, "Try to set CA certs")

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end

  C.ngx_http_apicast_ffi_set_proxy_ca_cert(r, store.ctx)
end

function _M:set_ssl_verify(verify)
  ngx.log(ngx.INFO, "Try to set verify")

  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "No valid request")
    return
  end

  C.ngx_http_apicast_ffi_set_ssl_verify(r, verify, ffi.new("int", 100))
end

return _M
