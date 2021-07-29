/*
 * APIcast nginx module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  X509                *proxy_client_cert;
  STACK_OF(X509)      *proxy_client_cert_chain;
  EVP_PKEY            *proxy_client_cert_key;
  X509_STORE          *proxy_client_ca_store;
  int                 proxy_ssl_verify;
  int                 proxy_ssl_verify_depth;
} ngx_http_apiast_ctx_t;


static ngx_http_apiast_ctx_t * ngx_http_apicast_set_ctx(ngx_http_request_t *r);
ngx_int_t ngx_http_upstream_secure_connection_handler(
    ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c);

static ngx_int_t ngx_http_apicast_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_apicast_init(ngx_conf_t *cf);
void ngx_http_apicast_ssl_cleanup_ctx(void *data);

static ngx_command_t  ngx_http_apicast_commands[] = {
};

static ngx_http_module_t  ngx_http_apicast_module_ctx = {
  NULL,                                  /* preconfiguration */
  ngx_http_apicast_init,               /* postconfiguration */

  NULL,                                  /* create main configuration */
  NULL,                                  /* init main configuration */

  NULL,                                  /* create server configuration */
  NULL,                                  /* merge server configuration */

  NULL,    /* create location configuration */
  NULL,      /* merge location configuration */
};


ngx_module_t  ngx_http_apicast_module = {
  NGX_MODULE_V1,
  &ngx_http_apicast_module_ctx,        /* module context */
  ngx_http_apicast_commands,           /* module directives */
  NGX_HTTP_MODULE,                       /* module type */
  NULL,                                  /* init master */
  NULL,                                  /* init module */
  NULL,                                  /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  NULL,                                  /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_http_apiast_ctx_t * ngx_http_apicast_set_ctx(ngx_http_request_t *r) {

  ngx_http_apiast_ctx_t *ctx;
  ngx_pool_cleanup_t  *cln;

  // @TODO maybe we need to clean this memory
  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_apiast_ctx_t));
  if (ctx == NULL) {
    return NULL;
  }


  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL) {
      return NULL;
  }

  /* The proxy_ssl_handler(ngx_ssl_cleanup_ctx) handler is not working for
   * proxy_client_cert_chain, so we need to
   * clean manually */
  cln->handler = ngx_http_apicast_ssl_cleanup_ctx;
  cln->data = ctx;

  ngx_http_set_ctx(r, ctx, ngx_http_apicast_module);
  return ctx;
}

static ngx_int_t ngx_http_apicast_handler(ngx_http_request_t *r) {
  // @TODO validate here that the ctx is deleted and it's not leaking
  ngx_http_apicast_set_ctx(r);
  return NGX_OK;
}

int ngx_http_apicast_ffi_set_proxy_cert_key(
    ngx_http_request_t *r, void *cdata_chain, void *cdata_key) {

  char *err = "";
  STACK_OF(X509) *cert_chain = cdata_chain;
  EVP_PKEY *cert_key = cdata_key;


  if ( cert_chain == NULL || cert_key == NULL ) {
    err = "No valid cert or key was received";
    goto failed;
  }

  ngx_http_apiast_ctx_t *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_apicast_module);

  if (ctx == NULL) {
    err = "Context cannot be retrieved";
    goto failed;
  }

  int number_of_certs = sk_X509_num(cert_chain);
  if (number_of_certs < 1) {
    err = "Invalid certificate chain";
    goto failed;
  }

  X509 *x509 = NULL;
  x509 = sk_X509_value(cert_chain, 0);
  if (x509 == NULL) {
    err = "sk_X509_value() failed";
    goto failed;
  }

	if (EVP_PKEY_up_ref(cert_key) == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"EVP_PKEY_up_ref: failed to increment key");
		return NGX_ERROR;
	}

  ctx->proxy_client_cert = x509;
  ctx->proxy_client_cert_key = cert_key;

  if ( number_of_certs > 1 ) {
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (chain == NULL) {
        err = "sk_X509_new_null() failed";
        goto failed;
    }

    X509 *x509_cert = NULL;
    for (int i = 1; i < number_of_certs; i++) {
      x509_cert = sk_X509_value(cert_chain, i);
      if (x509_cert == NULL) {
        sk_X509_pop_free(chain, X509_free);
        err = "sk_X509_value() failed on chain certificate";
        goto failed;
      }

      if (sk_X509_push(chain, x509_cert) == 0) {
        err = "sk_X509_push() failed on chain certificate";
        X509_free(x509_cert);
        sk_X509_pop_free(chain, X509_free);
        goto failed;
      }
    }
    ctx->proxy_client_cert_chain = chain;
  }

  return NGX_OK;

failed:
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    "set_proxy_cert: %s", err);
  return NGX_ERROR;
}

int ngx_http_apicast_ffi_set_proxy_ca_cert(
    ngx_http_request_t *r, void *cdata_ca) {
  X509_STORE  *ca_store = cdata_ca;

  if ( ca_store == NULL)
    return NGX_ERROR;

  ngx_http_apiast_ctx_t *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_apicast_module);

  if (ctx == NULL)
    return NGX_ERROR;

  if (X509_STORE_up_ref(ca_store) == 0) {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
      "SetProxyCaCert: cannot set the store ref");
    return NGX_ERROR;
  }
  ctx->proxy_client_ca_store = ca_store;
  return NGX_OK;
}

int ngx_http_apicast_ffi_set_ssl_verify(ngx_http_request_t *r, int verify, int verify_deph){
  ngx_http_apiast_ctx_t *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_apicast_module);

  if (ctx == NULL)
    return NGX_ERROR;

  ctx->proxy_ssl_verify = verify;
  ctx->proxy_ssl_verify_depth = verify_deph;
  return NGX_OK;
}


ngx_int_t ngx_http_apicast_set_proxy_cert_if_set(
    ngx_http_request_t *r, ngx_http_apiast_ctx_t *ctx, ngx_connection_t *conn) {

  char *err = "";

  if ( ctx == NULL ) {
    err = "No context found";
    goto ssl_failed;
  }

  if ( ctx->proxy_client_cert == NULL ) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
      "SetProxyCert: no certificate was set");
    return NGX_OK;
  }

  int rc = SSL_use_certificate(conn->ssl->connection, ctx->proxy_client_cert);
  if ( rc == 0 ) {
      err = "SSL_USE_certificate failed";
      goto ssl_failed;
  }

  if (ctx->proxy_client_cert_chain) {
    /* got a client cert chain */
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
      "SetProxyCert: set proxy certificate chain");
    rc = SSL_set1_chain(conn->ssl->connection, ctx->proxy_client_cert_chain);
    if (rc == 0 ) {
      err = "SSL chain cert failed";
      sk_X509_pop_free(ctx->proxy_client_cert_chain, X509_free);
      goto ssl_failed;
    }
  }
  
  return NGX_OK;

ssl_failed:
  ERR_print_errors_fp(stderr);
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    "SetProxyCert: %s", err);
  ERR_clear_error();
  return NGX_ERROR;
}

ngx_int_t ngx_http_apicast_set_proxy_cert_key_if_set(
    ngx_http_request_t *r,
    ngx_http_apiast_ctx_t *ctx,
    ngx_connection_t *conn) {
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  if ( ctx->proxy_client_cert_key == NULL ) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
      "SetProxyCertKey: certificate key was not found");
    return NGX_OK;
  }

  int rc = SSL_use_PrivateKey(
      conn->ssl->connection,
      ctx->proxy_client_cert_key);

  if ( rc == 0 ) {
		EVP_PKEY_free(ctx->proxy_client_cert_key);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
      "SetProxyCertKey: cannot use certificate key, rc:'%d'", rc);
    ERR_print_errors_fp(stderr);
    ERR_clear_error();
    return NGX_ERROR;
  }

  return NGX_OK;
}

ngx_int_t ngx_http_apicast_set_proxy_ca_cert_if_set(
    ngx_http_request_t *r,
    ngx_http_apiast_ctx_t *ctx,
    ngx_connection_t *conn) {

  if ( ctx == NULL ) {
    return NGX_ERROR;
  }

  if ( ctx->proxy_client_ca_store == NULL ) {
    return NGX_OK;
  }

  int rc = SSL_set1_verify_cert_store(
      conn->ssl->connection,
      ctx->proxy_client_ca_store);
  if ( rc == 0 ) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
      "Cannot set the ca cert to the store, rc:%d", rc);
    return NGX_ERROR;
  }

  return NGX_OK;
}


ngx_int_t ngx_http_apicast_set_proxy_ssl_verify(
    ngx_http_request_t *r,
    ngx_http_apiast_ctx_t *ctx,
    ngx_connection_t *conn) {

  if ( ctx == NULL ) {
    return NGX_ERROR;
  }

  if ( ctx->proxy_ssl_verify > 0 ) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Enable proxy ssl upstream verify");
    SSL_set_verify(conn->ssl->connection, SSL_VERIFY_PEER ,0);
  }

  if (ctx->proxy_ssl_verify_depth > 0) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Enable proxy ssl upstream verify depth to %d", ctx->proxy_ssl_verify_depth);
    SSL_set_verify_depth(conn->ssl->connection, ctx->proxy_ssl_verify_depth);
  }

  return NGX_OK;
}


ngx_int_t ngx_http_upstream_secure_connection_handler(
    ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c) {

  ngx_http_apiast_ctx_t *ctx;
  char *err = "";
  ctx = ngx_http_get_module_ctx(r, ngx_http_apicast_module);

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
    "Connection Handler started for request:'%p' and ctx:'%p'", r, ctx);
  if ( ctx == NULL ) {
    err = "Handler:: no context found";
    goto ssl_failed;
  }

  if ( ngx_http_apicast_set_proxy_cert_if_set(r, ctx, c) != NGX_OK ) {
    err = "SetCert:: cannot set proxy_cert";
    goto ssl_failed;
  }

  if ( ngx_http_apicast_set_proxy_cert_key_if_set(r, ctx, c) != NGX_OK ) {
    err = "SetPrivatekey:: cannot set proxy key";
    goto ssl_failed;
  }

  if ( ngx_http_apicast_set_proxy_ca_cert_if_set(r, ctx, c) != NGX_OK ) {
    err = "SetCaCert:: cannot set CA certs";
    goto ssl_failed;
  }

  if ( ngx_http_apicast_set_proxy_ssl_verify(r, ctx, c) != NGX_OK ) {
    err = "SetSSLVerifyandDepth:: cannot set ssl_verify";
    goto ssl_failed;
  }

  return NGX_OK;

ssl_failed:
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    "Connection Handler: %s", err);
  ERR_clear_error();
  return NGX_ERROR;
}

static ngx_int_t ngx_http_apicast_init(ngx_conf_t *cf) {

  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if ( h == NULL ) {
    return NGX_ERROR;
  }

  *h = ngx_http_apicast_handler;

  return NGX_OK;
}

void
ngx_http_apicast_ssl_cleanup_ctx(void *data)
{
  ngx_http_apiast_ctx_t *ctx = data;

  if (ctx->proxy_client_cert_chain) {
    sk_X509_pop_free(ctx->proxy_client_cert_chain, X509_free);
  }
}
