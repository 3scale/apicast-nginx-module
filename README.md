# apicast-nginx-module

Custom Nginx module that adds a few options to be able to run some special
operations on top of Openresty.

## Build

Create docker image
```
docker build -t 3scale/apicast-nginx-module .
```

This module needs some updates on nginx code, all of them appended on patches/

## Examples:

**test/mtls.conf:**
Example of upstream MTLs where the certs can be set on init/access phase.

# Testing:

All made on APICast project
