# apicast-nginx-module

Custom Nginx module that adds a few options to be able to run some special
operations on top of Openresty.

## Build

Create docker image
```
docker build -t 3scale/apicast-nginx-module .
```

Run

```
docker run --rm -v .:/opt -it 3scale/apicast-nginx-module bash
```

This module needs some updates on nginx code, all of them appended on patches/

```
make download
make patch
make compile
```

Download lua-resty-openssl
```
make openssl
```

## Examples:

**test/mtls.conf:**
Example of upstream MTLs where the certs can be set on init/access phase.

```
cd /opt/test
openresty -c /opt/test/mtls.conf
```

Run with valgrind

```
valgrind --tool=memcheck --leak-check=full --keep-debuginfo=yes --show-possibly-lost=no --gen-suppressions=all --suppressions=valgrind.suppress openresty -c /opt/test/mtls.conf
```

# Testing:
All made on APICast project
