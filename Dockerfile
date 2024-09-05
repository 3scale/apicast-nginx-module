FROM quay.io/centos/centos:stream8

ARG OPENRESTY_YUM_REPO="https://openresty.org/package/centos/openresty.repo"

COPY . /opt/

RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Stream-* \
    && sed -i 's/mirrorlist/#mirrorlist/g'  /etc/yum.repos.d/CentOS-*

RUN yum upgrade -y \
    && dnf install -y 'dnf-command(config-manager)' \
    && dnf --enablerepo=powertools install -y perl-List-MoreUtils perl-Test-LongString libyaml-devel\
    && yum install -y \
        gcc gcc-c++ make cmake git which curl expat-devel \
        openssl-devel m4 \
        perl-local-lib perl-App-cpanminus \
        libyaml wget vim valgrind valgrind-devel pcre-devel patch \
    && git clone https://github.com/ccache/ccache \
    && cd ccache \
    && mkdir build \
    && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make \
    && make install \
    && yum config-manager --add-repo ${OPENRESTY_YUM_REPO}\
    && dnf install -y \
        openresty-zlib-devel \
        openresty-openssl111-debug-devel \
        openresty-pcre2-devel \
        openresty-zlib \
        openresty-openssl111-debug \
        openresty-pcre2 \
    && yum clean all

# perl-Test-Nginx
RUN cpanm --notest IPC::Run && \
    cpanm https://cpan.metacpan.org/authors/id/A/AG/AGENT/Test-Nginx-0.29.tar.gz

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

WORKDIR /opt/
