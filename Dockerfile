FROM centos:8

RUN yum upgrade -y \
    && dnf install -y 'dnf-command(config-manager)' \
    && yum config-manager --add-repo http://packages.dev.3sca.net/dev_packages_3sca_net.repo \
    && dnf --enablerepo=powertools install -y perl-List-MoreUtils perl-Test-LongString libyaml-devel\
    && yum install -y \
        gcc make git which curl expat-devel \
        perl-Test-Nginx openssl-devel m4 \
        perl-local-lib perl-App-cpanminus \
        libyaml wget vim valgrind pcre-devel


WORKDIR /opt/
COPY Makefile /opt/
WORKDIR /opt/
RUN make download
