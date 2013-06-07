#! /bin/bash

TAG=$1
PPA_URL=https://raw.github.com/edx/edx-platform/${TAG}/requirements/system/ubuntu/apt-repos.txt
PACKAGE_URL=https://raw.github.com/edx/edx-platform/${TAG}/requirements/system/ubuntu/apt-packages.txt

echo "
FROM base

# Fix up initctl (as per https://www.nesono.com/node/368)
RUN dpkg-divert --local --rename --add /sbin/initctl
RUN ln -s /bin/true /sbin/initctl

RUN apt-get install -y software-properties-common
RUN apt-get install -y curl
"

#for PPA in $(curl --silent $PPA_URL); do
#    echo "RUN add-apt-repository -y $PPA"
#done
echo "RUN echo" $(curl --silent $PPA_URL) "| xargs -n1 add-apt-repository -y"

echo "
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update
"

#for PACKAGE in $(curl --silent $PACKAGE_URL | head -n 30); do
#    echo "RUN apt-get install -y $PACKAGE"
#done
echo "RUN echo" $(curl --silent $PACKAGE_URL) "| xargs apt-get install -y"

echo "
RUN apt-get install -y ruby1.9.1
RUN gem install bundler
RUN mkdir /opt/wwc && curl https://codeload.github.com/edx/edx-platform/tar.gz/${TAG} | tar -xz -C /opt/wwc --transform 's/edx-platform-[^\/]*/edx-platform/'
RUN cd /opt/wwc/edx-platform; bundle install; rake install_prereqs
CMD django-admin.py runserver --pythonpath=/opt/wwc/edx-platform --settings=lms.envs.dev
"