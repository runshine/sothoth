#!/bin/bash

cd ../99-external-service/
source setup-tls-nginx.sh

setup_tls_secret "*.harbor.sothothv2.com"       "harbor-ns"    "wildcard-harbor.sothothv2.com-tls"