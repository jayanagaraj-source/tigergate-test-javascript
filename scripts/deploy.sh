#!/usr/bin/env bash
# Deliberately insecure deploy script for scanner validation. Do not run.
set -e

# FIX-SEC-017: credentials exported in a shell script
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export DOCKER_PASSWORD="dockerhub-fixture-password"
DB_PASS='root-fixture-pw'

# FIX-IAC-060: piping remote content straight into a shell
curl -sSL http://get.example.com/install.sh | sh
# FIX-IAC-061: TLS verification disabled on download
wget --no-check-certificate https://releases.example.com/tool.tar.gz -O /tmp/tool.tar.gz
# FIX-IAC-062: world-writable permissions
chmod -R 777 /opt/app
# FIX-SAST-070: eval of interpolated input
eval "mysql -uroot -p$DB_PASS -e '$1'"
# FIX-SEC-018: password on the command line (visible in process list / history)
echo "$DOCKER_PASSWORD" | docker login -u fixture --password-stdin
mysql -u root --password=$DB_PASS app < schema.sql
