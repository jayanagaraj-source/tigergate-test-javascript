# Deliberately insecure Dockerfile for IaC/container scanner validation. Do not build for real use.
# FIX-IAC-001: mutable "latest" tag, no digest pin
FROM node:latest

# FIX-IAC-002: secrets baked into image via ARG/ENV
ARG NPM_TOKEN=npm_FIXTUREfixtureFIXTUREfixtureFIXTURE0
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV DATABASE_PASSWORD=fixture-db-password
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

# FIX-IAC-003: unpinned package install, apt lists not cleaned, sudo installed
RUN apt-get update && apt-get install -y curl wget sudo openssh-server

# FIX-IAC-004: remote script piped into shell, TLS verification off
RUN curl -k -sSL http://get.example.com/install.sh | bash
RUN wget --no-check-certificate -qO- https://example.com/setup.sh | sh

# FIX-IAC-005: ADD from a remote URL
ADD https://releases.example.com/tool.tar.gz /opt/tool.tar.gz

WORKDIR /app
# FIX-IAC-006: whole build context copied (includes .env, .git, keys)
COPY . .
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc && npm install

# FIX-IAC-007: world-writable app dir, SSH enabled, root password set
RUN chmod -R 777 /app && echo 'root:root' | chpasswd && mkdir -p /var/run/sshd

# FIX-IAC-008: SSH port and privileged port exposed
EXPOSE 22 80 3000

# FIX-IAC-009: no USER instruction — runs as root. No HEALTHCHECK.
CMD ["sh", "-c", "/usr/sbin/sshd && node src/server.js"]
