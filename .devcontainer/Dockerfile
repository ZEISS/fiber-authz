# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.238.1/containers/ubuntu/.devcontainer/base.Dockerfile

# [Choice] Ubuntu version (use ubuntu-22.04 or ubuntu-18.04 on local arm64/Apple Silicon): ubuntu-22.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="jammy"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

# zScaler certificate, for all busy engineers
ADD zscaler.pem /usr/local/share/ca-certificates/zscaler.crt
RUN sudo chmod 644 /usr/local/share/ca-certificates/zscaler.crt && sudo update-ca-certificates

# zScaler certificate, for all busy engineers
ADD zscaler.pem /usr/local/share/ca-certificates/zscaler.crt
RUN sudo chmod 644 /usr/local/share/ca-certificates/zscaler.crt && sudo update-ca-certificates

# Set the environment variable NODE_EXTRA_CA_CERTS to the zScaler certificate
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/zscaler.crt

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install protobuf-compiler