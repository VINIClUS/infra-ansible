FROM python:3.12-alpine

ARG TARGETARCH=amd64
ARG INFISICAL_CLI_VERSION=0.43.84

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ANSIBLE_FORCE_COLOR=0

RUN apk add --no-cache \
        bash \
        git \
        openssh-client \
        rsync \
        sshpass \
        wget \
    && pip install --no-cache-dir \
        ansible-core \
        ansible-lint \
        yamllint \
        "boto3>=1.35.0" \
        "botocore>=1.35.0" \
    && case "${TARGETARCH}" in \
        amd64) INFISICAL_SHA256="64a47155083c7b8042de64e67eee5629bf894903c102f7239f69c7ed93fdbfc5" ;; \
        arm64) INFISICAL_SHA256="28c3593bb14e4739f00058419304f6ffeb94741114efcc4208d74bdfc4ea881f" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && wget -q -O /tmp/infisical.tar.gz \
        "https://github.com/Infisical/cli/releases/download/v${INFISICAL_CLI_VERSION}/cli_${INFISICAL_CLI_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && echo "${INFISICAL_SHA256}  /tmp/infisical.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/infisical.tar.gz -C /usr/local/bin infisical \
    && chmod 0755 /usr/local/bin/infisical \
    && rm /tmp/infisical.tar.gz

COPY requirements.yml /tmp/requirements.yml

RUN ansible-galaxy collection install -r /tmp/requirements.yml

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/ansible-playbook"]
