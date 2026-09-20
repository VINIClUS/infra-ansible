FROM python:3.12-alpine

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ANSIBLE_FORCE_COLOR=0

RUN apk add --no-cache \
        age \
        bash \
        git \
        openssh-client \
        rsync \
        sshpass \
    && pip install --no-cache-dir \
        ansible-core \
        ansible-lint \
        yamllint \
        "boto3>=1.35.0" \
        "proxmoxer>=2.3.0" \
        "psycopg[binary]>=3.2.0" \
        "requests>=2.32.0" \
        "botocore>=1.35.0"

COPY requirements.yml /tmp/requirements.yml

RUN ansible-galaxy collection install -r /tmp/requirements.yml

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/ansible-playbook"]
