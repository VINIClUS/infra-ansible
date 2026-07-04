FROM python:3.12-alpine

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ANSIBLE_FORCE_COLOR=0

RUN apk add --no-cache \
        bash \
        git \
        openssh-client \
        rsync \
        sshpass \
    && pip install --no-cache-dir \
        ansible-core \
        ansible-lint \
        yamllint

COPY requirements.yml /tmp/requirements.yml

RUN ansible-galaxy collection install -r /tmp/requirements.yml

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/ansible-playbook"]
