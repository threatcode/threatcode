# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - redis.config
  - redis.sostatus

so-redis:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-redis:{{ GLOBALS.so_version }}
    - hostname: tc-redis
    - user: socore
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-redis'].ip }}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-redis'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/tc/log/redis:/var/log/redis:rw
      - /opt/tc/conf/redis/etc/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - /opt/tc/conf/redis/working:/redis:rw
      - /nsm/redis/data:/data:rw
      - /etc/pki/redis.crt:/certs/redis.crt:ro
      - /etc/pki/redis.key:/certs/redis.key:ro
      {% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - /etc/pki/ca.crt:/certs/ca.crt:ro
      {% else %}
      - /etc/pki/tls/certs/intca.crt:/certs/ca.crt:ro
      {% endif %}
      {% if DOCKER.containers['so-redis'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-redis'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-redis'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-redis'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers['so-redis'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-redis'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - entrypoint: "redis-server /usr/local/etc/redis/redis.conf"
    - watch:
      - file: /opt/tc/conf/redis/etc
    - require:
      - file: redisconf
      - x509: redis_crt
      - x509: redis_key
      {% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}

delete_so-redis_so-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/so-status/so-status.conf
    - regex: ^so-redis$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
