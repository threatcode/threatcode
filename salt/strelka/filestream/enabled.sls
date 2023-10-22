# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - strelka.filestream.config
  - strelka.filestream.sostatus

strelka_filestream:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-filestream:{{ GLOBALS.so_version }}
    - binds:
      - /opt/tc/conf/strelka/filestream/:/etc/strelka/:ro
      - /nsm/strelka:/nsm/strelka
      {% if DOCKER.containers['so-strelka-filestream'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-strelka-filestream'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - name: tc-strelka-filestream
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-strelka-filestream'].ip }}
    - command: strelka-filestream
    - extra_hosts:
      - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
      {% if DOCKER.containers['so-strelka-filestream'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-strelka-filestream'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-strelka-filestream'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-strelka-filestream'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}

delete_so-strelka-filestream_so-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/so-status/so-status.conf
    - regex: ^so-strelka-filestream$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
