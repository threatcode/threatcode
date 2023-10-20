# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - kibana.config
  - kibana.sostatus

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-kibana:{{ GLOBALS.so_version }}
    - hostname: kibana
    - user: kibana
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-kibana'].ip }}
    - environment:
      - ELASTICSEARCH_HOST={{ GLOBALS.manager }}
      - ELASTICSEARCH_PORT=9200
      - MANAGER={{ GLOBALS.manager }}
      {% if DOCKER.containers['so-kibana'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-kibana'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% if DOCKER.containers['so-kibana'].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers['so-kibana'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - binds:
      - /opt/tc/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/tc/log/kibana:/var/log/kibana:rw
      - /opt/tc/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      {% if DOCKER.containers['so-kibana'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-kibana'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-kibana'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: kibanaconfig

delete_so-kibana_so-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/so-status/so-status.conf
    - regex: ^so-kibana$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
