# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}


include:
  - suricata.config
  - suricata.sostatus

so-suricata:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-suricata:{{ GLOBALS.so_version }}
    - privileged: True
    - environment:
      - INTERFACE={{ GLOBALS.sensor.interface }}
      {% if DOCKER.containers['so-suricata'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-suricata'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - binds:
      - /opt/tc/conf/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /opt/tc/conf/suricata/threshold.conf:/etc/suricata/threshold.conf:ro
      - /opt/tc/conf/suricata/rules:/etc/suricata/rules:ro
      - /opt/tc/log/suricata/:/var/log/suricata/:rw
      - /nsm/suricata/:/nsm/:rw
      - /nsm/suricata/extracted:/var/log/suricata//filestore:rw
      - /opt/tc/conf/suricata/bpf:/etc/suricata/bpf:ro
      {% if DOCKER.containers['so-suricata'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-suricata'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - network_mode: host
    {% if DOCKER.containers['so-suricata'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-suricata'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: suriconfig
      - file: surithresholding
      - file: /opt/tc/conf/suricata/rules/
      - file: /opt/tc/conf/suricata/bpf
    - require:
      - file: suriconfig
      - file: surithresholding
      - file: suribpf

delete_so-suricata_so-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/so-status/so-status.conf
    - regex: ^so-suricata$

# Add eve clean cron
clean_suricata_eve_files:
  cron.present:
    - name: /usr/sbin/so-suricata-eve-clean > /dev/null 2>&1
    - identifier: clean_suricata_eve_files
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
