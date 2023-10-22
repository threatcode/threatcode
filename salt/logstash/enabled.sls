# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'logstash/map.jinja' import LOGSTASH_MERGED %}
{%   from 'logstash/map.jinja' import REDIS_NODES %}
{#   we append the manager here so that it is added to extra_hosts so the heavynode can resolve it #}
{#   we cannont append in the logstash/map.jinja because then it would be added to the 0900_input_redis.conf #}
{%   if GLOBALS.role == 'so-heavynode' %}
{%     do REDIS_NODES.append({GLOBALS.manager:GLOBALS.manager_ip}) %}
{%   endif %}
{%   set lsheap = LOGSTASH_MERGED.settings.lsheap %}

include:
{%   if GLOBALS.role not in ['so-receiver','so-fleet'] %}
  - elasticsearch.ca
{%   endif %}
  - logstash.config
  - logstash.sostatus
  - ssl

so-logstash:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-logstash:{{ GLOBALS.so_version }}
    - hostname: tc-logstash
    - name: tc-logstash
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-logstash'].ip }}
    - user: logstash
    - extra_hosts: {{ REDIS_NODES }}
    {% if DOCKER.containers['so-logstash'].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers['so-logstash'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    {% if DOCKER.containers['so-logstash'].extra_env %}
      {% for XTRAENV in DOCKER.containers['so-logstash'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-logstash'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/tc/conf/elasticsearch/templates/:/templates/:ro
      - /opt/tc/conf/logstash/etc/:/usr/share/logstash/config/:ro
      - /opt/tc/conf/logstash/pipelines:/usr/share/logstash/pipelines:ro
      - /opt/tc/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/tc/log/logstash:/var/log/logstash:rw
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /opt/tc/conf/logstash/etc/certs:/usr/share/logstash/certs:ro
      {% if GLOBALS.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
      {% endif %}
      {% if GLOBALS.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import', 'so-eval','so-fleet', 'so-heavynode', 'so-receiver'] %}
      - /etc/pki/elasticfleet-logstash.crt:/usr/share/logstash/elasticfleet-logstash.crt:ro
      - /etc/pki/elasticfleet-logstash.key:/usr/share/logstash/elasticfleet-logstash.key:ro
      - /etc/pki/elasticfleet-lumberjack.crt:/usr/share/logstash/elasticfleet-lumberjack.crt:ro
      - /etc/pki/elasticfleet-lumberjack.key:/usr/share/logstash/elasticfleet-lumberjack.key:ro
      {% endif %}
      {% if GLOBALS.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
      {% else %}
      - /etc/pki/tls/certs/intca.crt:/usr/share/filebeat/ca.crt:ro
      {% endif %}
      {% if GLOBALS.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-searchnode'] %}
      - /opt/tc/conf/ca/cacerts:/etc/pki/ca-trust/extracted/java/cacerts:ro
      - /opt/tc/conf/ca/tls-ca-bundle.pem:/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:ro
      {% endif %}
      {% if GLOBALS.role == 'so-eval' %}
      - /nsm/zeek:/nsm/zeek:ro
      - /nsm/suricata:/suricata:ro
      - /opt/tc/log/fleet/:/osquery/logs:ro
      - /opt/tc/log/strelka:/strelka:ro
      {% endif %}
      {% if DOCKER.containers['so-logstash'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-logstash'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - watch:
      {% if grains['role'] in ['so-manager', 'so-eval', 'so-managersearch', 'so-standalone', 'so-import', 'so-fleet', 'so-receiver'] %}
      - x509: etc_elasticfleet_logstash_key
      - x509: etc_elasticfleet_logstash_crt
      {% endif %}
      - file: lsetcsync
      {% for assigned_pipeline in LOGSTASH_MERGED.assigned_pipelines.roles[GLOBALS.role.split('-')[1]] %}
      - file: ls_pipeline_{{assigned_pipeline}}
        {% for CONFIGFILE in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
      - file: ls_pipeline_{{assigned_pipeline}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
        {% endfor %}
      {% endfor %}
    - require:
      {% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
      - x509: etc_filebeat_crt
      {% endif %}
      {% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}
      {% if grains.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - file: cacertz
      - file: capemz
      {% endif %}

delete_so-logstash_so-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/so-status/so-status.conf
    - regex: ^so-logstash$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
