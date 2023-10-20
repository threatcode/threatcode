# Copyright 2014-2023 Threat Code Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
  {% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
  {% set MANAGER = salt['grains.get']('master') %}
  {% set MANAGERIP = salt['pillar.get']('global:managerip') %}

  # Logstash Section - Decide which pillar to use
  {% set lsheap = salt['pillar.get']('logstash_settings:lsheap', '') %}
  {% if grains['role'] in ['tc-eval','tc-managersearch', 'tc-manager', 'tc-standalone'] %}
    {% set freq = salt['pillar.get']('manager:freq', '0') %}
    {% set dstats = salt['pillar.get']('manager:domainstats', '0') %}
    {% set nodetype = salt['grains.get']('role', '')  %}
  {% elif grains['role'] == 'tc-helix' %}
    {% set freq = salt['pillar.get']('manager:freq', '0') %}
    {% set dstats = salt['pillar.get']('manager:domainstats', '0') %}
    {% set nodetype = salt['grains.get']('role', '')  %}
  {% endif %}

  {% set PIPELINES = salt['pillar.get']('logstash:pipelines', {}) %}
  {% set DOCKER_OPTIONS = salt['pillar.get']('logstash:docker_options', {}) %}
  {% set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}

  {% from 'logstash/map.jinja' import REDIS_NODES with context %}

include:
  - ssl
{% if grains.role not in ['tc-receiver'] %}
  - elasticsearch
{% endif %}

# Create the logstash group
logstashgroup:
  group.present:
    - name: logstash
    - gid: 931

# Add the logstash user for the jog4j settings
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/tc/conf/logstash

lslibdir:
  file.absent:
    - name: /opt/tc/conf/logstash/lib

lsetcdir:
  file.directory:
    - name: /opt/tc/conf/logstash/etc
    - user: 931
    - group: 939
    - makedirs: True

lspipelinedir:
  file.directory:
    - name: /opt/tc/conf/logstash/pipelines
    - user: 931
    - group: 939

  {% for PL in PIPELINES %}
    {% for CONFIGFILE in PIPELINES[PL].config %}
ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
      {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/tc/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
      {% else %}
    - name: /opt/tc/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1]}}
      {% endif %}
    - user: 931
    - group: 939
    - mode: 660
    - makedirs: True
    - show_changes: False
    {% endfor %}

ls_pipeline_{{PL}}:
  file.directory:
    - name: /opt/tc/conf/logstash/pipelines/{{PL}}
    - user: 931
    - group: 939
    - require:
    {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
    - clean: True

  {% endfor %}

lspipelinesyml:
  file.managed:
    - name: /opt/tc/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        pipelines: {{ PIPELINES }}

# Copy down all the configs
lsetcsync:
  file.recurse:
    - name: /opt/tc/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - clean: True
    - exclude_pat: pipelines*

# Create the import directory
importdir:
  file.directory:
    - name: /nsm/import
    - user: 931
    - group: 939
    - makedirs: True

# Create the logstash data directory
nsmlsdir:
  file.directory:
    - name: /nsm/logstash/tmp
    - user: 931
    - group: 939
    - makedirs: True

# Create the log directory
lslogdir:
  file.directory:
    - name: /opt/tc/log/logstash
    - user: 931
    - group: 939
    - makedirs: True

tc-logstash:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-logstash:{{ VERSION }}
    - hostname: tc-logstash
    - name: tc-logstash
    - user: logstash
    - extra_hosts: {{ REDIS_NODES }}
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    - port_bindings:
  {% for BINDING in DOCKER_OPTIONS.port_bindings %}
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
  {% if grains['role'] in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import', 'tc-heavynode', 'tc-receiver'] %}
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
  {% endif %}
  {% if grains['role'] in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import'] %}
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
  {% else %}
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/ca.crt:ro
  {% endif %}
  {% if grains.role in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import', 'tc-heavynode', 'tc-node'] %}
      - /opt/tc/conf/ca/cacerts:/etc/pki/ca-trust/extracted/java/cacerts:ro
      - /opt/tc/conf/ca/tls-ca-bundle.pem:/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:ro
  {% endif %}
  {%- if grains['role'] == 'tc-eval' %}
      - /nsm/zeek:/nsm/zeek:ro
      - /nsm/suricata:/suricata:ro
      - /nsm/wazuh/logs/alerts:/wazuh/alerts:ro
      - /nsm/wazuh/logs/archives:/wazuh/archives:ro
      - /opt/tc/log/fleet/:/osquery/logs:ro
      - /opt/tc/log/strelka:/strelka:ro
  {%- endif %}
    - watch:
      - file: lsetcsync
  {% for PL in PIPELINES %}
      - file: ls_pipeline_{{PL}}
    {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
  {% endfor %}
    - require:
  {% if grains['role'] in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import', 'tc-heavynode', 'tc-receiver'] %}
      - x509: etc_filebeat_crt
  {% endif %}
  {% if grains['role'] in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import'] %}
      - x509: pki_public_ca_crt
  {% else %}
      - x509: trusttheca
  {% endif %}
  {% if grains.role in ['tc-manager', 'tc-helix', 'tc-managersearch', 'tc-standalone', 'tc-import'] %}
      - file: cacertz
      - file: capemz
  {% endif %}

append_tc-logstash_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-logstash

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
