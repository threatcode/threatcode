# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'logstash/map.jinja' import LOGSTASH_MERGED %}
{%   set ASSIGNED_PIPELINES = LOGSTASH_MERGED.assigned_pipelines.roles[GLOBALS.role.split('-')[1]] %}

include:
  - ssl
  {% if GLOBALS.role not in ['so-receiver','so-fleet'] %}
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

logstash_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://logstash/tools/sbin
    - user: 931
    - group: 939
    - file_mode: 755

#logstash_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://logstash/tools/sbin_jinja
#    - user: 931
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

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

{% for assigned_pipeline in ASSIGNED_PIPELINES %}
    {% for CONFIGFILE in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
ls_pipeline_{{assigned_pipeline}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
      {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/tc/conf/logstash/pipelines/{{assigned_pipeline}}/{{CONFIGFILE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}
        ES_USER: "{{ salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:user', '') }}"
        ES_PASS: "{{ salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:pass', '') }}"
        THREADS: {{ LOGSTASH_MERGED.config.pipeline_x_workers }}
        BATCH: {{ LOGSTASH_MERGED.config.pipeline_x_batch_x_size }}
      {% else %}
    - name: /opt/tc/conf/logstash/pipelines/{{assigned_pipeline}}/{{CONFIGFILE.split('/')[1]}}
      {% endif %}
    - user: 931
    - group: 939
    - mode: 660
    - makedirs: True
    - show_changes: False
    {% endfor %}

ls_pipeline_{{assigned_pipeline}}:
  file.directory:
    - name: /opt/tc/conf/logstash/pipelines/{{assigned_pipeline}}
    - user: 931
    - group: 939
    - require:
    {% for CONFIGFILE in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
      - file: ls_pipeline_{{assigned_pipeline}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
    - clean: True
{% endfor %}

# Copy down all the configs
lspipelinesyml:
  file.managed:
    - name: /opt/tc/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        ASSIGNED_PIPELINES: {{ ASSIGNED_PIPELINES }}

lsetcsync:
  file.recurse:
    - name: /opt/tc/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - clean: True
    - exclude_pat: pipelines*
    - defaults:
        LOGSTASH_MERGED: {{ LOGSTASH_MERGED }}

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

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
