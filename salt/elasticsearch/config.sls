# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.github.io/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - ssl
  - elasticsearch.ca

{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCHMERGED %}

vm.max_map_count:
  sysctl.present:
    - value: 262144

# Add ES Group
elasticsearchgroup:
  group.present:
    - name: elasticsearch
    - gid: 930

esconfdir:
  file.directory:
    - name: /opt/tc/conf/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

# Add ES user
elasticsearch:
  user.present:
    - uid: 930
    - gid: 930
    - home: /opt/tc/conf/elasticsearch
    - createhome: False

elasticsearch_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticsearch/tools/sbin
    - user: 930
    - group: 939
    - file_mode: 755
    - exclude_pat:
      - tc-elasticsearch-pipelines # exclude this because we need to watch it for changes, we sync it in another state

elasticsearch_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticsearch/tools/sbin_jinja
    - user: 939
    - group: 939 
    - file_mode: 755
    - template: jinja
    - exclude_pat:
      - tc-elasticsearch-ilm-policy-load # exclude this because we need to watch it for changes, we sync it in another state
    - defaults:
        GLOBALS: {{ GLOBALS }}

so-elasticsearch-ilm-policy-load-script:
  file.managed:
    - name: /usr/sbin/so-elasticsearch-ilm-policy-load
    - source: salt://elasticsearch/tools/sbin_jinja/so-elasticsearch-ilm-policy-load
    - user: 930
    - group: 939
    - mode: 754
    - template: jinja

so-elasticsearch-pipelines-script:
  file.managed:
    - name: /usr/sbin/so-elasticsearch-pipelines
    - source: salt://elasticsearch/tools/sbin/so-elasticsearch-pipelines
    - user: 930
    - group: 939
    - mode: 754

esingestdir:
  file.directory:
    - name: /opt/tc/conf/elasticsearch/ingest
    - user: 930
    - group: 939
    - makedirs: True

estemplatedir:
  file.directory:
    - name: /opt/tc/conf/elasticsearch/templates/index
    - user: 930
    - group: 939
    - makedirs: True

esrolesdir:
  file.directory:
    - name: /opt/tc/conf/elasticsearch/roles
    - user: 930
    - group: 939
    - makedirs: True

eslibdir:
  file.absent:
    - name: /opt/tc/conf/elasticsearch/lib

esingestdynamicconf:
  file.recurse:
    - name: /opt/tc/conf/elasticsearch/ingest
    - source: salt://elasticsearch/files/ingest-dynamic
    - user: 930
    - group: 939
    - template: jinja

esingestconf:
  file.recurse:
    - name: /opt/tc/conf/elasticsearch/ingest
    - source: salt://elasticsearch/files/ingest
    - user: 930
    - group: 939

eslog4jfile:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/log4j2.properties
    - source: salt://elasticsearch/files/log4j2.properties
    - user: 930
    - group: 939
    - template: jinja

esyml:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/elasticsearch.yml
    - source: salt://elasticsearch/files/elasticsearch.yaml.jinja
    - user: 930
    - group: 939
    - defaults:
        ESCONFIG: {{ ELASTICSEARCHMERGED.config }}
    - template: jinja

esroles:
  file.recurse:
    - source: salt://elasticsearch/roles/
    - name: /opt/tc/conf/elasticsearch/roles/
    - clean: True
    - template: jinja
    - user: 930
    - group: 939

nsmesdir:
  file.directory:
    - name: /nsm/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

eslogdir:
  file.directory:
    - name: /opt/tc/log/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

es_repo_dir:
  file.directory:
    - name: /nsm/elasticsearch/repo/
    - user: 930
    - group: 930
    - require:
      - file: nsmesdir

so-pipelines-reload:
  file.absent:
    - name: /opt/tc/state/espipelines.txt
    - onchanges:
      - file: esingestconf
      - file: esingestdynamicconf
      - file: esyml
      - file: tc-elasticsearch-pipelines-script

auth_users:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/users.tmp
    - source: salt://elasticsearch/files/users
    - user: 930
    - group: 930
    - mode: 600
    - show_changes: False

auth_users_roles:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/users_roles.tmp
    - source: salt://elasticsearch/files/users_roles
    - user: 930
    - group: 930
    - mode: 600
    - show_changes: False

auth_users_inode:
  require:
    - file: auth_users
  cmd.run:
    - name: cat /opt/tc/conf/elasticsearch/users.tmp > /opt/tc/conf/elasticsearch/users && chown 930:939 /opt/tc/conf/elasticsearch/users && chmod 660 /opt/tc/conf/elasticsearch/users
    - onchanges:
      - file: /opt/tc/conf/elasticsearch/users.tmp

auth_users_roles_inode:
  require:
    - file: auth_users_roles
  cmd.run:
    - name: cat /opt/tc/conf/elasticsearch/users_roles.tmp > /opt/tc/conf/elasticsearch/users_roles && chown 930:939 /opt/tc/conf/elasticsearch/users_roles && chmod 660 /opt/tc/conf/elasticsearch/users_roles
    - onchanges:
      - file: /opt/tc/conf/elasticsearch/users_roles.tmp

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
