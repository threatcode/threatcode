# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{%   from 'elastalert/map.jinja' import ELASTALERTMERGED %}

# Create the group
elastagroup:
  group.present:
    - name: elastalert
    - gid: 933

# Add user
elastalert:
  user.present:
    - uid: 933
    - gid: 933
    - home: /opt/tc/conf/elastalert
    - createhome: False

elastalogdir:
  file.directory:
    - name: /opt/tc/log/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastalert_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elastalert/tools/sbin
    - user: 933
    - group: 939
    - file_mode: 755

#elastalert_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://elastalert/tools/sbin_jinja
#    - user: 933
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

elastarules:
  file.directory:
    - name: /opt/tc/rules/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastaconfdir:
  file.directory:
    - name: /opt/tc/conf/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastasomodulesdir:
  file.directory:
    - name: /opt/tc/conf/elastalert/modules/so
    - user: 933
    - group: 933
    - makedirs: True

elastacustmodulesdir:
  file.directory:
    - name: /opt/tc/conf/elastalert/modules/custom
    - user: 933
    - group: 933
    - makedirs: True

elastasomodulesync:
  file.recurse:
    - name: /opt/tc/conf/elastalert/modules/so
    - source: salt://elastalert/files/modules/so
    - user: 933
    - group: 933
    - makedirs: True

elastaconf:
  file.managed:
    - name: /opt/tc/conf/elastalert/elastalert_config.yaml
    - source: salt://elastalert/files/elastalert_config.yaml.jinja
    - context:
        elastalert_config: {{ ELASTALERTMERGED.config }}
    - user: 933
    - group: 933
    - mode: 660
    - template: jinja
    - show_changes: False

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
