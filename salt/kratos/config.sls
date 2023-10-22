# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from "kratos/map.jinja" import KRATOSMERGED %}

# Add Kratos Group
kratosgroup:
  group.present:
    - name: kratos
    - gid: 928

# Add Kratos user
kratos:
  user.present:
    - uid: 928
    - gid: 928
    - home: /opt/tc/conf/kratos
    
kratosdir:
  file.directory:
    - name: /nsm/kratos
    - user: 928
    - group: 928
    - mode: 700
    - makedirs: True

kratosdbdir:
  file.directory:
    - name: /nsm/kratos/db
    - user: 928
    - group: 928
    - mode: 700
    - makedirs: True

kratoslogdir:
  file.directory:
    - name: /opt/tc/log/kratos
    - user: 928
    - group: 928
    - makedirs: True

kratosschema:
  file.managed:
    - name: /opt/tc/conf/kratos/schema.json
    - source: salt://kratos/files/schema.json
    - user: 928
    - group: 928
    - mode: 600

kratosconfig:
  file.managed:
    - name: /opt/tc/conf/kratos/kratos.yaml
    - source: salt://kratos/files/kratos.yaml.jinja
    - user: 928
    - group: 928
    - mode: 600
    - template: jinja
    - defaults:
        KRATOSMERGED: {{ KRATOSMERGED }}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
