# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set HIGHLANDER = salt['pillar.get']('global:highlander', False) %}
include:
  - kibana.enabled

dashboard_saved_objects_template:
  file.managed:
    - name: /opt/tc/conf/kibana/saved_objects.ndjson.template
    - source: salt://kibana/files/saved_objects.ndjson
    - user: 932
    - group: 939
    - show_changes: False

dashboard_saved_objects_changes:
  file.absent:
    - names:
      - /opt/tc/state/kibana_saved_objects.txt
    - onchanges:
      - file: dashboard_saved_objects_template

so-kibana-dashboard-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/tc/conf/kibana/saved_objects.ndjson.template
    - cwd: /opt/so
    - require:
      - sls: kibana.enabled
      - file: dashboard_saved_objects_template
{%- if HIGHLANDER %}
dashboard_saved_objects_template_hl:
  file.managed:
    - name: /opt/tc/conf/kibana/hl.ndjson.template
    - source: salt://kibana/files/hl.ndjson
    - user: 932
    - group: 939
    - show_changes: False

dashboard_saved_objects_hl_changes:
  file.absent:
    - names:
      - /opt/tc/state/kibana_hl.txt
    - onchanges:
      - file: dashboard_saved_objects_template_hl

so-kibana-dashboard-load_hl:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/tc/conf/kibana/hl.ndjson.template
    - cwd: /opt/so
    - require:
      - sls: kibana.enabled
      - file: dashboard_saved_objects_template_hl
{%- endif %}
