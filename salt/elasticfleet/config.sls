# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if sls.split('.')[0] in allowed_states %}

# Add EA Group
elasticfleetgroup:
  group.present:
    - name: elastic-fleet
    - gid: 947

# Add EA user
elastic-fleet:
  user.present:
    - uid: 947
    - gid: 947
    - home: /opt/tc/conf/elastic-fleet
    - createhome: False

elasticfleet_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin
    - user: 947
    - group: 939
    - file_mode: 755

elasticfleet_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin_jinja
    - user: 947
    - group: 939 
    - file_mode: 755
    - template: jinja
    - exclude_pat:
      - tc-elastic-fleet-package-upgrade # exclude this because we need to watch it for changes

eaconfdir:
  file.directory:
    - name: /opt/tc/conf/elastic-fleet
    - user: 947
    - group: 939
    - makedirs: True

ealogdir:
  file.directory:
    - name: /opt/tc/log/elasticfleet
    - user: 947
    - group: 939
    - makedirs: True

eastatedir:
  file.directory:
    - name: /opt/tc/conf/elastic-fleet/state
    - user: 947
    - group: 939
    - makedirs: True

eapackageupgrade:
  file.managed:
    - name: /usr/sbin/so-elastic-fleet-package-upgrade
    - source: salt://elasticfleet/tools/sbin_jinja/so-elastic-fleet-package-upgrade
    - user: 947
    - group: 939
    - template: jinja

{%   if GLOBALS.role != "so-fleet" %}
eaintegrationsdir:
  file.directory:
    - name: /opt/tc/conf/elastic-fleet/integrations
    - user: 947
    - group: 939
    - makedirs: True

eadynamicintegration:
  file.recurse:
    - name: /opt/tc/conf/elastic-fleet/integrations
    - source: salt://elasticfleet/files/integrations-dynamic
    - user: 947
    - group: 939
    - template: jinja

eaintegration:
  file.recurse:
    - name: /opt/tc/conf/elastic-fleet/integrations
    - source: salt://elasticfleet/files/integrations
    - user: 947
    - group: 939

ea-integrations-load:
  file.absent:
    - name: /opt/tc/state/eaintegrations.txt
    - onchanges:
      - file: eaintegration
      - file: eadynamicintegration
      - file: eapackageupgrade
{% endif %}
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
