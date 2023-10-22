# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - ssl

# Drop the correct nginx config based on role
nginxconfdir:
  file.directory:
    - name: /opt/tc/conf/nginx
    - user: 939
    - group: 939
    - makedirs: True

nginxconf:
  file.managed:
    - name: /opt/tc/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://nginx/etc/nginx.conf
    - show_changes: False

nginxlogdir:
  file.directory:
    - name: /opt/tc/log/nginx/
    - user: 939
    - group: 939
    - makedirs: True

nginxtmp:
  file.directory:
    - name: /opt/tc/tmp/nginx/tmp
    - user: 939
    - group: 939
    - makedirs: True

navigatorconfig:
  file.managed:
    - name: /opt/tc/conf/navigator/config.json
    - source: salt://nginx/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

navigatordefaultlayer:
  file.managed:
    - name: /opt/tc/conf/navigator/layers/nav_layer_playbook.json
    - source: salt://nginx/files/nav_layer_playbook.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False
    - template: jinja

navigatorpreattack:
  file.managed:
    - name: /opt/tc/conf/navigator/layers/pre-attack.json
    - source: salt://nginx/files/pre-attack.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False

navigatorenterpriseattack:
  file.managed:
    - name: /opt/tc/conf/navigator/layers/enterprise-attack.json
    - source: salt://nginx/files/enterprise-attack.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False

nginx_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://nginx/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#nginx_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://nginx/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
