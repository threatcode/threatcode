# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'ntp/config.map.jinja' import NTPCONFIG %}

chrony_pkg:
  pkg.installed:
    - name: chrony

chronyconf:
  file.managed:
    - name: /etc/chrony.conf
    - source: salt://ntp/chrony.conf
    - template: jinja
    - defaults:
        NTPCONFIG: {{ NTPCONFIG }}

{% if GLOBALS.os_family == 'RedHat' %}
chronyd:
{% else %}
chrony:
{% endif %}
  service.running:
    - enable: True
    - watch: 
      - file: chronyconf
    - require:
      - pkg: chrony_pkg
