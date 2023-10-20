# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'playbook/map.jinja' import PLAYBOOKMERGED %}

include:
{% if PLAYBOOKMERGED.enabled %}
  - playbook.enabled
{% else %}
  - playbook.disabled
{% endif %}
