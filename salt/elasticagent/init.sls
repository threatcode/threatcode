# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'elasticagent/map.jinja' import ELASTICAGENTMERGED %}

include:
{% if ELASTICAGENTMERGED.enabled %}
  - elasticagent.enabled
{% else %}
  - elasticagent.disabled
{% endif %}
