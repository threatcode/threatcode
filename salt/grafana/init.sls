{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set ADMINPASS = salt['pillar.get']('secrets:grafana_admin') %}

{% import_yaml 'grafana/defaults.yaml' as default_settings %}
{% set GRAFANA_SETTINGS = salt['grains.filter_by'](default_settings, default='grafana', merge=salt['pillar.get']('grafana', {})) %}

{% if grains['role'] in ['tc-manager', 'tc-managersearch', 'tc-standalone'] or (grains.role == 'tc-eval' and GRAFANA == 1) %}

{% set ALLOWED_DASHBOARDS = ['overview', 'standalone', 'manager', 'managersearch', 'sensor', 'searchnode', 'heavynode', 'eval', 'receiver'] %}
{% set DASHBOARDS = ['overview'] %}
{% if grains.role == 'tc-eval' %}
  {% do DASHBOARDS.append('eval') %}
{% else %}
  {% if not salt['pillar.get']('elasticsearch:true_cluster', False) %}
    {% do DASHBOARDS.append('pipeline_overview_nontc') %}
  {% else %}
    {% do DASHBOARDS.append('pipeline_overview_tc') %}
  {% endif %}
  {# Grab a unique listing of nodetypes that exists so that we create only the needed dashboards #}
  {% for dashboard in salt['cmd.shell']("ls /opt/tc/saltstack/local/pillar/minions/|awk -F'_' {'print $2'}|awk -F'.' {'print $1'}").split() %}
    {% if dashboard in ALLOWED_DASHBOARDS %}
      {% do DASHBOARDS.append(dashboard) %}
    {% endif %}
  {% endfor %}
{% endif %}



# Grafana all the things
grafanadir:
  file.directory:
    - name: /nsm/grafana
    - user: 939
    - group: 939
    - makedirs: True

grafanaconfdir:
  file.directory:
    - name: /opt/tc/conf/grafana/etc
    - user: 939
    - group: 939
    - makedirs: True

grafanadashdir:
  file.directory:
    - name: /opt/tc/conf/grafana/grafana_dashboards
    - user: 939
    - group: 939
    - makedirs: True

{% for type in ['eval','manager','managersearch','search_nodes','sensor_nodes','standalone'] %}
remove_dashboard_dir_{{type}}:
  file.absent:
    - name: /opt/tc/conf/grafana/grafana_dashboards/{{type}}
{% endfor %}

grafana-dashboard-config:
  file.managed:
    - name: /opt/tc/conf/grafana/etc/dashboards/dashboard.yml
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/dashboards/dashboard.yml
    - makedirs: True


grafana-datasources-config:
  file.managed:
    - name: /opt/tc/conf/grafana/etc/datasources/influxdb.yaml
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/datasources/influxdb.yaml
    - makedirs: True

grafana-config:
  file.managed:
    - name: /opt/tc/conf/grafana/etc/grafana.ini
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/grafana.ini.jinja
    - context:
        config: {{ GRAFANA_SETTINGS.config|json }}

# these are the files that are referenced inside the config such as smtp:cert_file, smtp:cert_key, auth.ldap:config_file, enterprise:license_path
grafana-config-files:
  file.recurse:
    - name: /opt/tc/conf/grafana/etc/files
    - user: 939
    - group: 939
    - source: salt://grafana/etc/files
    - makedirs: True

tc-grafana-dashboard-folder-delete:
  cmd.run:
    - name: /usr/sbin/tc-grafana-dashboard-folder-delete
    - unless: ls /opt/tc/state/tc-grafana-dashboard-folder-delete-complete

{% for dashboard in DASHBOARDS | unique %}
{{dashboard}}-dashboard:
  file.managed:
    - name: /opt/tc/conf/grafana/grafana_dashboards/{{dashboard}}.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/common_template.json.jinja
    - defaults:
        DASHBOARD: {{ dashboard }}
        PANELS: {{GRAFANA_SETTINGS.dashboards[dashboard].panels}}
        TEMPLATES: {{GRAFANA_SETTINGS.dashboards[dashboard].templating.list}}
        TITLE: {{ GRAFANA_SETTINGS.dashboards[dashboard].get('title', dashboard| capitalize) }}
        ID: {{ loop.index }}
{% endfor %}

tc-grafana:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-grafana:{{ VERSION }}
    - hostname: grafana
    - user: socore
    - binds:
      - /nsm/grafana:/var/lib/grafana:rw
      - /opt/tc/conf/grafana/etc/grafana.ini:/etc/grafana/grafana.ini:ro
      - /opt/tc/conf/grafana/etc/datasources:/etc/grafana/provisioning/datasources:rw
      - /opt/tc/conf/grafana/etc/dashboards:/etc/grafana/provisioning/dashboards:rw
      - /opt/tc/conf/grafana/grafana_dashboards:/etc/grafana/grafana_dashboards:rw
      - /opt/tc/conf/grafana/etc/files:/etc/grafana/config/files:ro
    - environment:
      - GF_SECURITY_ADMIN_PASSWORD={{ ADMINPASS }}
    - port_bindings:
      - 0.0.0.0:3000:3000
    - watch:
      - file: /opt/tc/conf/grafana/*
    - require:
      - file: grafana-config

append_tc-grafana_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-grafana

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
