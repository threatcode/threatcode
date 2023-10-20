{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}

{% if grains['role'] in ['tc-manager', 'tc-managersearch', 'tc-standalone'] or (grains.role == 'tc-eval' and GRAFANA == 1) %}

{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% import_yaml 'influxdb/defaults.yaml' as default_settings %}
{% set influxdb = salt['grains.filter_by'](default_settings, default='influxdb', merge=salt['pillar.get']('influxdb', {})) %}
{% from 'salt/map.jinja' import PYTHON3INFLUX with context %}
{% from 'salt/map.jinja' import  PYTHONINFLUXVERSION with context %}
{% set PYTHONINFLUXVERSIONINSTALLED = salt['cmd.run']("python3 -c \"exec('try:import influxdb; print (influxdb.__version__)\\nexcept:print(\\'Module Not Found\\')')\"", python_shell=True) %}

include:
  - salt.minion
  - salt.python3-influxdb
  - ssl
  
# Influx DB
influxconfdir:
  file.directory:
    - name: /opt/tc/conf/influxdb/etc
    - makedirs: True

influxlogdir:
  file.directory:
    - name: /opt/tc/log/influxdb
    - dir_mode: 755
    - user: 939
    - group: 939
    - makedirs: True

influxdbdir:
  file.directory:
    - name: /nsm/influxdb
    - makedirs: True

influxdbconf:
  file.managed:
    - name: /opt/tc/conf/influxdb/etc/influxdb.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://influxdb/etc/influxdb.conf

tc-influxdb:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-influxdb:{{ VERSION }}
    - hostname: influxdb
    - environment:
      - INFLUXDB_HTTP_LOG_ENABLED=false
    - binds:
      - /opt/tc/log/influxdb/:/log:rw
      - /opt/tc/conf/influxdb/etc/influxdb.conf:/etc/influxdb/influxdb.conf:ro
      - /nsm/influxdb:/var/lib/influxdb:rw
      - /etc/pki/influxdb.crt:/etc/ssl/influxdb.crt:ro
      - /etc/pki/influxdb.key:/etc/ssl/influxdb.key:ro
    - port_bindings:
      - 0.0.0.0:8086:8086
    - watch:
      - file: influxdbconf
    - require:
      - file: influxdbconf
      - x509: influxdb_key
      - x509: influxdb_crt

append_tc-influxdb_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-influxdb

# We have to make sure the influxdb module is the right version prior to state run since reload_modules is bugged
{% if PYTHONINFLUXVERSIONINSTALLED == PYTHONINFLUXVERSION %}
wait_for_influxdb:
  http.query:
    - name: 'https://{{MANAGER}}:8086/query?q=SHOW+DATABASES'
    - ssl: True
    - verify_ssl: False
    - status: 200
    - timeout: 30
    - retry:
        attempts: 5
        interval: 60
    - require:
      - docker_container: tc-influxdb

telegraf_database:
  influxdb_database.present:
    - name: telegraf
    - database: telegraf
    - ssl: True
    - verify_ssl: /etc/pki/ca.crt
    - cert: ['/etc/pki/influxdb.crt', '/etc/pki/influxdb.key']
    - influxdb_host: {{ MANAGER }}
    - require:
      - docker_container: tc-influxdb
      - sls: salt.python3-influxdb
      - http: wait_for_influxdb

{% for rp in influxdb.retention_policies.keys() %}
{{rp}}_retention_policy:
  influxdb_retention_policy.present:
    - name: {{rp}}
    - database: telegraf
    - duration: {{influxdb.retention_policies[rp].duration}}
    - shard_duration: {{influxdb.retention_policies[rp].shard_duration}}
    - replication: 1
    - default: {{influxdb.retention_policies[rp].get('default', 'False')}}
    - ssl: True
    - verify_ssl: /etc/pki/ca.crt
    - cert: ['/etc/pki/influxdb.crt', '/etc/pki/influxdb.key']
    - influxdb_host: {{ MANAGER }}
    - require:
      - docker_container: tc-influxdb
      - influxdb_database: telegraf_database
      - file: influxdb_retention_policy.present_patch
      - sls: salt.python3-influxdb
{% endfor %}

{% for dest_rp in influxdb.downsample.keys() %}
  {% for measurement in influxdb.downsample[dest_rp].get('measurements', []) %}
so_downsample_{{measurement}}_cq:
  influxdb_continuous_query.present:
    - name: so_downsample_{{measurement}}_cq
    - database: telegraf
    - query: SELECT mean(*) INTO "{{dest_rp}}"."{{measurement}}" FROM "{{measurement}}" GROUP BY time({{influxdb.downsample[dest_rp].resolution}}),*
    - ssl: True
    - verify_ssl: /etc/pki/ca.crt
    - cert: ['/etc/pki/influxdb.crt', '/etc/pki/influxdb.key']
    - influxdb_host: {{ MANAGER }}
    - require:
      - docker_container: tc-influxdb
      - influxdb_database: telegraf_database
      - file: influxdb_continuous_query.present_patch
  {% endfor %}
{% endfor %}

{% endif %}
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
