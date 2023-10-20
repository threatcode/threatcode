{# this state can run regardless if in allowed_states or not #}
{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
{%- set FLEETPASS = salt['pillar.get']('secrets:fleet', None) -%}
{%- set FLEETJWT = salt['pillar.get']('secrets:fleet_jwt', None) -%}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set FLEETARCH = salt['grains.get']('role') %}

{% if FLEETARCH == "tc-fleet" %}
  {% set MAININT = salt['pillar.get']('host:mainint') %}
  {% set MAINIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% else %}
  {% set MAINIP = salt['pillar.get']('global:managerip') %}
{% endif %}
{% set DNET = salt['pillar.get']('global:dockernet', '172.17.0.0') %}


include:
  - ssl
  - mysql

# Fleet Setup
fleetcdir:
  file.directory:
    - name: /opt/tc/conf/fleet/etc
    - user: 939
    - group: 939
    - makedirs: True

fleetpackcdir:
  file.directory:
    - name: /opt/tc/conf/fleet/packs
    - user: 939
    - group: 939
    - makedirs: True
    
fleetnsmdir:
  file.directory:
    - name: /nsm/osquery/fleet
    - user: 939
    - group: 939
    - makedirs: True

fleetpacksync:
  file.recurse:
    - name: /opt/tc/conf/fleet/packs
    - source: salt://fleet/files/packs
    - user: 939
    - group: 939

fleetpackagessync:
  file.recurse:
    - name: /opt/tc/conf/fleet/packages
    - source: salt://fleet/packages/
    - user: 939
    - group: 939

fleetlogdir:
  file.directory:
    - name: /opt/tc/log/fleet
    - user: 939
    - group: 939
    - makedirs: True

fleetdb:
  mysql_database.present:
    - name: fleet
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}
    - require: 
      - sls: mysql

fleetdbuser:
  mysql_user.present:
    - host: {{ DNET }}/255.255.255.0
    - password: {{ FLEETPASS }}
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}
    - require: 
      - fleetdb

fleetdbpriv:
  mysql_grants.present:
    - grant: all privileges
    - database: fleet.*
    - user: fleetdbuser
    - host: {{ DNET }}/255.255.255.0
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}
    - require: 
      - fleetdb


{% if FLEETPASS == None or FLEETJWT == None %}

fleet_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "Fleet MySQL Password or JWT Key Error - Not Starting Fleet"

{% else %}

tc-fleet:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-fleet:{{ VERSION }}
    - hostname: tc-fleet
    - port_bindings:
      - 0.0.0.0:8080:8080
    - environment:
      - FLEET_MYSQL_ADDRESS={{ MAINIP }}:3306
      - FLEET_REDIS_ADDRESS={{ MAINIP }}:6379
      - FLEET_MYSQL_DATABASE=fleet
      - FLEET_MYSQL_USERNAME=fleetdbuser
      - FLEET_MYSQL_PASSWORD={{ FLEETPASS }}
      - FLEET_SERVER_CERT=/ssl/server.cert
      - FLEET_SERVER_KEY=/ssl/server.key
      - FLEET_LOGGING_JSON=true
      - FLEET_AUTH_JWT_KEY= {{ FLEETJWT }}
      - FLEET_FILESYSTEM_STATUS_LOG_FILE=/var/log/fleet/status.log
      - FLEET_FILESYSTEM_RESULT_LOG_FILE=/var/log/osquery/result.log
      - FLEET_SERVER_URL_PREFIX=/fleet
      - FLEET_FILESYSTEM_ENABLE_LOG_ROTATION=true
      - FLEET_FILESYSTEM_ENABLE_LOG_COMPRESSION=true
    - binds:
      - /etc/pki/fleet.key:/ssl/server.key:ro
      - /etc/pki/fleet.crt:/ssl/server.cert:ro
      - /opt/tc/log/fleet:/var/log/fleet
      - /nsm/osquery/fleet:/var/log/osquery
      - /opt/tc/conf/fleet/packs:/packs
    - watch:
      - /opt/tc/conf/fleet/etc
    - require:
      - x509: fleet_key
      - x509: fleet_crt

append_tc-fleet_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-fleet

{% endif %}
