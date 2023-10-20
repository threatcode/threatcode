{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) %}
{%- set MANAGERIP = salt['pillar.get']('global:managerip', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('elasticsearch:mainip') %}
{% set FLEETARCH = salt['grains.get']('role') %}

{% if FLEETARCH == "tc-fleet" %}
  {% set MAININT = salt['pillar.get']('host:mainint') %}
  {% set MAINIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% else %}
  {% set MAINIP = salt['pillar.get']('global:managerip') %}
{% endif %}

# MySQL Setup
mysqlpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      {% if grains['os'] != 'CentOS' %}
        {% if grains['oscodename'] == 'bionic' %}
      - python3-mysqldb
        {% elif grains['oscodename'] == 'focal' %}
      - python3-mysqldb
        {% endif %}
      {% else %}
      - MySQL-python
      {% endif %}

mysqletcdir:
  file.directory:
    - name: /opt/tc/conf/mysql/etc
    - user: 939
    - group: 939
    - makedirs: True

mysqlpiddir:
  file.directory:
    - name: /opt/tc/conf/mysql/pid
    - user: 939
    - group: 939
    - makedirs: True

mysqlcnf:
  file.managed:
    - name: /opt/tc/conf/mysql/etc/my.cnf
    - source: salt://mysql/etc/my.cnf
    - user: 939
    - group: 939

mysqlpass:
  file.managed:
    - name: /opt/tc/conf/mysql/etc/mypass
    - source: salt://mysql/etc/mypass
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        MYSQLPASS: {{ MYSQLPASS }}

mysqllogdir:
  file.directory:
    - name: /opt/tc/log/mysql
    - user: 939
    - group: 939
    - makedirs: True

mysqldatadir:
  file.directory:
    - name: /nsm/mysql
    - user: 939
    - group: 939
    - makedirs: True

{% if MYSQLPASS == None %}

mysql_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "MySQL Password Error - Not Starting MySQL"

{% else %}

tc-mysql:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-mysql:{{ VERSION }}
    - hostname: tc-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
      - MYSQL_ROOT_HOST={{ MAINIP }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/tc/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/tc/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/tc/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/tc/conf/mysql/etc
    - require:
      - file: mysqlcnf
      - file: mysqlpass
  cmd.run:
    - name: until nc -z {{ MAINIP }} 3306; do sleep 1; done
    - timeout: 600
    - onchanges:
      - docker_container: tc-mysql
  module.run:
    - so.mysql_conn:
      - retry: 300
    - onchanges:
      - cmd: tc-mysql

append_tc-mysql_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-mysql

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
