{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - common.soup_scripts
  - common.packages
{% if GLOBALS.role in GLOBALS.manager_roles %}
  - manager.elasticsearch # needed for elastic_curl_config state
{% endif %}

net.core.wmem_default:
  sysctl.present:
    - value: 26214400

# Remove variables.txt from /tmp - This is temp
rmvariablesfile:
  file.absent:
    - name: /tmp/variables.txt

# Add socore Group
socoregroup:
  group.present:
    - name: socore
    - gid: 939

# Add socore user
socore:
  user.present:
    - uid: 939
    - gid: 939
    - home: /opt/so
    - createhome: True
    - shell: /bin/bash

soconfperms:
  file.directory:
    - name: /opt/tc/conf
    - user: 939
    - group: 939
    - dir_mode: 770

sostatusconf:
  file.directory:
    - name: /opt/tc/conf/so-status
    - user: 939
    - group: 939
    - dir_mode: 770

so-status.conf:
  file.touch:
    - name: /opt/tc/conf/so-status/so-status.conf
    - unless: ls /opt/tc/conf/so-status/so-status.conf

socore_opso_perms:
  file.directory:
    - name: /opt/so
    - user: 939
    - group: 939
    
so_log_perms:
  file.directory:
    - name: /opt/tc/log
    - dir_mode: 755

# Create a state directory
statedir:
  file.directory:
    - name: /opt/tc/state
    - user: 939
    - group: 939
    - makedirs: True

salttmp:
  file.directory:
    - name: /opt/tc/tmp
    - user: 939
    - group: 939
    - makedirs: True

# VIM config
vimconfig:
  file.managed:
    - name: /root/.vimrc
    - source: salt://common/files/vimrc
    - replace: False

# Always keep these packages up to date

alwaysupdated:
  pkg.latest:
    - pkgs:
      - openssl
      - openssh-server
      - bash
    - skip_suggestions: True

# Set time to UTC
Etc/UTC:
  timezone.system

# Sync curl configuration for Elasticsearch authentication
{% if GLOBALS.role in ['so-eval', 'so-heavynode', 'so-import', 'so-manager', 'so-managersearch', 'so-searchnode', 'so-standalone'] %}
elastic_curl_config:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/curl.config
    - source: salt://elasticsearch/curl.config
    - mode: 600
    - show_changes: False
    - makedirs: True
  {% if GLOBALS.role in GLOBALS.manager_roles %}
    - require:
      - file: elastic_curl_config_distributed
  {% endif %}
{% endif %}


common_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://common/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

common_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://common/tools/sbin_jinja
    - user: 939
    - group: 939 
    - file_mode: 755
    - template: jinja

so-status_script:
  file.managed:
    - name: /usr/sbin/so-status
    - source: salt://common/tools/sbin/so-status
    - mode: 755

{% if GLOBALS.role in GLOBALS.sensor_roles %}
# Add sensor cleanup
so-sensor-clean:
  cron.present:
    - name: /usr/sbin/so-sensor-clean
    - identifier: tc-sensor-clean
    - user: root
    - minute: '*'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{% endif %}

# Create the status directory
sostatusdir:
  file.directory:
    - name: /opt/tc/log/sostatus
    - user: 0
    - group: 0
    - makedirs: True

sostatus_log:
  file.managed:
    - name: /opt/tc/log/sostatus/status.log
    - mode: 644

# Install sostatus check cron. This is used to populate Grid.
so-status_check_cron:
  cron.present:
    - name: '/usr/sbin/so-status -j > /opt/tc/log/sostatus/status.log 2>&1'
    - identifier: tc-status_check_cron
    - user: root
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

remove_post_setup_cron:
  cron.absent:
    - name: 'PATH=$PATH:/usr/sbin salt-call state.highstate'
    - identifier: post_setup_cron

{% if GLOBALS.role not in ['eval', 'manager', 'managersearch', 'standalone'] %}

soversionfile:
  file.managed:
    - name: /etc/soversion
    - source: salt://common/files/soversion
    - mode: 644
    - template: jinja
    
{% endif %}

{% if GLOBALS.so_model and GLOBALS.so_model not in ['SO2AMI01', 'SO2AZI01', 'SO2GCI01'] %}
  {% if GLOBALS.os == 'OEL' %}     
# Install Raid tools
raidpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - threatcode-raidtools
      - threatcode-megactl
  {% endif %}

# Install raid check cron
so-raid-status:
  cron.present:
    - name: '/usr/sbin/so-raid-status > /dev/null 2>&1'
    - identifier: tc-raid-status
    - user: root
    - minute: '*/15'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

  {% endif %}
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
