{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set role = grains.id.split('_') | last %}
{% from 'elasticsearch/auth.map.jinja' import ELASTICAUTH with context %}

include:
  - common.tcup_scripts
{% if grains.role in ['tc-eval', 'tc-manager', 'tc-standalone', 'tc-managersearch', 'tc-import'] %}
  - manager.elasticsearch # needed for elastic_curl_config state
{% endif %}

# Remove variables.txt from /tmp - This is temp
rmvariablesfile:
  file.absent:
    - name: /tmp/variables.txt

dockergroup:
  group.present:
    - name: docker
    - gid: 920

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

tcstatusconf:
  file.directory:
    - name: /opt/tc/conf/tc-status
    - user: 939
    - group: 939
    - dir_mode: 770

tc-status.conf:
  file.touch:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - unless: ls /opt/tc/conf/tc-status/tc-status.conf

sosaltstackperms:
  file.directory:
    - name: /opt/tc/saltstack
    - user: 939
    - group: 939
    - dir_mode: 770

tc_log_perms:
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

# Install common packages
{% if grains['os'] != 'CentOS' %}     
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - apache2-utils
      - wget
      - ntpdate
      - jq
      - python3-docker
      - curl
      - ca-certificates
      - software-properties-common
      - apt-transport-https
      - openssl
      - netcat
      - python3-mysqldb
      - sqlite3
      - libssl-dev
      - python3-dateutil
      - python3-m2crypto
      - python3-packaging
      - python3-lxml
      - git
      - vim

heldpackages:
  pkg.installed:
    - pkgs:
    {% if grains['oscodename'] == 'bionic' %}
      - containerd.io: 1.4.4-1
      - docker-ce: 5:20.10.5~3-0~ubuntu-bionic
      - docker-ce-cli: 5:20.10.5~3-0~ubuntu-bionic
      - docker-ce-rootless-extras: 5:20.10.5~3-0~ubuntu-bionic
    {% elif grains['oscodename'] == 'focal' %}
      - containerd.io: 1.4.9-1
      - docker-ce: 5:20.10.8~3-0~ubuntu-focal
      - docker-ce-cli: 5:20.10.5~3-0~ubuntu-focal
      - docker-ce-rootless-extras: 5:20.10.5~3-0~ubuntu-focal
    {% endif %}
    - hold: True
    - update_holds: True

{% else %}
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - wget
      - ntpdate
      - bind-utils
      - jq
      - tcpdump
      - httpd-tools
      - net-tools
      - curl
      - sqlite
      - mariadb-devel
      - nmap-ncat
      - python3
      - python36-docker
      - python36-dateutil
      - python36-m2crypto
      - python36-packaging
      - python36-lxml
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - vim-enhanced

heldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.4.4-3.1.el7
      - docker-ce: 3:20.10.5-3.el7
      - docker-ce-cli: 1:20.10.5-3.el7
      - docker-ce-rootless-extras: 20.10.5-3.el7
      - python36-mysql: 1.3.12-2.el7
    - hold: True
    - update_holds: True
{% endif %}

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

{% if salt['pillar.get']('elasticsearch:auth:enabled', False) %}
elastic_curl_config:
  file.managed:
    - name: /opt/tc/conf/elasticsearch/curl.config
    - source: salt://elasticsearch/curl.config
    - mode: 600
    - show_changes: False
    - makedirs: True
  {% if grains.role in ['tc-eval', 'tc-manager', 'tc-standalone', 'tc-managersearch', 'tc-import'] %}
    - require:
      - file: elastic_curl_config_distributed
  {% endif %}
{% endif %}

# Sync some Utilities
utilsyncscripts:
  file.recurse:
    - name: /usr/sbin
    - user: root
    - group: root
    - file_mode: 755
    - template: jinja
    - source: salt://common/tools/sbin
    - defaults:
        ELASTICCURL: 'curl'
    - context:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}
    - exclude_pat:
        - tc-common
        - tc-firewall
        - tc-image-common
        - tcup

{% if role in ['eval', 'standalone', 'sensor', 'heavynode'] %}
# Add sensor cleanup
/usr/sbin/tc-sensor-clean:
  cron.present:
    - user: root
    - minute: '*'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

sensorrotatescript:
  file.managed:
    - name: /usr/local/bin/sensor-rotate
    - source: salt://common/cron/sensor-rotate
    - mode: 755

sensorrotateconf:
  file.managed:
    - name: /opt/tc/conf/sensor-rotate.conf
    - source: salt://common/files/sensor-rotate.conf
    - mode: 644

/usr/local/bin/sensor-rotate:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% endif %}

commonlogrotatescript:
  file.managed:
    - name: /usr/local/bin/common-rotate
    - source: salt://common/cron/common-rotate
    - mode: 755

commonlogrotateconf:
  file.managed:
    - name: /opt/tc/conf/log-rotate.conf
    - source: salt://common/files/log-rotate.conf
    - template: jinja
    - mode: 644

/usr/local/bin/common-rotate:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

# Create the status directory
tcstatusdir:
  file.directory:
    - name: /opt/tc/log/tcstatus
    - user: 0
    - group: 0
    - makedirs: True

tcstatus_log:
  file.managed:
    - name: /opt/tc/log/tcstatus/status.log
    - mode: 644
    
# Install tcstatus check cron
'/usr/sbin/tc-status -q; echo $? > /opt/tc/log/tcstatus/status.log 2>&1':
  cron.present:
    - user: root
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% if role in ['eval', 'manager', 'managersearch', 'standalone'] %}
# Install cron job to determine size of influxdb for telegraf
'du -s -k /nsm/influxdb | cut -f1 > /opt/tc/log/telegraf/influxdb_size.log 2>&1':
  cron.present:
    - user: root
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
    
# Lock permissions on the backup directory
backupdir:
  file.directory:
    - name: /nsm/backup
    - user: 0
    - group: 0
    - makedirs: True
    - mode: 700
  
# Add config backup
/usr/sbin/tc-config-backup > /dev/null 2>&1:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{% else %}
soversionfile:
  file.managed:
    - name: /etc/soversion
    - source: salt://common/files/soversion
    - mode: 644
    - template: jinja
    
{% endif %}

# Manager daemon.json
docker_daemon:
  file.managed:
    - source: salt://common/files/daemon.json
    - name: /etc/docker/daemon.json
    - template: jinja 

# Make sure Docker is always running
docker:
  service.running:
    - enable: True
    - watch:
      - file: docker_daemon

# Reserve OS ports for Docker proxy in case boot settings are not already applied/present
# 55000 = Wazuh, 57314 = Strelka, 47760-47860 = Zeek
dockerapplyports:
    cmd.run:
      - name: if [ ! -s /etc/sysctl.d/99-reserved-ports.conf ]; then sysctl -w net.ipv4.ip_local_reserved_ports="55000,57314,47760-47860"; fi

# Reserve OS ports for Docker proxy
dockerreserveports:
  file.managed:
    - source: salt://common/files/99-reserved-ports.conf
    - name: /etc/sysctl.d/99-reserved-ports.conf

{% if salt['grains.get']('sosmodel', '') %}
  {% if grains['os'] == 'CentOS' %}     
# Install Raid tools
raidpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - threatcode-raidtools
      - threatcode-megactl
  {% endif %}

# Install raid check cron
/usr/sbin/tc-raid-status > /dev/null 2>&1:
  cron.present:
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
