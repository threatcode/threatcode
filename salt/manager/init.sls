# Copyright 2014-2023 Threat Code Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set STRELKA_RULES = salt['pillar.get']('strelka:rules', '1') %}

include:
  - salt.minion
  - kibana.secrets
  - manager.sync_es_users
  - manager.elasticsearch

socore_own_saltstack:
  file.directory:
    - name: /opt/tc/saltstack
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

/opt/tc/saltstack/default/pillar/data/addtotab.sh:
  file.managed:
    - mode: 750
    - replace: False

# Create the directories for apt-cacher-ng
aptcacherconfdir:
  file.directory:
    - name: /opt/tc/conf/aptcacher-ng/etc
    - user: 939
    - group: 939
    - makedirs: True

aptcachercachedir:
  file.directory:
    - name: /opt/tc/conf/aptcacher-ng/cache
    - user: 939
    - group: 939
    - makedirs: True

aptcacherlogdir:
  file.directory:
    - name: /opt/tc/log/aptcacher-ng
    - user: 939
    - group: 939
    - makedirs: true

acngconf:
  file.managed:
    - name: /opt/tc/conf/aptcacher-ng/etc/acng.conf
    - source: salt://manager/files/acng/acng.conf
    - template: jinja
    - show_changes: False

# Install the apt-cacher-ng container
tc-aptcacherng:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-acng:{{ VERSION }}
    - hostname: tc-acng
    - restart_policy: always
    - port_bindings:
      - 0.0.0.0:3142:3142
    - binds:
      - /opt/tc/conf/aptcacher-ng/cache:/var/cache/apt-cacher-ng:rw
      - /opt/tc/log/aptcacher-ng:/var/log/apt-cacher-ng:rw
      - /opt/tc/conf/aptcacher-ng/etc/acng.conf:/etc/apt-cacher-ng/acng.conf:ro
    - require:
      - file: acngconf

append_tc-aptcacherng_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-aptcacherng

strelka_yara_update_old_1:
  cron.absent:
    - user: root
    - name: '[ -d /opt/tc/saltstack/default/salt/strelka/rules/ ] && /usr/sbin/tc-yara-update > /dev/null 2>&1'
    - hour: '7'
    - minute: '1'

strelka_yara_update_old_2:
  cron.absent:
    - user: root
    - name: '/usr/sbin/tc-yara-update > /dev/null 2>&1'
    - hour: '7'
    - minute: '1'

strelka_yara_update:
  cron.present:
    - user: root
    - name: '/usr/sbin/tc-yara-update >> /nsm/strelka/log/yara-update.log 2>&1'
    - hour: '7'
    - minute: '1'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
