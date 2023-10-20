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

{% from "zeek/map.jinja" import ZEEKOPTIONS with context %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set BPF_ZEEK = salt['pillar.get']('zeek:bpf', {}) %}
{% set BPF_STATUS = 0  %}
{% set INTERFACE = salt['pillar.get']('sensor:interface', 'bond0') %}

{% set ZEEK = salt['pillar.get']('zeek', {}) %}

# Zeek Salt State

# Add Zeek group
zeekgroup:
  group.present:
    - name: zeek
    - gid: 937

# Add Zeek User
zeek:
  user.present:
    - uid: 937
    - gid: 937
    - home: /home/zeek

# Create some directories
zeekpolicydir:
  file.directory:
    - name: /opt/tc/conf/zeek/policy
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Log Directory
zeeklogdir:
  file.directory:
    - name: /nsm/zeek/logs
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Spool Directory
zeekspooldir:
  file.directory:
    - name: /nsm/zeek/spool/manager
    - user: 937
    - makedirs: True

# Zeek extracted
zeekextractdir:
  file.directory:
    - name: /nsm/zeek/extracted
    - user: 937
    - group: 939
    - mode: 770
    - makedirs: True

zeekextractcompletedir:
  file.directory:
    - name: /nsm/zeek/extracted/complete
    - user: 937
    - group: 939
    - mode: 770
    - makedirs: True

# Sync the policies
zeekpolicysync:
  file.recurse:
    - name: /opt/tc/conf/zeek/policy
    - source: salt://zeek/policy
    - user: 937
    - group: 939
    - template: jinja

# Ensure the zeek spool tree (and state.db) ownership is correct
zeekspoolownership:
  file.directory:
    - name: /nsm/zeek/spool
    - user: 937
zeekstatedbownership:
  file.managed:
    - name: /nsm/zeek/spool/state.db
    - user: 937
    - replace: False
    - create: False

# Sync Intel
zeekintelloadsync:
  file.managed:
    - name: /opt/tc/conf/policy/intel/__load__.zeek
    - source: salt://zeek/policy/intel/__load__.zeek
    - user: 937
    - group: 939
    - makedirs: True

zeekctlcfg:
  file.managed:
    - name: /opt/tc/conf/zeek/zeekctl.cfg
    - source: salt://zeek/files/zeekctl.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        ZEEKCTL: {{ ZEEK.zeekctl | tojson }}

# Sync node.cfg
nodecfg:
  file.managed:
    - name: /opt/tc/conf/zeek/node.cfg
    - source: salt://zeek/files/node.cfg
    - user: 937
    - group: 939
    - template: jinja

networkscfg:
  file.managed:
    - name: /opt/tc/conf/zeek/networks.cfg
    - source: salt://zeek/files/networks.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja

#zeekcleanscript:
#  file.managed:
#    - name: /usr/local/bin/zeek_clean
#    - source: salt://zeek/cron/zeek_clean
#    - mode: 755

#/usr/local/bin/zeek_clean:
#  cron.present:
#    - user: root
#    - minute: '*'
#    - hour: '*'
#    - daymonth: '*'
#    - month: '*'
#    - dayweek: '*'

plcronscript:
  file.managed:
    - name: /usr/local/bin/packetloss.sh
    - source: salt://zeek/cron/packetloss.sh
    - mode: 755

zeekpacketlosscron:
  cron.{{ZEEKOPTIONS.pl_cron_state}}:
    - name: /usr/local/bin/packetloss.sh
    - user: root
    - minute: '*/10'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

# BPF compilation and configuration
{% if BPF_ZEEK %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/tc-bpf-compile', INTERFACE + ' ' + BPF_ZEEK|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
       {% set BPF_STATUS = 1  %}
  {% else  %}
zeekbpfcompilationfailure:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "BPF Syntax Error - Discarding Specified BPF"
   {% endif %}
{% endif %}

zeekbpf:
  file.managed:
    - name: /opt/tc/conf/zeek/bpf
    - user: 940
    - group: 940
{% if BPF_STATUS %}
    - contents_pillar: zeek:bpf
{% else %}
    - contents:
      - "ip or not ip"
{% endif %}


localzeek:
  file.managed:
    - name: /opt/tc/conf/zeek/local.zeek
    - source: salt://zeek/files/local.zeek.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        LOCAL: {{ ZEEK.local | tojson }}

tc-zeek:
  docker_container.{{ ZEEKOPTIONS.status }}:
  {% if ZEEKOPTIONS.status == 'running' %}
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-zeek:{{ VERSION }}
    - start: {{ ZEEKOPTIONS.start }}
    - privileged: True
    - ulimits:
      - core=0
    - binds:
      - /nsm/zeek/logs:/nsm/zeek/logs:rw
      - /nsm/zeek/spool:/nsm/zeek/spool:rw
      - /nsm/zeek/extracted:/nsm/zeek/extracted:rw
      - /opt/tc/conf/zeek/local.zeek:/opt/zeek/share/zeek/site/local.zeek:ro
      - /opt/tc/conf/zeek/node.cfg:/opt/zeek/etc/node.cfg:ro
      - /opt/tc/conf/zeek/networks.cfg:/opt/zeek/etc/networks.cfg:ro
      - /opt/tc/conf/zeek/zeekctl.cfg:/opt/zeek/etc/zeekctl.cfg:ro
      - /opt/tc/conf/zeek/policy/threatcode:/opt/zeek/share/zeek/policy/threatcode:ro
      - /opt/tc/conf/zeek/policy/custom:/opt/zeek/share/zeek/policy/custom:ro
      - /opt/tc/conf/zeek/policy/cve-2020-0601:/opt/zeek/share/zeek/policy/cve-2020-0601:ro
      - /opt/tc/conf/zeek/policy/intel:/opt/zeek/share/zeek/policy/intel:rw
      - /opt/tc/conf/zeek/bpf:/opt/zeek/etc/bpf:ro 
    - network_mode: host
    - watch:
      - file: /opt/tc/conf/zeek/local.zeek
      - file: /opt/tc/conf/zeek/node.cfg
      - file: /opt/tc/conf/zeek/networks.cfg
      - file: /opt/tc/conf/zeek/zeekctl.cfg
      - file: /opt/tc/conf/zeek/policy
      - file: /opt/tc/conf/zeek/bpf
    - require:
      - file: localzeek
      - file: nodecfg
      - file: zeekctlcfg
      - file: zeekbpf
  {% else %} {# if Zeek isn't enabled, then stop and remove the container #}
    - force: True
  {% endif %}

append_tc-zeek_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-zeek
    - unless: grep -q tc-zeek /opt/tc/conf/tc-status/tc-status.conf

  {% if not ZEEKOPTIONS.start %}
tc-zeek_tc-status.disabled:
  file.comment:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - regex: ^tc-zeek$
  {% else %}
delete_tc-zeek_tc-status.disabled:
  file.uncomment:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - regex: ^tc-zeek$
  {% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
