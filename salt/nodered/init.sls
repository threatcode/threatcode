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

{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}

# Create the nodered group
noderedgroup:
  group.present:
    - name: nodered
    - gid: 947

# Add the nodered user
nodered:
  user.present:
    - uid: 947
    - gid: 947
    - home: /opt/tc/conf/nodered

#noderedconfdir:
#  file.directory:
#    - name: /opt/tc/conf/nodered
#    - user: 947
#    - group: 939
#    - mode: 775
#    - makedirs: True

noderedflows:
  file.recurse:
    - name: /opt/tc/saltstack/default/salt/nodered/
    - source: salt://nodered/files
    - user: 947
    - group: 939
    - template: jinja

noderedflowsload:
  file.managed:
    - name: /usr/sbin/tc-nodered-load-flows
    - source: salt://nodered/files/nodered_load_flows
    - user: root
    - group: root
    - mode: 755
    - template: jinja

noderedlog:
  file.directory:
    - name: /opt/tc/log/nodered
    - user: 947
    - group: 939
    - mode: 755
    - makedirs: True

tc-nodered:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-nodered:{{ VERSION }}
    - interactive: True
    - binds:
      - /opt/tc/conf/nodered/:/data:rw
    - port_bindings:
      - 0.0.0.0:1880:1880

append_tc-nodered_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-nodered

tc-nodered-flows:
  cmd.run:
    - name: /usr/sbin/tc-nodered-load-flows
    - cwd: /

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
