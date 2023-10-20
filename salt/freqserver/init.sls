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

# Create the user
fservergroup:
  group.present:
    - name: freqserver
    - gid: 935

# Add ES user
freqserver:
  user.present:
    - uid: 935
    - gid: 935
    - home: /opt/tc/conf/freqserver
    - createhome: False

# Create the log directory
freqlogdir:
  file.directory:
    - name: /opt/tc/log/freq_server
    - user: 935
    - group: 935
    - makedirs: True

tc-freqimage:
 cmd.run:
   - name: docker pull {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-freqserver:{{ VERSION }}

tc-freq:
  docker_container.running:
    - require:
      - tc-freqimage
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/tc-freqserver:{{ VERSION }}
    - hostname: freqserver
    - name: tc-freqserver
    - user: freqserver
    - binds:
      - /opt/tc/log/freq_server:/var/log/freq_server:rw

append_tc-freq_tc-status.conf:
  file.append:
    - name: /opt/tc/conf/tc-status/tc-status.conf
    - text: tc-freq

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}

