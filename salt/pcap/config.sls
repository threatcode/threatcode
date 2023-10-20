# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from "pcap/config.map.jinja" import PCAPMERGED %}
{% from 'bpf/pcap.map.jinja' import PCAPBPF %}

{% set BPF_COMPILED = "" %}

# PCAP Section

stenographergroup:
  group.present:
    - name: stenographer
    - gid: 941

stenographer:
  user.present:
    - uid: 941
    - gid: 941
    - home: /opt/tc/conf/steno

stenoconfdir:
  file.directory:
    - name: /opt/tc/conf/steno
    - user: 941
    - group: 939
    - makedirs: True

pcap_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://pcap/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

{% if PCAPBPF %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/so-bpf-compile', GLOBALS.sensor.interface + ' ' + PCAPBPF|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
      {% set BPF_COMPILED =  ",\\\"--filter=" + BPF_CALC['stdout'] + "\\\""  %}
   {% else  %}

bpfcompilationfailure:
  test.configurable_test_state:
   - changes: False
   - result: False
   - comment: "BPF Compilation Failed - Discarding Specified BPF"
   {% endif %}
{% endif %}

stenoconf:
  file.managed:
    - name: /opt/tc/conf/steno/config
    - source: salt://pcap/files/config.jinja
    - user: stenographer
    - group: stenographer
    - mode: 644
    - template: jinja
    - defaults:
        PCAPMERGED: {{ PCAPMERGED }}
        BPF_COMPILED: "{{ BPF_COMPILED }}"

stenoca:
  file.directory:
    - name: /opt/tc/conf/steno/certs
    - user: 941
    - group: 939

pcapdir:
  file.directory:
    - name: /nsm/pcap
    - user: 941
    - group: 941
    - makedirs: True

pcaptmpdir:
  file.directory:
    - name: /nsm/pcaptmp
    - user: 941
    - group: 941
    - makedirs: True

pcapoutdir:
  file.directory:
    - name: /nsm/pcapout
    - user: 939
    - group: 939
    - makedirs: True

pcapindexdir:
  file.directory:
    - name: /nsm/pcapindex
    - user: 941
    - group: 941
    - makedirs: True

stenolog:
  file.directory:
    - name: /opt/tc/log/stenographer
    - user: 941
    - group: 941
    - makedirs: True

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
