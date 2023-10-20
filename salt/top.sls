{% set ZEEKVER = salt['pillar.get']('global:mdengine', '') %}
{% set WAZUH = salt['pillar.get']('global:wazuh', '0') %}
{% set PLAYBOOK = salt['pillar.get']('manager:playbook', '0') %}
{% set FREQSERVER = salt['pillar.get']('manager:freq', '0') %}
{% set DOMAINSTATS = salt['pillar.get']('manager:domainstats', '0') %}
{% set FLEETMANAGER = salt['pillar.get']('global:fleet_manager', False) %}
{% set FLEETNODE = salt['pillar.get']('global:fleet_node', False) %}
{% set ELASTALERT = salt['pillar.get']('elastalert:enabled', True) %}
{% set ELASTICSEARCH = salt['pillar.get']('elasticsearch:enabled', True) %}
{% set FILEBEAT = salt['pillar.get']('filebeat:enabled', True) %}
{% set KIBANA = salt['pillar.get']('kibana:enabled', True) %}
{% set LOGSTASH = salt['pillar.get']('logstash:enabled', True) %}
{% set REDIS = salt['pillar.get']('redis:enabled', True) %}
{% set STRELKA = salt['pillar.get']('strelka:enabled', '0') %}
{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}
{% set INSTALLEDSALTVERSION = grains.saltversion %}

base:

  '*':
    - cron.running
    - repo.client

  'not G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion-state-apply-test
    - salt.minion

  'G@os:CentOS and G@saltversion:{{saltversion}}':
    - match: compound
    - yum.packages

  '* and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion
    - patch.os.schedule
    - motd
    - salt.minion-check
    - salt.lasthighstate

  'not *_workstation and G@saltversion:{{saltversion}}':
    - match: compound
    - common
  
  '*_helixsensor and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - telegraf
    - firewall
    - idstools
    - suricata.manager
    - pcap
    - suricata
    - zeek
    - redis
    - elasticsearch
    - logstash
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - schedule

  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - nginx
    - pcap
    - suricata
    - healthcheck
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - healthcheck
    {%- if (FLEETMANAGER or FLEETNODE) or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - redis
    - fleet
    - fleet.install_package
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if PLAYBOOK != 0 %}
    - playbook
    - redis
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}
    - docker_clean
    - pipeline.load
    - learn

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - kratos
    - firewall
    - manager
    - idstools
    - suricata.manager
    {%- if (FLEETMANAGER or FLEETNODE) or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - curator
    - utility
    - schedule
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - fleet.install_package
    {%- endif %}
    - soctopus
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}
    - docker_clean
    - pipeline.load
    - learn

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager    
    - healthcheck
    {%- if (FLEETMANAGER or FLEETNODE) or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %} 
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - fleet.install_package
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}
    - docker_clean
    - pipeline.load
    - learn

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    - curator
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean
    - pipeline.load

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - kratos
    - firewall
    - manager
    - idstools
    - suricata.manager
    {%- if (FLEETMANAGER or FLEETNODE) or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    - curator
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - utility
    - schedule
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - fleet.install_package
    {%- endif %}
    - soctopus
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}
    - docker_clean
    - pipeline.load
    - learn

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    - curator
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - schedule
    - docker_clean
    - pipeline.load
  
  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    - mysql
    - redis
    - fleet
    - fleet.install_package
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - schedule
    - docker_clean

  '*_import and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - nginx
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - pcap
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - utility
    - suricata
    - zeek
    - schedule
    - docker_clean
    - pipeline.load
    - learn

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_idh and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean
    {%- if FILEBEAT %}
    - filebeat
    {%- endif %}
    - idh

  'J@workstation:gui:enabled:^[Tt][Rr][Uu][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:CentOS )':
    - match: compound
    - workstation

  'J@workstation:gui:enabled:^[Ff][Aa][Ll][Ss][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:CentOS )':
    - match: compound
    - workstation.remove_gui
