{% from 'logrotate/map.jinja' import LOGROTATEMERGED %}

logrotateconfdir:
  file.directory:
    - name: /opt/tc/conf/logrotate
    - makedirs: True

commonlogrotatescript:
  file.managed:
    - name: /usr/local/bin/common-rotate
    - source: salt://logrotate/tools/sbin/common-rotate
    - mode: 755

commonlogrotateconf:
  file.managed:
    - name: /opt/tc/conf/logrotate/common-rotate.conf
    - source: salt://logrotate/etc/rotate.conf.jinja
    - template: jinja
    - mode: 644
    - defaults:
        CONFIG: {{ LOGROTATEMERGED.config }}

common-rotate:
  cron.present:
    - name: /usr/local/bin/common-rotate
    - identifier: common-rotate
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
