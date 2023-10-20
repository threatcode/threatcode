elastic_curl_config_distributed:
  file.managed:
    - name: /opt/tc/saltstack/local/salt/elasticsearch/curl.config
    - source: salt://elasticsearch/files/curl.config.template
    - template: jinja
    - mode: 600
    - show_changes: False
