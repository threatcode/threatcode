# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}


dockergroup:
  group.present:
    - name: docker
    - gid: 920

{% if GLOBALS.os_family == 'Debian' %}
{%    if grains.oscodename == 'bookworm' %}
dockerheldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.6.21-1
      - docker-ce: 5:24.0.3-1~debian.12~bookworm
      - docker-ce-cli: 5:24.0.3-1~debian.12~bookworm
      - docker-ce-rootless-extras: 5:24.0.3-1~debian.12~bookworm
    - hold: True
    - update_holds: True
{%    elif grains.oscodename == 'jammy' %}
dockerheldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.6.21-1
      - docker-ce: 5:24.0.2-1~ubuntu.22.04~jammy
      - docker-ce-cli: 5:24.0.2-1~ubuntu.22.04~jammy
      - docker-ce-rootless-extras: 5:24.0.2-1~ubuntu.22.04~jammy
    - hold: True
    - update_holds: True
{%    else %}
dockerheldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.4.9-1
      - docker-ce: 5:20.10.8~3-0~ubuntu-focal
      - docker-ce-cli: 5:20.10.5~3-0~ubuntu-focal
      - docker-ce-rootless-extras: 5:20.10.5~3-0~ubuntu-focal
    - hold: True
    - update_holds: True
{% endif %}
{% else %}
dockerheldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.6.21-3.1.el9
      - docker-ce: 24.0.4-1.el9
      - docker-ce-cli: 24.0.4-1.el9
      - docker-ce-rootless-extras: 24.0.4-1.el9
    - hold: True
    - update_holds: True
{% endif %}

#disable docker from managing iptables
iptables_disabled:
  file.managed:
    - name: /etc/systemd/system/docker.service.d/iptables-disabled.conf
    - source: salt://docker/files/iptables-disabled.conf
    - makedirs: True
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: iptables_disabled

# Make sure etc/docker exists
dockeretc:
  file.directory:
    - name: /etc/docker

# Manager daemon.json
docker_daemon:
  file.managed:
    - source: salt://common/files/daemon.json
    - name: /etc/docker/daemon.json
    - template: jinja 

# Make sure Docker is always running
docker_running:
  service.running:
    - name: docker
    - enable: True
    - watch:
      - file: docker_daemon

# Reserve OS ports for Docker proxy in case boot settings are not already applied/present
# 57314 = Strelka, 47760-47860 = Zeek
dockerapplyports:
    cmd.run:
      - name: if [ ! -s /etc/sysctl.d/99-reserved-ports.conf ]; then sysctl -w net.ipv4.ip_local_reserved_ports="57314,47760-47860"; fi

# Reserve OS ports for Docker proxy
dockerreserveports:
  file.managed:
    - source: salt://common/files/99-reserved-ports.conf
    - name: /etc/sysctl.d/99-reserved-ports.conf

sos_docker_net:
  docker_network.present:
    - name: sobridge
    - subnet: {{ DOCKER.range }}
    - gateway: {{ DOCKER.gateway }}
    - options:
        com.docker.network.bridge.name: 'sobridge'
        com.docker.network.driver.mtu: '1500'
        com.docker.network.bridge.enable_ip_masquerade: 'true'
        com.docker.network.bridge.enable_icc: 'true'
        com.docker.network.bridge.host_binding_ipv4: '0.0.0.0'
    - unless: 'docker network ls | grep sobridge'
