{% set ENROLLSECRET = salt['cmd.shell']('docker exec tc-fleet fleetctl get enroll-secret --json | jq -r ".spec.secrets[].secret"') %}

so/fleet:
  event.send:
    - data:
        action: 'update-enrollsecret'
        enroll-secret: {{ ENROLLSECRET }}