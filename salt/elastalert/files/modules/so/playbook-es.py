# -*- coding: utf-8 -*-

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://threatcode.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


from time import gmtime, strftime
import requests,json
from elastalert.alerts import Alerter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PlaybookESAlerter(Alerter):
    """
    Use matched data to create alerts in elasticsearch
    """

    required_options = set(['play_title','play_url','sigma_level'])

    def alert(self, matches):
       for match in matches:
            today = strftime("%Y.%m.%d", gmtime())
            timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S"'.000Z', gmtime())
            headers = {"Content-Type": "application/json"}

            creds = None
            if 'es_username' in self.rule and 'es_password' in self.rule:
                creds = (self.rule['es_username'], self.rule['es_password'])

            payload = {"tags":"alert","rule": { "name": self.rule['play_title'],"case_template": self.rule['play_id'],"uuid": self.rule['play_id'],"category": self.rule['rule.category']},"event":{ "severity": self.rule['event.severity'],"module": self.rule['event.module'],"dataset": self.rule['event.dataset'],"severity_label": self.rule['sigma_level']},"kibana_pivot": self.rule['kibana_pivot'],"soc_pivot": self.rule['soc_pivot'],"play_url": self.rule['play_url'],"sigma_level": self.rule['sigma_level'],"event_data": match, "@timestamp": timestamp}
            url = f"https://{self.rule['es_host']}:{self.rule['es_port']}/logs-playbook.alerts-so/_doc/"
            requests.post(url, data=json.dumps(payload), headers=headers, verify=False, auth=creds)
                            
    def get_info(self):
        return {'type': 'PlaybookESAlerter'} 
