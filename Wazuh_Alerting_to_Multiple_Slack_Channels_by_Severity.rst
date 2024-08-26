.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
   :description: The Wazuh Integrator module allows Wazuh to connect to external APIs and alerting tools. Learn more in this section of the documentation.

Wazuh Alerting to Multiple Slack Channels by Severity
======================================================

The Wazuh Integrator module allows Wazuh to connect to external APIs and alerting tools such as Slack, PagerDuty, VirusTotal, Shuffle, and Maltiverse. You can also configure the Integrator module to connect to other software. These integrations empower security administrators to enhance orchestration, automate responses, and fortify their defenses against cyber threats.

Creating an integration script
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You are recommended to follow the instructions below when creating an integration script:

#. Create the script in ``/var/ossec/integrations/`` directory on the Wazuh server with the same name indicated in the configuration block.

#. The script  must contain execution permissions and belong to the ``root`` user of the ``wazuh`` group. The commands below assign permissions and ownership to the ``/var/ossec/integrations/custom-slack`` script.

   .. code-block:: console

      # chmod 750 /var/ossec/integrations/custom-slack
      # chown root:wazuh /var/ossec/integrations/custom-slack

#. Use this custom script for slack integration:

   .. code-block:: python

      #!/var/ossec/framework/python/bin/python3
      # Copyright (C) 2015, Wazuh Inc.
      # March 13, 2018.
      # This program is free software; you can redistribute it
      # and/or modify it under the terms of the GNU General Public
      # License (version 2) as published by the FSF - Free Software
      # Foundation.

      import json
      import sys
      import time
      import os

      try:
          import requests
          from requests.auth import HTTPBasicAuth
      except Exception as e:
          print("No module 'requests' found. Install: pip install requests")
          sys.exit(1)

      # Global vars

      debug_enabled = False
      pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
      json_alert = {}
      now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

      webhook1 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"
      webhook2 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"
      webhook3 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"

      # Set paths
      log_file = '{0}/logs/integrations.log'.format(pwd)


      def main(args):
          debug("# Starting")

          # Read args
          alert_file_location = args[1]

          debug("# File location")
          debug(alert_file_location)

          # Load alert. Parse JSON object.
          with open(alert_file_location) as alert_file:
              json_alert = json.load(alert_file)
          debug("# Processing alert")
          debug(json_alert)

          debug("# Generating message")
          msg = generate_and_send_msg(json_alert)



      def debug(msg):
          if debug_enabled:
              msg = "{0}: {1}\n".format(now, msg)
              print(msg)
              f = open(log_file, "a")
              f.write(msg)
              f.close()


      def generate_and_send_msg(alert):

          level = alert['rule']['level']

          if (level <= 10):
              color = "good"
          elif (level >= 11 and level <= 14):
              color = "warning"
          else:
              color = "danger"

          msg = {}
          msg['color'] = color
          msg['pretext'] = "WAZUH Alert"
          msg['title'] = alert['rule']['description'] if 'description' in alert['rule'] else "N/A"
          msg['text'] = alert.get('full_log')

          msg['fields'] = []
          if 'agent' in alert:
              msg['fields'].append({
                  "title": "Agent",
                  "value": "({0}) - {1}".format(
                      alert['agent']['id'],
                      alert['agent']['name']
                  ),
              })
          if 'agentless' in alert:
              msg['fields'].append({
                  "title": "Agentless Host",
                  "value": alert['agentless']['host'],
              })
          msg['fields'].append({"title": "Location", "value": alert['location']})
          msg['fields'].append({
              "title": "Rule ID",
              "value": "{0} _(Level {1})_".format(alert['rule']['id'], level),
          })

          msg['ts'] = alert['id']
          attach = {'attachments': [msg]}
          if (level > 6 and level <= 11):
              webhook = webhook1
          elif (level > 11  and level <= 14):
              webhook = webhook2
          elif (level > 14):
              webhook = webhook3 

          headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
          msg = json.dumps(attach)
          debug(msg)

          debug("# Sending message")
          res = requests.post(webhook, data=msg, headers=headers)
          debug(res)




      if __name__ == "__main__":
          try:
              # Read arguments
              bad_arguments = False
              if len(sys.argv) >= 2:
                  msg = '{0} {1} {2}'.format(
                      now,
                      sys.argv[1],
                      sys.argv[2] if len(sys.argv) > 2 else '',
                  )
                  debug_enabled = (len(sys.argv) > 2 and sys.argv[2] == 'debug')
              else:
                  msg = '{0} Wrong arguments'.format(now)
                  bad_arguments = True

              # Logging the call
              f = open(log_file, 'a')
              f.write(msg + '\n')
              f.close()

              if bad_arguments:
                  debug("# Exiting: Bad arguments.")
                  sys.exit(1)

              # Main function
              main(sys.argv)

          except Exception as e:
              debug(str(e))
              raise

#. Modify the Slack integration script to send the appropriate alerts to the appropriate channels. For this create three Webhooks, one for each channel, and update them in the script in the following section:

   .. code-block:: python

      webhook1 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"
      webhook2 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"
      webhook3 = "https://hooks.slack.com/services/XXXXXXXXXXXXXX"

Wazuh Manager Configuration
---------------------------

To configure this integration, add the following configuration within the ``<ossec_config>`` in the ``/var/ossec/etc/ossec.conf`` file on the Wazuh server:

.. code-block:: xml

   <integration>
     <name>custom-slack</name>
     <level>6</level>
     <alert_format>json</alert_format>
   </integration>

Where:

-  ``<name>`` indicates the name of the service to integrate with. The allowed values are slack, pagerduty, virustotal, shuffle, maltiverse. For custom integrations, the name must be any string that begins with ``custom-``.
-  ``<alert_format>`` writes the alert file in the JSON format. The Integrator module makes use of this alert file to fetch field values. The allowed value is ``json``.
-  ``<level>`` filters alerts by rule level so only alerts with the specified level or above are pushed. The allowed value is any alert level from ``0`` to ``16``.

.. note::

   Restart the Wazuh manager when you make any changes to the configuration file. This will ensure that the changes take effect.

Restart the Wazuh manager via the command line interface with the following command:


Systemd

   .. code-block:: console

            # systemctl restart wazuh-manager
SysV init

   .. code-block:: console

            # service wazuh-manager restart


Once the configuration is complete, alerts start showing in the selected channel.

.. thumbnail:: /images/manual/wazuh-server/alerts-in-slack-channel.png
   :title: Alerts in selected Slack channel
   :alt: Alerts in selected Slack channel
   :align: center
   :width: 80%

