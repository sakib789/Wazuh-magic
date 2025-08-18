# **Mail:**
First, configure a SMTP server on the Wazuh indexer node following this “SMTP server with authentication” section of this document for Wazuh.

https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#smtp-server-with-authentication


Now configure the SMTP sender form, **Explore** > **Notifications** > **Email senders**

Click on **Create SMTP sender**

Now configure it following this screenshot
<img width="3420" height="1242" alt="image" src="https://github.com/user-attachments/assets/26cf361f-b255-42db-9b57-9219899a5942" />

**Sender name**: Anything\
**Email address**: Sender mail address that you configured in the Postfix\
**Host**: hostname in the Postfix configuration. If you followed the document above for configuration, the host will be **localhost**\
**Port**: 25




Now configure the mail channel form, **Explore** > **Notifications** > **Channels**

Click on **Create channel**



Now, create a mail notification channel following this screenshot.
<img width="1600" height="789" alt="image" src="https://github.com/user-attachments/assets/57230147-d2d0-419e-a3b8-77430311aa82" />


You can test the configuration by clicking the **Send text message** at the end of the configuration next to **Create**.

# **Discord:**

Create a Discord webhook from the Edit Channel > Integrations > Webhooks 



Ref: https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks
Copy the webhook URL.

Now configure the Discord channel form, Explore > Notifications > Channels

Click on Create channel

Now, create a mail notification channel following this screenshot.



Now, if you click on Send test message. It will show you this error.

Failed to send the test message.

View error details and adjust the channel settings.

Nothing to worry about. 

This is not working because of the format of the test message. The test message looks like this:
Test message content body for config id <id>
But that is not valid JSON. Discord expects a value for the "content" key. In the Create Monitor page, you can put in the full message. If you format it as JSON, it works.
Like this: {"content": "test"}






To test this, configure a test monitor.

You can use this sample query for FIM Alerts. (Per Query monitor > Extraction query editor )

```
{
    "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "match_all": {}
        },
        {
          "match_phrase": {
            "rule.groups": "syscheck"
          }
        },
        {
          "range": {
            "timestamp": {
              "gt": "now-5m",
              "lte": "now",
              "format": "strict_date_optional_time"
            }
          }
        }
      ]
    }
    }
}
```

In the text Actions section, use the JSON format message.

Check this screenshot for reference:



{"content": "Monitor {{ctx.monitor.name}} just entered alert status. Please investigate the issue. \n- Trigger: {{ctx.trigger.name}} \n- Severity: {{ctx.trigger.severity}} \n- Period start: {{ctx.periodStart}} UTC \n- Period end: {{ctx.periodEnd}} UTC"}



Or 

{"content": "Wazuh File Integrity Monitoring \n\n{{#ctx.results.0.hits.hits}} \n- Index: {{_index}} \n- Document: {{_id}} \n- Alert Description : {{_source.rule.description}} \n- Alert id : {{_source.rule.id}} \n- FIM path : {{_source.syscheck.path}} \n- FIM event: {{_source.syscheck.event}} \n- Alert Timestamp : {{_source.@timestamp}} /n{{/ctx.results.0.hits.hits}}"}


Now, if you have a FIM Alert in the last 5 minutes, you should get an alert like this when you click on the send test message.

