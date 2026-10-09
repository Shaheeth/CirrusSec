# CloudTrail and Logging (project notes)

## What CloudTrail records
CloudTrail records AWS API calls: who did what, from which IP, when. It is the primary audit source for detecting and investigating cloud incidents.

## Recommended configuration
Use a multi-region trail so activity in unused regions is also captured. Enable log file validation to detect tampering, deliver logs to a restricted S3 bucket, and optionally send to CloudWatch for alerting.

## Events worth alerting on
`StopLogging`, `DeleteTrail`, `UpdateTrail`, changes to security groups, `CreateUser`, `CreateAccessKey`, policy attachments, console logins from new locations, and root account use.

## Configuration vs activity analysis
Configuration analysis inspects how resources are set up (is the trail enabled?). Activity analysis inspects what happened over time (who stopped the trail?). Both are needed: one finds weaknesses, the other finds possible exploitation of them.

## Why disabled logging is serious
With logging off, attacker actions leave no audit trail, which prevents detection, scoping and forensic investigation.
