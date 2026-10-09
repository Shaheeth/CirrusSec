# IAM Best Practices (project notes)

## Least privilege
Grant only the actions and resources a workload needs. Start narrow and widen on evidence. Wildcard actions such as `*` or `s3:*` combined with resource `*` mean any compromise of that identity inherits everything. IAM Access Analyzer can generate policies from observed activity.

## Prefer roles over long-lived keys
Roles issue short-lived credentials automatically. Long-lived access keys that are old or unused are rarely noticed when stolen. Deactivate then delete unused keys and rotate required ones about every 90 days.

## Multi-factor authentication
Require MFA for every console user, especially those with broad permissions. A single password is easily phished or reused.

## Privilege escalation permissions
Permissions such as `iam:PassRole`, `iam:CreateAccessKey`, `iam:AttachUserPolicy` and `iam:PutUserPolicy` let an identity grant itself more power. Treat them as sensitive and restrict them to administrators, with logging and alerts.

## Role trust and instance profiles
An EC2 instance receives role credentials through the instance metadata service. If the instance is compromised, so are the role permissions. Use IMDSv2 and keep instance roles minimal.
