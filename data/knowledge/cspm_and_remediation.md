# CSPM and Safe Remediation (project notes)

## Cloud Security Posture Management
CSPM continuously checks cloud configuration against best practice and benchmarks (for example CIS AWS Foundations), reports misconfigurations and prioritises them. It answers whether resources are configured safely, not whether an attack is in progress.

## Prioritising remediation
Rank by risk, not just severity: internet exposure, sensitive data, privilege level and presence on an attack path raise priority. Fix issues that sit on attack paths first because each fix can break an entire chain.

## Safe remediation practice
Test changes in a non-production account first, make one change at a time, keep a rollback plan and record the change. Prefer restricting access over deleting resources. Never delete buckets, databases, trails or keys as a first response: deactivate or restrict first, preserve evidence, then clean up after review.

## Encryption notes
Existing unencrypted RDS instances and EBS volumes cannot be encrypted in place; create an encrypted snapshot copy and restore from it.

## Incident handling reminder
If suspicious activity is found, preserve logs, rotate or deactivate affected credentials, review newly created identities and escalate to the incident response owner before making destructive changes.
