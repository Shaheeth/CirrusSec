# S3 Security (project notes)

## Block Public Access
S3 Block Public Access overrides public ACLs and bucket policies at bucket or account level. Enable it everywhere unless a bucket is deliberately a public website, and even then prefer CloudFront with origin access control.

## Public buckets and data leaks
A bucket that allows public read can be discovered and downloaded by anyone. Buckets holding customer, backup or log data should never be public. Sensitive data in a public bucket is a critical finding.

## Encryption at rest
Enable default encryption (SSE-S3 or SSE-KMS). It protects data if storage media, copies or snapshots are exposed, and many compliance regimes require it. Also enable versioning for recovery from accidental or malicious deletion.

## Access via IAM
Bucket access is the union of IAM policies and bucket policies. A role with `s3:*` on `*` can read every bucket in the account, including sensitive ones; scope policies to named bucket ARNs.
