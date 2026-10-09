# Security Groups and Network Exposure (project notes)

## What security groups do
Security groups are stateful virtual firewalls attached to instances and databases. Rules are allow-only. A source of `0.0.0.0/0` means the entire internet.

## SSH and remote administration
SSH (TCP 22) and RDP (TCP 3389) open to the internet are scanned and brute-forced constantly. Restrict them to a VPN or bastion range, or use AWS Systems Manager Session Manager and close the ports entirely.

## Database and service ports
Ports such as 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 6379 (Redis), 9200 (Elasticsearch) and 27017 (MongoDB) should only be reachable from application security groups, never from the internet.

## Public databases
Setting an RDS instance as publicly accessible gives it a public endpoint. Keep databases in private subnets with PubliclyAccessible disabled.

## Reducing exposure
Put web workloads behind a load balancer or WAF, keep instances in private subnets, and reference other security groups instead of CIDR ranges.
