# Attack Paths and MITRE ATT&CK (project notes)

## Attack-path analysis
Individual misconfigurations may look moderate in isolation, but chained together they form a route to valuable assets. A typical cloud chain is: internet exposure of an instance, a credential-bearing role on that instance, an over-broad policy on the role, and a sensitive data store reachable through that policy. Graph analysis models resources as nodes and trust or reachability as edges, then searches from internet entry points to sensitive targets. Results are potential paths based on configuration, not evidence that an attack happened.

## Blast radius
Blast radius is everything reachable if one resource is compromised. Reducing permissions on roles and tightening network exposure shrinks it.

## Breaking a path
Fix the cheapest link that breaks the most paths: close the internet entry, remove the role from the instance, or scope the role policy to least privilege.

## MITRE ATT&CK for cloud
ATT&CK catalogues adversary tactics and techniques. Useful cloud mappings include T1530 (Data from Cloud Storage), T1078.004 (Valid Accounts: Cloud Accounts), T1562.008 (Disable or Modify Cloud Logs), T1136.003 (Create Cloud Account), T1098.001 (Additional Cloud Credentials), T1110 (Brute Force) and T1133 (External Remote Services). A mapping describes how behaviour resembles a technique; it is not proof of an adversary, and some findings have no sensible technique.
