# Sumo Logic Rule Tuning: Local User Created (Event ID 4720)

This document details the tuning performed on the "Local User Created" detection rule in Sumo Logic to distinguish between local and domain user creation events (Windows Event ID 4720).

## Rule: Local User Created

**Issue:**

The Windows Event ID 4720 ("A user account was created") is generated for both domain user creations (when logged on a domain controller) and local user creations (when logged on a non-domain controller, such as a workstation or member server). The original Sumo Logic rule correctly identified all events with `metadata_deviceEventId = 'Security-4720'`. However, the rule was too broad as it triggered alerts for domain user creations, which might be expected behavior and not indicative of a security incident requiring immediate investigation (i.e., generating false positives).

**Original Rule Expression:**

```kql
metadata_deviceEventId = 'Security-4720'
````

This expression simply matched *any* instance of Windows Event ID 4720.

**Implemented Changes:**

To tune the rule to specifically target *local* user creations and ignore those originating from known domain controllers, logic was added to exclude events where the source matches a predefined list of domain controllers. This is achieved by using the `NOT array_contains` operator against a list likely configured within Sumo Logic (represented here as `listMatches, 'domain_controllers'`).

**Corrected Rule Expression:**

```kql
metadata_deviceEventId = 'Security-4720' AND NOT array_contains(listMatches, 'domain_controllers')
```

This revised expression ensures that the rule only triggers for Event ID 4720 if the event *does not* originate from a system identified as a domain controller in the `domain_controllers` list.

**Outcome:**

By excluding domain controller events, the rule now focuses on user creations occurring on non-domain controller machines, significantly reducing false positives and highlighting potentially suspicious local account creations on workstations or servers.
