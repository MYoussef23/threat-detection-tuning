# Sumo Logic Rule Tuning: vCenter - Invalid Login Attempt

This document details the tuning performed on the "vCenter - Invalid Login Attempt" detection rule in Sumo Logic to improve its accuracy and reduce false positives.

## Rule: vCenter - Invalid Login Attempt

**Issue:**

The original logic for this rule did not explicitly match events related to VMware ESX authentication failures as intended. The primary issue stemmed from the incorrect prioritization of the final `OR` statement, which caused the rule to trigger on events that were not directly related to authentication failures, leading to false positives.

**Original Rule Expression:**

```kql
metadata_vendor = 'VMware'
AND metadata_product = 'ESX'
AND metadata_deviceEventId = 'authentication failure'
AND (user_userId != "null" OR targetUser_username != "null")
OR (device_hostname != "null" OR device_ip != "null")
````

In the original expression, the last `OR (device_hostname != "null" OR device_ip != "null")` was evaluated independently of the preceding `AND` conditions. This meant the rule would trigger if *either* the first four conditions were met *or* if `device_hostname` or `device_ip` were not null, regardless of whether it was an authentication failure event.

**Implemented Changes:**

To ensure the rule specifically targets VMware ESX authentication failures, the `OR` statements related to identifying the source (`user_userId`, `targetUser_username`, `device_hostname`, `device_ip`) were explicitly grouped using parentheses. This forces the logic to evaluate these conditions *only* within the context of a confirmed VMware ESX authentication failure event.

**Corrected Rule Expression:**

```kql
metadata_vendor = 'VMware'
AND metadata_product = 'ESX'
AND metadata_deviceEventId = 'authentication failure'
AND ((user_userId != "null" OR targetUser_username != "null") OR (device_hostname != "null" OR device_ip != "null"))
```

By grouping the final `OR` conditions within an outer set of parentheses, the rule now correctly requires that the event is from `VMware` ESX, is an `authentication failure`, AND has either a user identifier OR device information present.

**Outcome:**

This tuning significantly reduced false positives by ensuring that the rule only triggered for events that were genuine VMware ESX authentication failures, thereby improving the signal-to-noise ratio for security analysts.
