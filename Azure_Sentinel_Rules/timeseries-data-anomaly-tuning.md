# Azure Sentinel Rule Tuning: Time series anomaly for data size transferred to public internet

This document details the tuning performed on the "Threat Essentials - Time series anomaly for data size transferred to public internet" detection rule in Azure Sentinel. The goal of this tuning is to reduce false positives by correlating destination IP addresses with threat intelligence feeds.

## Rule: Threat Essentials - Time series anomaly for data size transferred to public internet

**Issue:**

The original rule effectively identifies anomalies in the volume of data transferred to public IP addresses based on historical baseline data. However, it generates false positives by alerting on legitimate, high-volume traffic to known benign service providers (e.g., Google, Microsoft, ServiceNow). This reduces the effectiveness of the alert and increases the workload for security analysts.

**Original Logic (Summary):**

The original logic calculates a baseline for `BytesSent` over a historical period (e.g., 14 days), identifies anomalies based on a score threshold, and then joins these anomalies back to the raw connection logs (`VMConnection`, `CommonSecurityLog`) to get details like Source/Destination IPs and total bytes sent during the anomaly hour.

```kql
// The query_now parameter represents the time (in UTC) at which the scheduled analytics rule ran to produce this alert.
set query_now = datetime(2025-03-21T02:53:37.3449496Z); // Placeholder, will be dynamic in Sentinel
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let scorethreshold = 5;
let bytessentperhourthreshold = 10;
let PrivateIPregex = @'^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.';
let TimeSeriesData = (union isfuzzy=true
        (
        VMConnection
        | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
        | where isnotempty(DestinationIp) and isnotempty(SourceIp)
        | extend DestinationIpType = iff(DestinationIp matches regex PrivateIPregex, "private", "public")
        | where DestinationIpType == "public"
        | extend DeviceVendor = "VMConnection"
        | project TimeGenerated, BytesSent, DeviceVendor
        | make-series TotalBytesSent=sum(BytesSent) on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceVendor
        ),
        (
        CommonSecurityLog
        | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
        | where isnotempty(DestinationIP) and isnotempty(SourceIP)
        | extend DestinationIpType = iff(DestinationIP matches regex PrivateIPregex, "private", "public")
        | where DestinationIpType == "public"
        | project TimeGenerated, SentBytes, DeviceVendor
        | make-series TotalBytesSent=sum(SentBytes) on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceVendor
        )
    );
//Filter anomolies against TimeSeriesData
let TimeSeriesAlerts = materialize(TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(TotalBytesSent, scorethreshold, -1, 'linefit')
    | mv-expand
        TotalBytesSent to typeof(double),
        TimeGenerated to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long)
    | where anomalies > 0
    | extend AnomalyHour = TimeGenerated
    | extend
        TotalBytesSentinMBperHour = round(((TotalBytesSent / 1024) / 1024), 2),
        baselinebytessentperHour = round(((baseline / 1024) / 1024), 2),
        score = round(score, 2)
    | project
        DeviceVendor,
        AnomalyHour,
        TimeGenerated,
        TotalBytesSentinMBperHour,
        baselinebytessentperHour,
        anomalies,
        score);
let AnomalyHours = materialize(TimeSeriesAlerts
    | where TimeGenerated > ago(2d)
    | project TimeGenerated);
//Union of all BaseLogs aggregated per hour
let BaseLogs = (union isfuzzy=true
        (
        CommonSecurityLog
        | where isnotempty(DestinationIP) and isnotempty(SourceIP)
        | where TimeGenerated > ago(2d)
        | extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
        | where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
        | extend DestinationIpType = iff(DestinationIP matches regex PrivateIPregex, "private", "public")
        | where DestinationIpType == "public"
        | extend
            SentBytesinMB = ((SentBytes / 1024) / 1024),
            ReceivedBytesinMB = ((ReceivedBytes / 1024) / 1024)
        | summarize
            HourlyCount = count(),
            TimeGeneratedMax=arg_max(TimeGenerated, *),
            DestinationIPList=make_set(DestinationIP, 100),
            DestinationPortList = make_set(DestinationPort, 100),
            TotalSentBytesinMB = sum(SentBytesinMB),
            TotalReceivedBytesinMB = sum(TotalReceivedBytesinMB)
            by SourceIP, DeviceVendor, TimeGeneratedHour=bin(TimeGenerated, 1h)
        | where TotalSentBytesinMB > bytessentperhourthreshold
        | sort by TimeGeneratedHour asc, TotalSentBytesinMB desc
        | extend Rank=row_number(1, prev(TimeGeneratedHour) != TimeGeneratedHour) // Ranking the dataset per Hourly Partition
        | where Rank < 10  // Selecting Top 10 records with Highest BytesSent in each Hour
        | project
            DeviceVendor,
            TimeGeneratedHour,
            TimeGeneratedMax,
            SourceIP,
            DestinationIPList,
            DestinationPortList,
            TotalSentBytesinMB,
            TotalReceivedBytesinMB,
            Rank
        ),
        (
        VMConnection
        | where isnotempty(DestinationIp) and isnotempty(SourceIp)
        | where TimeGenerated > ago(2d)
        | extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
        | where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
        | extend SourceIP = SourceIp, DestinationIP = DestinationIp
        | extend DestinationIpType = iff(DestinationIp matches regex PrivateIPregex, "private", "public")
        | where DestinationIpType == "public"
        | extend DeviceVendor = "VMConnection"
        | extend
            SentBytesinMB = ((BytesSent / 1024) / 1024),
            ReceivedBytesinMB = ((BytesReceived / 1024) / 1024)
        | summarize
            HourlyCount = count(),
            TimeGeneratedMax=arg_max(TimeGenerated, *),
            DestinationIPList=make_set(DestinationIP, 100),
            DestinationPortList = make_set(DestinationPort, 100),
            TotalSentBytesinMB = sum(SentBytesinMB),
            TotalReceivedBytesinMB = sum(TotalReceivedBytesinMB)
            by SourceIP, DeviceVendor, TimeGeneratedHour=bin(TimeGenerated, 1h)
        | where TotalSentBytesinMB > bytessentperhourthreshold
        | sort by TimeGeneratedHour asc, TotalSentBytesinMB desc
        | extend Rank=row_number(1, prev(TimeGeneratedHour) != TimeGeneratedHour) // Ranking the dataset per Hourly Partition
        | where Rank < 10  // Selecting Top 10 records with Highest BytesSent in each Hour
        | project
            DeviceVendor,
            TimeGeneratedHour,
            TimeGeneratedMax,
            SourceIP,
            DestinationIPList,
            DestinationPortList,
            TotalSentBytesinMB,
            TotalReceivedBytesinMB,
            Rank
        )
    );
// Join against base logs to retrive records associated with the hour of anomaly
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
    BaseLogs
    | extend AnomalyHour = TimeGeneratedHour
    )
    on DeviceVendor, AnomalyHour
| sort by score desc
| project
    DeviceVendor,
    AnomalyHour,
    TimeGeneratedMax,
    SourceIP,
    DestinationIPList,
    DestinationPortList,
    TotalSentBytesinMB,
    TotalReceivedBytesinMB,
    TotalBytesSentinMBperHour,
    baselinebytessentperHour,
    score,
    anomalies
| summarize
    EventCount = count(),
    StartTimeUtc= min(TimeGeneratedMax),
    EndTimeUtc= max(TimeGeneratedMax),
    SourceIPMax= arg_max(SourceIP, *),
    TotalBytesSentinMB = sum(TotalSentBytesinMB),
    TotalBytesReceivedinMB = sum(TotalBytesReceivedinMB),
    SourceIPList = make_set(SourceIP, 100),
    DestinationIPList = make_set(DestinationIPList, 100)
    by
    AnomalyHour,
    TotalBytesSentinMBperHour,
    baselinebytessentperHour,
    score,
    anomalies
| project
    DeviceVendor,
    AnomalyHour,
    StartTimeUtc,
    EndTimeUtc,
    SourceIPMax,
    SourceIPList,
    DestinationIPList,
    DestinationPortList,
    TotalBytesSentinMB,
    TotalBytesReceivedinMB,
    TotalBytesSentinMBperHour,
    baselinebytessentperHour,
    score,
    anomalies,
    EventCount
````

**Implemented Changes:**

To address the false positive issue, the tuning involves correlating the `DestinationIP` from the identified anomalous traffic with the `ThreatIntelligenceIndicator` table. This table in Azure Sentinel contains indicators of compromise (IOCs) from various threat intelligence feeds. By joining with this table and filtering for matches, we can prioritize alerts where the anomalous traffic is directed towards known malicious or suspicious IP addresses.

Traffic directed towards IPs *not* found in threat intelligence (especially if they are known benign services) can then be excluded or handled with lower severity.

**Tuned Logic (Conceptual Change):**

The core change involves adding a join operation to the final result set or the `BaseLogs` section to check if any of the `DestinationIP` values are present in the `ThreatIntelligenceIndicator` table.

```kql
// ... (Previous logic to identify anomalies and get BaseLogs) ...

// Join anomalous traffic with Threat Intelligence Indicators
BaseLogs
| join kind=inner (
    ThreatIntelligenceIndicator
    | where ExpirationDateTime > now()
    | where Active == true
    | where IndicatorType == 'ipv4-addr' or IndicatorType == 'ipv6-addr'
    | extend TI_DestinationIP = NetworkIP
) on $left.DestinationIPList == $right.TI_DestinationIP // Join on the list of destination IPs
| project // Select relevant fields, including TI match details
    DeviceVendor,
    AnomalyHour,
    StartTimeUtc,
    EndTimeUtc,
    SourceIPMax,
    SourceIPList,
    DestinationIPList,
    DestinationPortList,
    TotalBytesSentinMB,
    TotalBytesReceivedinMB,
    TotalBytesSentinMBperHour,
    baselinebytessentperHour,
    score,
    anomalies,
    EventCount,
    // Include relevant TI feilds
    TI_DestinationIP,
    Description,
    ThreatType,
    ConfidenceScore
// Further filtering or scoring can be added here based on TI match
```

*(Note: The KQL above is a conceptual representation of where the join would be added. The exact placement and join logic might need adjustment based on the full original query structure and how `DestinationIPList` is handled.)*

**Outcome:**

By correlating anomalous data transfer events with threat intelligence, the tuned rule significantly reduces false positives caused by traffic to benign services. This ensures that alerts generated by this rule are more likely to represent actual suspicious or malicious data exfiltration attempts, allowing SOC analysts to focus on higher-fidelity incidents.
