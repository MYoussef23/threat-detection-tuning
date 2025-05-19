# Azure Sentinel Rule Tuning: Process Execution Frequency Anomaly

This document details the tuning performed on the "Process Execution Frequency Anomaly" detection rule in Azure Sentinel to increase the granularity of anomaly detection and improve the handling of command line data.

## Rule: Process Execution Frequency Anomaly

**Issue:**

The original rule detected anomalies based solely on the overall execution count of specific sensitive processes (`powershell.exe`, `cmd.exe`, etc.) within a given time frame (hourly). This approach was too broad, as a high frequency of a process might be normal in certain contexts (e.g., a legitimate script running frequently), but unusual with specific command-line arguments, parent processes, or on a particular computer/account. The lack of granularity led to potential false positives and missed detections of truly anomalous executions. Additionally, the handling of command line counts in the detailed results could be improved.

**Original Logic (Relevant Snippets):**

The original logic used `make-series` grouped only by `Process` to build the baseline:

```kql
// The query_now parameter represents the time (in UTC) at which the scheduled analytics rule ran to produce this alert.
set query_now = datetime(2025-05-17T04:40:00.2817686Z);
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 5;
// Configure the list with sensitive process names 
let ExeList = dynamic(["powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "cacls.exe", "rundll32.exe"]);
let TimeSeriesData =
    SecurityEvent
    | where EventID == 4688
    | extend Process = tolower(Process)
    | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
    | where Process in~ (ExeList) and not(Account matches regex "^.+\\$")
    | project TimeGenerated, Computer, AccountType, Account, Process
    | make-series Total=count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by Process;
let TimeSeriesAlerts = materialize(TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 1.5, -1, 'linefit')
    | mv-expand
        Total to typeof(double),
        TimeGenerated to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long)
    | where anomalies > 0
    | project Process, TimeGenerated, Total, baseline, anomalies, score
    | where Total > TotalEventsThreshold);
let AnomalyHours = materialize(TimeSeriesAlerts
    | where TimeGenerated > ago(2d)
    | project TimeGenerated);
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
    SecurityEvent
    | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
    | extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
    | where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
    | where EventID == 4688 and not(Account matches regex "^.+\\$")
    | extend Process = tolower(Process)
    | summarize CommandlineCount = count() by bin(TimeGenerated, 1h), Process, CommandLine, Computer, Account
    )
    on Process, TimeGenerated
| project
    AnomalyHour = TimeGenerated,
    Computer,
    Account,
    Process,
    CommandLine,
    CommandlineCount,
    Total,
    baseline,
    anomalies,
    score
| extend
    timestamp = AnomalyHour,
    NTDomain = split(Account, '\\', 0)[0],
    Name = split(Account, '\\', 1)[0],
    HostName = tostring(split(Computer, '.', 0)[0]),
    DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
````

The anomaly detection was based on the `Total` count per `Process` only.

**Implemented Changes:**

The tuning focuses on increasing the granularity of the baseline calculation and anomaly detection. Instead of just counting the total executions of a process, the baseline is now calculated based on specific combinations of `Account`, `Process`, `Computer`, `ParentProcessName`, and `CommandLine`. This allows the rule to detect anomalies when a *specific instance* of a process execution (e.g., `powershell.exe` run by a particular `Account` on a specific `Computer` with certain `CommandLine` arguments from a particular `ParentProcessName`) deviates significantly from its historical pattern.

Additionally, the `summarize` step was modified to use `countif(isnotempty(CommandLine))`. This ensures that the `CommandlineCount` accurately reflects the number of events where a command line was actually recorded, excluding events where the field might be empty.

**Recommended Logic:**

1. TimeSeriesData Projection: Added ParentProcessName and CommandLine to the project statement feeding make-series.
2. make-series Granularity: Changed the by clause from by Process to by Account, Process, Computer, ParentProcessName, CommandLine.
3. summarise Grouping: Added ParentProcessName to the by clause.
4. summarise Counting: Changed the aggregation for CommandlineCount from count() to countif(isnotempty(CommandLine)).

```kql
// The query_now parameter represents the time (in UTC) at which the scheduled analytics rule ran to produce this alert.
set query_now = datetime(2025-04-19T06:31:33.7869892Z);
let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 5;
// Configure the list with sensitive process names
let ExeList = dynamic(["powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "cacls.exe", "rundll32.exe"]);
let TimeSeriesData =
    SecurityEvent
    | where EventID == 4688
    | extend Process = tolower(Process)
    | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
    | where Process in~ (ExeList) and not(Account matches regex "^.+\\$")
    | project TimeGenerated, Computer, AccountType, Account, Process, ParentProcessName, CommandLine // Change 1. TimeSeriesData Projection: Added ParentProcessName and CommandLine to the project statement feeding make-series.
    | make-series Total=count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by Account, Process, Computer, ParentProcessName, CommandLine; // Change 2. make-series Granularity: Changed the by clause from by Process to by Account, Process, Computer, ParentProcessName, CommandLine.
let TimeSeriesAlerts = materialize(TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 1.5, -1, 'linefit')
    | mv-expand
        Total to typeof(double),
        TimeGenerated to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long)
    | where anomalies > 0
    | project Process, TimeGenerated, Total, baseline, anomalies, score
    | where Total > TotalEventsThreshold);
let AnomalyHours = materialize(TimeSeriesAlerts
    | where TimeGenerated > ago(2d)
    | project TimeGenerated);
TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
    SecurityEvent
    | where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
    | extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour
    | where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours
    | where EventID == 4688 and not(Account matches regex "^.+\\$")
    | extend Process = tolower(Process)
    // Exclude events where the CommandLine field is empty
    | summarize CommandlineCount = countif(isnotempty(CommandLine)) by bin(TimeGenerated, 1h), Process, ParentProcessName, CommandLine, Computer, Account // Change 3. summarize Grouping: Added ParentProcessName to the by clause. and 4. summarize Counting: Changed the aggregation for CommandlineCount from count() to countif(isnotempty(CommandLine)).
    )
    on Process, TimeGenerated
| project
    AnomalyHour = TimeGenerated,
    Computer,
    Account,
    Process,
    ParentProcessName, // Add the parent process to the projection
    CommandLine,
    CommandlineCount,
    Total,
    baseline,
    anomalies,
    score
| extend
    timestamp = AnomalyHour,
    NTDomain = split(Account, '\\', 0)[0],
    Name = split(Account, '\\', 1)[0],
    HostName = tostring(split(Computer, '.', 0)[0]),
    DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
```

**Outcome:**

By increasing the granularity of the baseline calculation, the tuned rule provides much higher-fidelity alerts. Anomalies are now detected based on specific and potentially suspicious combinations of execution parameters, rather than just a general increase in process activity. This reduces false positives by not alerting on routine process executions and improves the detection of malicious activity that might involve unusual command-line arguments or parent processes, even if the overall process count isn't exceptionally high. The improved command line counting also provides more accurate details in the alert output.
