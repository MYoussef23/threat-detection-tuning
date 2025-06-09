# Tuning Request: Enhance Event ID 4625 (Failed Logon) Alerts

This README outlines a tuning request to enrich the context of Event ID 4625 (Failed Logon) alerts within Azure Sentinel. By projecting additional authentication-related fields, we aim to provide crucial details that will significantly improve an analyst's ability to quickly triage and investigate potential attacks or misconfigurations.

## Table of Contents

* [Description](#Description)  
* [Current Behavior](#current-behavior)  
* [Expected Behavior](expected-behavior)  
* [Logs / Examples](logs--examples)  
* [Impact](impact)  
* [Suggested Changes](suggested-changes)  
* [Environment](environment)

## Description

This tuning request aims to enrich the context of Event ID 4625 (Failed Logon) alerts by projecting additional authentication-related fields. Including these fields will provide crucial details about the authentication protocol, NTLM version, and the specific logon process, enhancing an analyst's ability to quickly triage and investigate potential attacks or misconfigurations.

## Current Behavior

The current analytics rule for failed logons provides basic information such as the Account, IpAddress, and SubStatus. While SubStatus is mapped to a Reason string, it lacks deeper context regarding the authentication mechanism (AuthenticationPackageName, LmPackageName) and, crucially, the process that initiated the logon session (LogonProcessName).

This limited context often leads to:

* **Increased investigation time:** Analysts must manually pivot to raw logs to gather missing authentication details, slowing down triage.  
* **Reduced visibility:** Important anomalies, such as the use of an unknown LogonProcessName or fallback to weaker NTLM versions, are not immediately apparent in the alert, potentially masking subtle threats or persistent misconfigurations.  
* **Difficulty in distinguishing legitimate failures from suspicious activity:** Without knowing the authentication package, it's harder to identify targeted Kerberos attacks or NTLM relay attempts.

## Expected Behavior

After tuning, alerts for Event ID 4625 will include the following additional fields in their projection:

* ```AuthenticationPackageName```: To identify the authentication protocol used (e.g., Kerberos, NTLM, Negotiate, Anonymous).  
* ```LmPackageName```: To specify the NTLM version (e.g., NTLM V1, NTLM V2, LM) if NTLM was used.  
* ```LogonProcessName```: To identify the specific trusted logon process that initiated the authentication attempt (e.g., Advapi, User32, or unusual custom processes).  
* ```Status```: For events where SubStatus is "0x0", the Status is beneficial to understand the cause of the failures and specific lookup if needed.  
* ```SubjectAccount```: Provides the account name of the account attempting the logon, offering an additional identifier.

This enhanced context will enable faster, more accurate triage of failed logon alerts, improving detection efficacy and incident response efficiency.

## **Logs / Examples**

Below are examples of how the additional fields would provide critical context, based on recent investigative findings:

### Example 1: Persistent Kerberos Trust Failure for Tableau service account - Logs from SecurityEvent

```
TimeGenerated [UTC]	SourceSystem	Account	AccountType	Computer	EventSourceName	Channel	Task	Level	EventData	EventID	Activity	AuthenticationPackageName	FailureReason	IpAddress	IpPort	KeyLength	LmPackageName	LogonProcessName	LogonType	LogonTypeName	Process	ProcessId	ProcessName	Status	SubjectAccount	SubjectDomainName	SubjectLogonId	SubjectUserName	SubjectUserSid	SubStatus	TargetAccount	TargetDomainName	TargetUserSid	TransmittedServices	WorkstationName	EventLevelName
6/7/2025, 12:05:40.678 AM	OpsManager	-\	User	TableauServer01.mycorp.com	Microsoft-Windows-Security-Auditing	Security	12544	0		4625	4625 - An account failed to log on.	Kerberos	%%2304	-	-	0	-	TabImp	3	3 - Network	tabprotosrv.exe	0x8214	C:\Program Files\Tableau\Tableau Server\packages\bin.20233.24.0425.1414\tabprotosrv.exe	0xc000018d	MYCORP\Tableau_serviceAcc	MYCORP	0x192aa2	Tableau_serviceAcc	S-0-0-00-[redacted]	0x0	-\	-	S-1-0-0	-	TableauServer01	LogAlways
```

**Context added by new fields:** The combination of ```AuthenticationPackageName```: Kerberos, ```Status```: 0xc000018d ("The user account did not have the required trust relationship"), and ```LogonProcessName```: TabImp reveals a persistent Kerberos trust misconfiguration on a Tableau Server, with the added anomaly of an unknown logon process. This specific context is vital for differentiating from generic bad password attempts.

### Example 2: Account Lockout/Brute-Force Activity - Logs from SecurityEvent:

```
TimeGenerated [UTC]	SourceSystem	Account	AccountType	Computer	EventSourceName	Channel	Task	Level	EventData	EventID	Activity	AuthenticationPackageName	FailureReason	IpAddress	IpPort	KeyLength	LmPackageName	LogonProcessName	LogonType	LogonTypeName	Process	ProcessId	ProcessName	Status	SubjectAccount	SubjectDomainName	SubjectLogonId	SubjectUserName	SubjectUserSid	SubStatus	TableId	TargetAccount	TargetDomainName	TargetLogonId	TargetUserName	TargetUserSid	TransmittedServices	WorkstationName	EventLevelName
6/7/2025, 12:06:42.071 PM	OpsManager	MYCORP\MyUser	User	PrintServer.mycorp.com	Microsoft-Windows-Security-Auditing	Security	12544	0		4625	4625 - An account failed to log on.	NTLM	%%2309	[internal/private IP address]	56651	0	-	NtLmSsp 	3	3 - Network	-	0x0	-	0xc000006e	-\-	-	0x0	-	S-1-0-0	0xc0000071		MYCORP\MyUser	MYCORP		MyUser	S-1-0-0	-	MyCorpWorkstation01	LogAlways
```

**Context added by new fields:** ```AuthenticationPackageName```: NTLM combined with ```LmPackageName```: -, indicating that NTLMv1 (or other outdated version of NTLM) may have been used to authenticate, which would cause failures due to the unsupported/incompatible authentication protocol.

## Impact

The current lack of these fields in the alert projection hinders the analysts' ability to efficiently triage and investigate failed logon events. It forces manual deep-dives into raw logs for every significant alert, increasing mean time to detect (MTTD) and mean time to respond (MTTR). More importantly, unique indicators like a custom authentication logon process (LogonProcessName) that may point to sophisticated compromise or rootkit activity can be missed without this immediate context. Without proper AuthenticationPackageName visibility, detecting specific attack types like NTLM relay or Kerberos ticketing issues becomes reactive rather than proactive at the alert stage.

## Suggested Changes

Modify the analytics rule to include the following fields in the summarize and project clauses, ensuring they are present in both the "today" and "prev 7 day" parts of the query:

1. ```Status```  
2. ```AuthenticationPackageName```  
3. ```LmPackageName```  
4. ```LogonProcessName```  
5. ```SubjectAccount```

Code snippet
```kql
// The query_now parameter represents the time (in UTC) at which the scheduled analytics rule ran to produce this alert.
set query_now = datetime(2025-06-07T09:55:00.0000000Z);
let starttime = 8d;
let endtime = 1d;
let threshold = 0.333;
let countlimit = 50;
SecurityEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4625 and AccountType =~ "User"
| where IpAddress !in ("127.0.0.1", "::1")
| summarize
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    CountToday = count()
    by
    EventID,
    Account,
    LogonTypeName,
    SubStatus,
    Status,//Change (1)
    AccountType,
    Computer,
    WorkstationName,
    IpAddress,
    Process,
    AuthenticationPackageName,	//Change (2)
    LmPackageName,	//Change (3)
    LogonProcessName,	//Change (4)
    SubjectAccount	//Change (5)
| join kind=leftouter (
    SecurityEvent
    | where TimeGenerated between (ago(starttime) .. ago(endtime))
    | where EventID == 4625 and AccountType =~ "User"
    | where IpAddress !in ("127.0.0.1", "::1")
    | summarize CountPrev7day = count()
        by
        EventID,
        Account,
        LogonTypeName,
        SubStatus,
        Status,	//Change (1)
        AccountType,
        Computer,
        WorkstationName,
        IpAddress,
        AuthenticationPackageName,	//Change (2)
        LmPackageName,	//Change (3)
        LogonProcessName,	//Change (4)
        SubjectAccount	//Change (5)
    )
    on
    EventID,
    Account,
    LogonTypeName,
    SubStatus,
    Status,	//Change (1)
    AccountType,
    Computer,
    WorkstationName,
    IpAddress,
    AuthenticationPackageName,	//Change (2)
    LmPackageName,	//Change (3)
    LogonProcessName,	//Change (4)
    SubjectAccount	//Change (5)
| where CountToday >= coalesce(CountPrev7day, 0) * threshold and CountToday >= countlimit
//SubStatus Codes are detailed here - https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4625
| extend Reason = case(
                    SubStatus =~ '0xC000005E',
                    'There are currently no logon servers available to service the logon request.',
                    SubStatus =~ '0xC0000064',
                    'User logon with misspelled or bad user account',
                    SubStatus =~ '0xC000006A',
                    'User logon with misspelled or bad password',
                    SubStatus =~ '0xC000006D',
                    'Bad user name or password',
                    SubStatus =~ '0xC000006E',
                    'Unknown user name or bad password',
                    SubStatus =~ '0xC000006F',
                    'User logon outside authorized hours',
                    SubStatus =~ '0xC0000070',
                    'User logon from unauthorized workstation',
                    SubStatus =~ '0xC0000071',
                    'User logon with expired password',
                    SubStatus =~ '0xC0000072',
                    'User logon to account disabled by administrator',
                    SubStatus =~ '0xC00000DC',
                    'Indicates the Sam Server was in the wrong state to perform the desired operation',
                    SubStatus =~ '0xC0000133',
                    'Clocks between DC and other computer too far out of sync',
                    SubStatus =~ '0xC000015B',
                    'The user has not been granted the requested logon type (aka logon right) at this machine',
                    SubStatus =~ '0xC000018C',
                    'The logon request failed because the trust relationship between the primary domain and the trusted domain failed',
                    SubStatus =~ '0xC0000192',
                    'An attempt was made to logon, but the Netlogon service was not started',
                    SubStatus =~ '0xC0000193',
                    'User logon with expired account',
                    SubStatus =~ '0xC0000224',
                    'User is required to change password at next logon',
                    SubStatus =~ '0xC0000225',
                    'Evidently a bug in Windows and not a risk',
                    SubStatus =~ '0xC0000234',
                    'User logon with account locked',
                    SubStatus =~ '0xC00002EE',
                    'Failure Reason: An Error occurred during Logon',
                    SubStatus =~ '0xC0000413',
                    'Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine',
                    strcat('Unknown reason substatus: ', SubStatus)
                )
| extend WorkstationName = iff(WorkstationName == "-" or isempty(WorkstationName), Computer, WorkstationName)
| project
    StartTime,
    EndTime,
    EventID,
    Account,
    LogonTypeName,
    SubStatus,
    Reason,
    Status,	//Change (1)
    AccountType,
    Computer,
    WorkstationName,
    IpAddress,
    CountToday,
    CountPrev7day,
    Avg7Day = round(CountPrev7day * 1.00 / 7, 2),
    Process,
    AuthenticationPackageName,	//Change (2)
    LmPackageName,	//Change (3)
    LogonProcessName,	//Change (4)
    SubjectAccount	//Change (5)
| summarize
    StartTime = min(StartTime),
    EndTime = max(EndTime),
    Computer = make_set(Computer, 128),
    IpAddressList = make_set(IpAddress, 128),
    sum(CountToday),
    sum(CountPrev7day),
    avg(Avg7Day)
    by
    EventID,
    Account,
    LogonTypeName,
    SubStatus,
    Reason,
    Status,	//Change (1)
    AccountType,
    WorkstationName,
    Process,
    AuthenticationPackageName,	//Change (2)
    LmPackageName,	//Change (3)
    LogonProcessName,	//Change (4)
    SubjectAccount	//Change (5)
| order by sum_CountToday desc nulls last
| extend
    timestamp = StartTime,
    NTDomain = tostring(split(Account, '\\', 0)[0]),
    Name = tostring(split(Account, '\\', 1)[0]),
    HostName = tostring(split(WorkstationName, '.', 0)[0]),
    DnsDomain = tostring(strcat_array(array_slice(split(WorkstationName, '.'), 1, -1), '.'))
```

## Environment

SIEM Platform: Azure Sentinel  
Detection Rule Name/ID: Excessive Windows Logon Failures
