/* Lab content for the shared Wazuh SOC (Windows 11 endpoint AI-SOC-WIN11, agent 001).
   Sample alerts are illustrative and marked as such in the UI; real alerts come from Team 2. */
(function (root) {
  'use strict';
  var agent = { id: '001', name: 'AI-SOC-WIN11', ip: '192.168.56.101' };
  var manager = { name: 'ai-soc-server' };
  var ADMIN_SID = 'S-1-5-21-3874120598-1294467102-2981557330-1001';
  var TEST_SID = 'S-1-5-21-3874120598-1294467102-2981557330-1002';

  var SAMPLE_ALERTS = [
    {
      timestamp: '2026-11-09T09:12:41.207+0000',
      rule: {
        level: 10, description: 'Multiple Windows Logon Failures', id: '60204', frequency: 8, firedtimes: 1,
        mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] },
        groups: ['windows', 'windows_security', 'authentication_failures']
      },
      agent: agent, manager: manager, id: '1762679561.402118',
      decoder: { name: 'windows_eventchannel' },
      data: { win: {
        system: {
          providerName: 'Microsoft-Windows-Security-Auditing', eventID: '4625', level: '0', task: '12544',
          keywords: '0x8010000000000000', systemTime: '2026-11-09T09:12:33.5810442Z', eventRecordID: '18342',
          channel: 'Security', computer: 'DESKTOP-2KUSA93', severityValue: 'AUDIT_FAILURE',
          message: 'An account failed to log on. Account For Which Logon Failed: soc.test. Failure Reason: Unknown user name or bad password. Logon Type: 2.'
        },
        eventdata: {
          subjectUserSid: ADMIN_SID, subjectUserName: 'labadmin', subjectDomainName: 'DESKTOP-2KUSA93', subjectLogonId: '0x3a91f',
          targetUserSid: 'S-1-0-0', targetUserName: 'soc.test', targetDomainName: 'DESKTOP-2KUSA93',
          status: '0xc000006d', failureReason: '%%2313', subStatus: '0xc000006a', logonType: '2',
          logonProcessName: 'seclogo', authenticationPackageName: 'Negotiate', workstationName: 'DESKTOP-2KUSA93',
          processName: 'C:\\Windows\\System32\\svchost.exe', ipAddress: '::1', ipPort: '0'
        }
      } },
      location: 'EventChannel'
    },
    {
      timestamp: '2026-11-09T09:14:05.880+0000',
      rule: {
        level: 3, description: 'Windows Logon Success', id: '60106', firedtimes: 1,
        mitre: { id: ['T1078'], tactic: ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'], technique: ['Valid Accounts'] },
        groups: ['windows', 'windows_security', 'authentication_success']
      },
      agent: agent, manager: manager, id: '1762679645.415503',
      decoder: { name: 'windows_eventchannel' },
      data: { win: {
        system: {
          providerName: 'Microsoft-Windows-Security-Auditing', eventID: '4624', level: '0', task: '12544',
          keywords: '0x8020000000000000', systemTime: '2026-11-09T09:13:58.1294410Z', eventRecordID: '18351',
          channel: 'Security', computer: 'DESKTOP-2KUSA93', severityValue: 'AUDIT_SUCCESS',
          message: 'An account was successfully logged on. New Logon Account Name: soc.test. Logon Type: 2. Elevated Token: No.'
        },
        eventdata: {
          subjectUserSid: 'S-1-5-18', subjectUserName: 'DESKTOP-2KUSA93$', subjectDomainName: 'WORKGROUP', subjectLogonId: '0x3e7',
          targetUserSid: TEST_SID, targetUserName: 'soc.test', targetDomainName: 'DESKTOP-2KUSA93', targetLogonId: '0x4b2c11',
          logonType: '2', logonProcessName: 'seclogo', authenticationPackageName: 'Negotiate', workstationName: 'DESKTOP-2KUSA93',
          processName: 'C:\\Windows\\System32\\svchost.exe', ipAddress: '::1', ipPort: '0',
          elevatedToken: '%%1843', virtualAccount: '%%1843'
        }
      } },
      location: 'EventChannel'
    },
    {
      timestamp: '2026-11-09T09:16:22.341+0000',
      rule: {
        level: 12, description: 'Administrators Group Changed', id: '60154', firedtimes: 1,
        mitre: { id: ['T1484'], tactic: ['Defense Evasion', 'Privilege Escalation'], technique: ['Domain Policy Modification'] },
        groups: ['windows', 'windows_security', 'group_changed', 'win_group_changed']
      },
      agent: agent, manager: manager, id: '1762679782.427790',
      decoder: { name: 'windows_eventchannel' },
      data: { win: {
        system: {
          providerName: 'Microsoft-Windows-Security-Auditing', eventID: '4732', level: '0', task: '13826',
          keywords: '0x8020000000000000', systemTime: '2026-11-09T09:16:19.0072215Z', eventRecordID: '18366',
          channel: 'Security', computer: 'DESKTOP-2KUSA93', severityValue: 'AUDIT_SUCCESS',
          message: 'A member was added to a security-enabled local group. Group Name: Administrators.'
        },
        eventdata: {
          memberName: '-', memberSid: TEST_SID, targetUserName: 'Administrators', targetDomainName: 'Builtin', targetSid: 'S-1-5-32-544',
          subjectUserSid: ADMIN_SID, subjectUserName: 'labadmin', subjectDomainName: 'DESKTOP-2KUSA93', subjectLogonId: '0x3a91f',
          privilegeList: '-'
        }
      } },
      location: 'EventChannel'
    }
  ];

  /* Example AI output for the samples. Tokens (default order: real baseline, sample 2, sample 3):
     HOST_1 agent, IP_1 agent IP, HOST_2 manager, HOST_3 computer, SID_1/USER_1 soc.test, SID_2/USER_2 labadmin.
     Each example holds one claim the log contradicts. */
  var EXAMPLE_ANALYSES = [
    {
      severity: 'Medium',
      severity_reason: 'At least eight failed logons for one local account inside the rule window. Nothing in this alert shows a success, so Medium matches the Wazuh level.',
      attack_technique: { id: 'T1110', name: 'Brute Force' },
      hypotheses: [
        { text: 'Someone with access to HOST_3 is guessing the password of USER_1.', likelihood: 'High' },
        { text: 'This is a safe test event generated by Team 2 for the exercise.', likelihood: 'Medium' },
        { text: 'The account owner mistyped the password several times.', likelihood: 'Low' }
      ],
      claims: [
        { text: 'Wazuh correlation rule 60204 fired: multiple Windows logon failures.', type: 'fact', field: 'rule.id', value: '60204' },
        { text: 'The underlying Windows event is 4625, a failed logon.', type: 'fact', field: 'data.win.system.eventID', value: '4625' },
        { text: 'The targeted account is USER_1.', type: 'fact', field: 'data.win.eventdata.targetUserName', value: 'USER_1' },
        { text: 'The attempts came from another machine on the lab network.', type: 'fact', field: 'data.win.eventdata.ipAddress', value: 'IP_1' },
        { text: 'Sub-status 0xc000006a means the account exists and only the password was wrong, so the attacker knows a valid username.', type: 'inference', field: '', value: '' }
      ],
      response_options: [
        { action: 'Search for a successful logon (event 4624) for USER_1 in the minutes after these failures.', priority: 'Now' },
        { action: 'Confirm with Team 2 whether this matches their test window.', priority: 'Now' },
        { action: 'Check who used the Secondary Logon service on HOST_3 during this time.', priority: 'Soon' },
        { action: 'Set an account lockout threshold of 5 attempts on lab endpoints.', priority: 'Later' }
      ],
      unknowns: ['Whether any later logon for USER_1 succeeded.', 'Which local process launched the attempts.']
    },
    {
      severity: 'High',
      severity_reason: 'A successful logon for USER_1 came about a minute and a half after a burst of failed logons for the same account. Wazuh rates a single success as level 3, but this sequence is a common sign of a guessed password.',
      attack_technique: { id: 'T1078', name: 'Valid Accounts' },
      hypotheses: [
        { text: "USER_1's password was guessed and is now being used.", likelihood: 'High' },
        { text: 'This is a safe test event generated by Team 2 for the exercise.', likelihood: 'Medium' },
        { text: 'The account owner finally typed the right password.', likelihood: 'Low' }
      ],
      claims: [
        { text: 'This is a successful Windows logon, event 4624.', type: 'fact', field: 'data.win.system.eventID', value: '4624' },
        { text: 'The account that logged on is USER_1.', type: 'fact', field: 'data.win.eventdata.targetUserName', value: 'USER_1' },
        { text: 'It was a Remote Desktop logon (logon type 10).', type: 'fact', field: 'data.win.eventdata.logonType', value: '10' },
        { text: 'The session did not receive an elevated (admin) token.', type: 'fact', field: 'data.win.eventdata.elevatedToken', value: '%%1843' },
        { text: 'This success follows the failed attempts in INC-01 by about 90 seconds.', type: 'inference', field: '', value: '' }
      ],
      response_options: [
        { action: 'Ask the owner of USER_1 to confirm whether they made this logon.', priority: 'Now' },
        { action: 'Log off the USER_1 session on HOST_3 if the owner did not make it.', priority: 'Now' },
        { action: 'Reset the password for USER_1.', priority: 'Soon' },
        { action: 'Add a correlation rule: failed logons followed by a success for the same account.', priority: 'Later' }
      ],
      unknowns: ['Who started the session.', 'What the session did after logon.']
    },
    {
      severity: 'Critical',
      severity_reason: 'The account that was just brute-forced and then logged on was added to the local Administrators group two minutes later. That gives full control of HOST_3.',
      attack_technique: { id: 'T1098', name: 'Account Manipulation' },
      hypotheses: [
        { text: 'An attacker gave the compromised account admin rights to keep control of HOST_3.', likelihood: 'High' },
        { text: 'This is a safe test event generated by Team 2 for the exercise.', likelihood: 'Medium' },
        { text: 'An administrator made an approved change without a ticket.', likelihood: 'Low' }
      ],
      claims: [
        { text: 'Wazuh rule 60154 fired: Administrators group changed.', type: 'fact', field: 'rule.id', value: '60154' },
        { text: 'Windows event 4732: a member was added to a security-enabled local group.', type: 'fact', field: 'data.win.system.eventID', value: '4732' },
        { text: 'The group is the built-in Administrators group.', type: 'fact', field: 'data.win.eventdata.targetSid', value: 'S-1-5-32-544' },
        { text: 'The account added is the same account that logged on in INC-02.', type: 'fact', field: 'data.win.eventdata.memberSid', value: 'SID_1' },
        { text: 'USER_1 added itself to the Administrators group.', type: 'fact', field: 'data.win.eventdata.subjectUserName', value: 'USER_1' },
        { text: 'Together with INC-01 and INC-02 this forms one attack chain: guess the password, log on, take admin rights.', type: 'inference', field: '', value: '' }
      ],
      response_options: [
        { action: 'Remove USER_1 from the Administrators group on HOST_3.', priority: 'Now' },
        { action: 'Disable USER_1 until the investigation is closed.', priority: 'Now' },
        { action: 'Ask the owner of the account that made the change why it was made.', priority: 'Now' },
        { action: 'Review every account and group change (events 4720, 4732, 4738) on HOST_3 today.', priority: 'Soon' },
        { action: 'Send every Administrators group change straight to the Command Center.', priority: 'Later' }
      ],
      unknowns: ['Whether the account that made the change was itself misused.', 'Whether other persistence was added.']
    }
  ];


  /* Real alert from Team 1's baseline test (8 Nov 2026), exactly as exported from Wazuh. */
  var BASELINE_DOC = {
    "_index": "wazuh-alerts-4.x-2026.11.08",
    "_id": "HFXuvKEB_cPlIJWCZtdO",
    "_score": null,
    "_source": {
      "input": {
        "type": "log"
      },
      "agent": {
        "ip": "192.168.56.101",
        "name": "AI-SOC-WIN11",
        "id": "001"
      },
      "manager": {
        "name": "ai-soc-server"
      },
      "data": {
        "win": {
          "eventdata": {
            "subjectLogonId": "0x3e7",
            "subjectDomainName": "WORKGROUP",
            "ipAddress": "127.0.0.1",
            "authenticationPackageName": "Negotiate",
            "subStatus": "0xc0000380",
            "logonProcessName": "User32",
            "keyLength": "0",
            "subjectUserSid": "S-1-5-18",
            "processId": "0x5f8",
            "processName": "C:\\\\Windows\\\\System32\\\\svchost.exe",
            "ipPort": "0",
            "failureReason": "%%2304",
            "targetUserSid": "S-1-0-0",
            "logonType": "2",
            "subjectUserName": "DESKTOP-2KUSA93$",
            "status": "0xc000006d"
          },
          "system": {
            "eventID": "4625",
            "keywords": "0x8010000000000000",
            "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "level": "0",
            "channel": "Security",
            "opcode": "0",
            "message": "\"An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-2KUSA93$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Type:\t\t\t2\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t-\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tAn Error occured during Logon.\r\n\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC0000380\r\n\r\nProcess Information:\r\n\tCaller Process ID:\t0x5f8\r\n\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\r\n\r\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe Process Information fields indicate which account and process on the system requested the logon.\r\n\r\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"",
            "version": "0",
            "systemTime": "2026-11-08T20:48:07.5436490Z",
            "eventRecordID": "24745",
            "threadID": "3076",
            "computer": "DESKTOP-2KUSA93",
            "task": "12544",
            "processID": "816",
            "severityValue": "AUDIT_FAILURE",
            "providerName": "Microsoft-Windows-Security-Auditing"
          }
        }
      },
      "rule": {
        "mail": false,
        "level": 5,
        "pci_dss": [
          "10.2.4",
          "10.2.5"
        ],
        "hipaa": [
          "164.312.b"
        ],
        "tsc": [
          "CC6.1",
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ],
        "description": "Logon Failure - Unknown user or bad password",
        "groups": [
          "windows",
          "windows_security",
          "authentication_failed"
        ],
        "nist_800_53": [
          "AU.14",
          "AC.7"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "firedtimes": 1,
        "mitre": {
          "technique": [
            "Account Access Removal"
          ],
          "id": [
            "T1531"
          ],
          "tactic": [
            "Impact"
          ]
        },
        "id": "60122",
        "gpg13": [
          "7.1"
        ]
      },
      "location": "EventChannel",
      "decoder": {
        "name": "windows_eventchannel"
      },
      "id": "1794171096.3404653",
      "timestamp": "2026-11-08T20:51:36.296+0000"
    },
    "fields": {
      "timestamp": [
        "2026-11-08T20:51:36.296Z"
      ]
    },
    "sort": [
      1794171096296
    ]
  };

  /* Claude's analysis of the real baseline alert, written from the redacted prompt. No planted errors. */
  var BASELINE_ANALYSIS = {
    severity: 'Low',
    severity_reason: 'One failed interactive logon at the machine\'s own sign-in screen, with no network source and no follow-up in this alert. That matches the Wazuh level 5.',
    attack_technique: { id: 'T1110', name: 'Brute Force (only if more failures follow)' },
    hypotheses: [
      { text: 'Team 1 typed a wrong PIN or password on purpose for their baseline test.', likelihood: 'High' },
      { text: 'A user mistyped their Windows Hello PIN at the HOST_3 sign-in screen.', likelihood: 'Medium' },
      { text: 'Someone with console access to HOST_3 tried to sign in.', likelihood: 'Low' }
    ],
    claims: [
      { text: 'Wazuh rule 60122 fired: logon failure, unknown user or bad password.', type: 'fact', field: 'rule.id', value: '60122' },
      { text: 'The underlying Windows event is 4625, a failed logon.', type: 'fact', field: 'data.win.system.eventID', value: '4625' },
      { text: 'It was an interactive logon at the machine\'s own sign-in screen (logon type 2).', type: 'fact', field: 'data.win.eventdata.logonType', value: '2' },
      { text: 'The attempt came from the machine itself, not from the network.', type: 'fact', field: 'data.win.eventdata.ipAddress', value: '127.0.0.1' },
      { text: 'Windows did not record which account was tried (null SID).', type: 'fact', field: 'data.win.eventdata.targetUserSid', value: 'S-1-0-0' },
      { text: 'The failure sub-status is 0xc0000380.', type: 'fact', field: 'data.win.eventdata.subStatus', value: '0xc0000380' },
      { text: 'Sub-status 0xc0000380 is the code Windows uses for a wrong PIN or smart-card credential, so this was most likely a wrong Windows Hello PIN, not a wrong password as the rule name suggests.', type: 'inference', field: '', value: '' },
      { text: 'A single failure is not an attack on its own; it matters only if more failures or a success follow.', type: 'inference', field: '', value: '' }
    ],
    response_options: [
      { action: 'Confirm with Team 1 that this was their test at 20:48 UTC on 8 November.', priority: 'Now' },
      { action: 'Search HOST_3 for more 4625 events or a 4624 success around that time.', priority: 'Soon' },
      { action: 'Close as a lab test once Team 1 confirms.', priority: 'Soon' },
      { action: 'Compare the clocks of HOST_3 and HOST_2 to explain the 3.5-minute gap between event and alert.', priority: 'Later' }
    ],
    unknowns: ['Which account was tried.', 'Whether the 3 min 29 s gap is ingestion delay or a clock difference between the Windows VM and the Wazuh server.']
  };


  /* Real alert: account change on the lab VM, 8 Nov 2026 (rule 60110), exactly as exported from Wazuh. */
  var REAL_INC03_DOC = {
    "_index": "wazuh-alerts-4.x-2026.11.08",
    "_id": "IVXuvKEB_cPlIJWCZtdP",
    "_score": null,
    "_source": {
      "input": {
        "type": "log"
      },
      "agent": {
        "ip": "192.168.56.101",
        "name": "AI-SOC-WIN11",
        "id": "001"
      },
      "manager": {
        "name": "ai-soc-server"
      },
      "data": {
        "win": {
          "eventdata": {
            "subjectLogonId": "0x3e7",
            "targetUserName": "labuser",
            "subjectUserSid": "S-1-5-18",
            "subjectDomainName": "WORKGROUP",
            "displayName": "Lab User",
            "targetDomainName": "DESKTOP-2KUSA93",
            "targetSid": "S-1-5-21-3660433104-1980362115-1287893582-1001",
            "subjectUserName": "DESKTOP-2KUSA93$"
          },
          "system": {
            "eventID": "4738",
            "keywords": "0x8020000000000000",
            "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "level": "0",
            "channel": "Security",
            "opcode": "0",
            "message": "\"A user account was changed.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-2KUSA93$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nTarget Account:\r\n\tSecurity ID:\t\tS-1-5-21-3660433104-1980362115-1287893582-1001\r\n\tAccount Name:\t\tlabuser\r\n\tAccount Domain:\t\tDESKTOP-2KUSA93\r\n\r\nChanged Attributes:\r\n\tSAM Account Name:\t-\r\n\tDisplay Name:\t\tLab User\r\n\tUser Principal Name:\t-\r\n\tHome Directory:\t\t-\r\n\tHome Drive:\t\t-\r\n\tScript Path:\t\t-\r\n\tProfile Path:\t\t-\r\n\tUser Workstations:\t-\r\n\tPassword Last Set:\t-\r\n\tAccount Expires:\t\t-\r\n\tPrimary Group ID:\t-\r\n\tAllowedToDelegateTo:\t-\r\n\tOld UAC Value:\t\t-\r\n\tNew UAC Value:\t\t-\r\n\tUser Account Control:\t-\r\n\tUser Parameters:\t-\r\n\tSID History:\t\t-\r\n\tLogon Hours:\t\t-\r\n\r\nAdditional Information:\r\n\tPrivileges:\t\t-\"",
            "version": "0",
            "systemTime": "2026-11-08T20:48:11.3225974Z",
            "eventRecordID": "24755",
            "threadID": "1188",
            "computer": "DESKTOP-2KUSA93",
            "task": "13824",
            "processID": "816",
            "severityValue": "AUDIT_SUCCESS",
            "providerName": "Microsoft-Windows-Security-Auditing"
          }
        }
      },
      "rule": {
        "mail": false,
        "level": 8,
        "pci_dss": [
          "8.1.2",
          "10.2.5"
        ],
        "hipaa": [
          "164.312.a.2.I",
          "164.312.a.2.II",
          "164.312.b"
        ],
        "tsc": [
          "CC6.8",
          "CC7.2",
          "CC7.3"
        ],
        "description": "User account changed",
        "groups": [
          "windows",
          "windows_security",
          "account_changed"
        ],
        "nist_800_53": [
          "AC.2",
          "IA.4",
          "AU.14",
          "AC.7"
        ],
        "gdpr": [
          "IV_35.7.d",
          "IV_32.2"
        ],
        "firedtimes": 4,
        "mitre": {
          "technique": [
            "Account Manipulation"
          ],
          "id": [
            "T1098"
          ],
          "tactic": [
            "Persistence"
          ]
        },
        "id": "60110",
        "gpg13": [
          "7.10"
        ]
      },
      "location": "EventChannel",
      "decoder": {
        "name": "windows_eventchannel"
      },
      "id": "1794171099.3433247",
      "timestamp": "2026-11-08T20:51:39.639+0000"
    },
    "fields": {
      "timestamp": [
        "2026-11-08T20:51:39.639Z"
      ]
    },
    "sort": [
      1794171099639
    ]
  };

  /* Claude's analysis of the real INC-03 alert. Written with real values; the console swaps them for
     tokens before display, so the AI-facing text and the checks use the same tokens as the redacted alert. */
  var REAL_INC03_ANALYSIS = {
    severity: 'Low',
    severity_reason: 'Wazuh rates every account change level 8 (Medium). Here the change was made by SYSTEM four seconds after a sign-in attempt, and the only attribute with a value is the display name: no password, group or account-control change. That looks like routine Windows behaviour at sign-in.',
    attack_technique: { id: 'T1098', name: 'Account Manipulation (Wazuh mapping)' },
    hypotheses: [
      { text: 'Windows refreshed the display name of labuser automatically during sign-in.', likelihood: 'High' },
      { text: 'Team 1 set the display name to "Lab User" while preparing the lab VM.', likelihood: 'Medium' },
      { text: 'Someone tampered with the account labuser.', likelihood: 'Low' }
    ],
    claims: [
      { text: 'Wazuh rule 60110 fired: user account changed.', type: 'fact', field: 'rule.id', value: '60110' },
      { text: 'The underlying Windows event is 4738, a user account was changed.', type: 'fact', field: 'data.win.system.eventID', value: '4738' },
      { text: 'The account that was changed is labuser.', type: 'fact', field: 'data.win.eventdata.targetUserName', value: 'labuser' },
      { text: 'The change was made by the operating system itself (SYSTEM, S-1-5-18), not by a person.', type: 'fact', field: 'data.win.eventdata.subjectUserSid', value: 'S-1-5-18' },
      { text: 'The attribute recorded in the event is the display name, now "Lab User".', type: 'fact', field: 'data.win.eventdata.displayName', value: 'Lab User' },
      { text: 'Windows logged the change at 20:48:11 UTC, four seconds after the failed logon in INC-01.', type: 'fact', field: 'data.win.system.systemTime', value: '20:48:11' },
      { text: 'Rule 60110 fired 4 times in this burst.', type: 'fact', field: 'rule.firedtimes', value: '4' },
      { text: 'Every other attribute in the event message is "-", so no password, group membership or account-control setting changed.', type: 'inference', field: '', value: '' },
      { text: 'The alert arrived about 3 min 28 s after the event, the same gap as INC-01. A constant gap points to the Windows VM clock running behind the Wazuh server, not to a slow pipeline.', type: 'inference', field: '', value: '' }
    ],
    response_options: [
      { action: 'Ask Team 1 whether "Lab User" is the expected display name for labuser.', priority: 'Now' },
      { action: 'Open the other three rule 60110 alerts from 21:51 and check none changed a password, group or account-control value.', priority: 'Soon' },
      { action: 'Sync the Windows VM clock with the Wazuh server (time.windows.com or the host).', priority: 'Soon' },
      { action: 'Lower account changes made by SYSTEM that touch only the display name to level 3, so level 8 means something.', priority: 'Later' }
    ],
    unknowns: ['What the other three 4738 events in the burst changed.', 'Whether the display name was set by a person earlier.']
  };


  /* Real alert: screen unlock on the lab VM, 8 Nov 2026 (rule 67022), exactly as exported from Wazuh. */
  var REAL_INC02_DOC = {
    "_index": "wazuh-alerts-4.x-2026.11.08",
    "_id": "IlXuvKEB_cPlIJWCZtdP",
    "_score": null,
    "_source": {
      "input": {
        "type": "log"
      },
      "agent": {
        "ip": "192.168.56.101",
        "name": "AI-SOC-WIN11",
        "id": "001"
      },
      "manager": {
        "name": "ai-soc-server"
      },
      "data": {
        "win": {
          "eventdata": {
            "subjectLogonId": "0x3e7",
            "subjectDomainName": "WORKGROUP",
            "targetLinkedLogonId": "0x5d4f0ab",
            "impersonationLevel": "%%1833",
            "authenticationPackageName": "Negotiate",
            "workstationName": "DESKTOP-2KUSA93",
            "targetLogonId": "0x5d4f03e",
            "logonProcessName": "Negotiat",
            "logonGuid": "{00000000-0000-0000-0000-000000000000}",
            "targetUserName": "lab.user@example.com",
            "keyLength": "0",
            "elevatedToken": "%%1842",
            "subjectUserSid": "S-1-5-18",
            "processId": "0x330",
            "processName": "C:\\\\Windows\\\\System32\\\\lsass.exe",
            "targetDomainName": "MicrosoftAccount",
            "targetUserSid": "S-1-5-21-3660433104-1980362115-1287893582-1001",
            "virtualAccount": "%%1843",
            "logonType": "7",
            "subjectUserName": "DESKTOP-2KUSA93$"
          },
          "system": {
            "eventID": "4624",
            "keywords": "0x8020000000000000",
            "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "level": "0",
            "channel": "Security",
            "opcode": "0",
            "message": "\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-2KUSA93$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t7\r\n\tRestricted Admin Mode:\t-\r\n\tRemote Credential Guard:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-3660433104-1980362115-1287893582-1001\r\n\tAccount Name:\t\tlab.user@example.com\r\n\tAccount Domain:\t\tMicrosoftAccount\r\n\tLogon ID:\t\t0x5D4F03E\r\n\tLinked Logon ID:\t\t0x5D4F0AB\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x330\r\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-2KUSA93\r\n\tSource Network Address:\t-\r\n\tSource Port:\t\t-\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tNegotiat\r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"",
            "version": "3",
            "systemTime": "2026-11-08T20:48:11.3401030Z",
            "eventRecordID": "24757",
            "threadID": "1188",
            "computer": "DESKTOP-2KUSA93",
            "task": "12544",
            "processID": "816",
            "severityValue": "AUDIT_SUCCESS",
            "providerName": "Microsoft-Windows-Security-Auditing"
          }
        }
      },
      "rule": {
        "firedtimes": 7,
        "mail": false,
        "level": 3,
        "description": "Non network or service local logon.",
        "groups": [
          "windows",
          " WEF"
        ],
        "id": "67022"
      },
      "location": "EventChannel",
      "decoder": {
        "name": "windows_eventchannel"
      },
      "id": "1794171099.3436894",
      "timestamp": "2026-11-08T20:51:39.670+0000"
    },
    "fields": {
      "timestamp": [
        "2026-11-08T20:51:39.670Z"
      ]
    },
    "sort": [
      1794171099670
    ]
  };

  /* Claude's analysis of the real INC-02 alert, written with real values (tokenized before display). */
  var REAL_INC02_ANALYSIS = {
    severity: 'Low',
    severity_reason: 'This is the locked screen being unlocked (logon type 7) at the console, four seconds after one wrong PIN. That fits a corrected typo, not an attack. The session runs with an elevated admin token, which is worth noting but is not suspicious on its own.',
    attack_technique: { id: 'T1078', name: 'Valid Accounts' },
    hypotheses: [
      { text: 'The account owner mistyped the PIN on the lock screen and unlocked on the next try.', likelihood: 'High' },
      { text: 'Team 1 unlocked the VM while preparing the baseline test.', likelihood: 'Medium' },
      { text: 'Someone else who knows the PIN unlocked the console.', likelihood: 'Low' }
    ],
    claims: [
      { text: 'Wazuh rule 67022 fired: a local, non-network logon succeeded.', type: 'fact', field: 'rule.id', value: '67022' },
      { text: 'The underlying Windows event is 4624, a successful logon.', type: 'fact', field: 'data.win.system.eventID', value: '4624' },
      { text: 'Logon type 7 means the locked screen was unlocked; it is not a new sign-in and not a remote session.', type: 'fact', field: 'data.win.eventdata.logonType', value: '7' },
      { text: 'The account that unlocked is the Microsoft account lab.user@example.com.', type: 'fact', field: 'data.win.eventdata.targetUserName', value: 'lab.user@example.com' },
      { text: 'It is the same account that was changed in INC-03 (same SID).', type: 'fact', field: 'data.win.eventdata.targetUserSid', value: 'S-1-5-21-3660433104-1980362115-1287893582-1001' },
      { text: 'The session holds an elevated token (%%1842 means Yes), so the account is a local administrator.', type: 'fact', field: 'data.win.eventdata.elevatedToken', value: '%%1842' },
      { text: 'Windows logged the unlock at 20:48:11 UTC, four seconds after the failed logon in INC-01.', type: 'fact', field: 'data.win.system.systemTime', value: '20:48:11' },
      { text: 'Together with INC-01 this reads as a wrong PIN on the lock screen corrected four seconds later, not password guessing.', type: 'inference', field: '', value: '' },
      { text: 'A separate alert at 20:48:10 (rule 67028, event 4672) shows the same account received administrator privileges such as SeDebugPrivilege, so an admin account is used for everyday work.', type: 'inference', field: '', value: '' }
    ],
    response_options: [
      { action: 'Confirm with Team 1 that the owner of lab.user@example.com unlocked the VM at 20:48 UTC.', priority: 'Now' },
      { action: 'Use a standard account for daily work on the lab VM and keep admin rights for a separate account.', priority: 'Soon' },
      { action: 'Add a rule that alerts when a failed logon is followed within 60 seconds by an elevated logon for the same account.', priority: 'Later' }
    ],
    unknowns: ['Whether the person at the console was the account owner.', 'What was done in the session after the unlock.']
  };

  /* Token map the sample example analyses were written against; the console moves them onto the live map. */
  var SAMPLE_TOKENS = [
    { token: 'HOST_1', value: 'AI-SOC-WIN11' }, { token: 'HOST_2', value: 'ai-soc-server' }, { token: 'HOST_3', value: 'DESKTOP-2KUSA93' },
    { token: 'IP_1', value: '192.168.56.101' }, { token: 'USER_1', value: 'soc.test' }, { token: 'USER_2', value: 'labadmin' },
    { token: 'SID_1', value: 'S-1-5-21-3874120598-1294467102-2981557330-1002' }, { token: 'SID_2', value: 'S-1-5-21-3874120598-1294467102-2981557330-1001' }
  ];

  /* ---------- Team 2: test plan for the real lab ---------- */

  var SETUP = [
    '# Run once, in PowerShell as Administrator, on the Windows test VM (AI-SOC-WIN11).',
    '# 1. Check auditing. Expect "Success and Failure" for Logon and "Success" for the other two.',
    'auditpol /get /subcategory:"Logon","User Account Management","Security Group Management"',
    '',
    '# Only if one of them shows "No Auditing":',
    'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
    'auditpol /set /subcategory:"User Account Management" /success:enable',
    'auditpol /set /subcategory:"Security Group Management" /success:enable',
    '',
    '# 2. Create the lab test account. You type the password; nothing is stored in this script.',
    "$pw = Read-Host 'Choose a password for soc.test' -AsSecureString",
    "New-LocalUser -Name 'soc.test' -Password $pw -Description 'AI-SOC lab test account - delete after the exercise'"
  ].join('\n');

  var CLEANUP = [
    '# After the demo, in PowerShell as Administrator on AI-SOC-WIN11:',
    "Remove-LocalGroupMember -Group 'Administrators' -Member 'soc.test'",
    "Remove-LocalUser -Name 'soc.test'"
  ].join('\n');

  var SCENARIOS = [
    {
      title: 'Failed logins',
      what: 'Repeated wrong passwords for one account: the first sign of password guessing.',
      events: [['4625', 'Failed logon']],
      expectRules: ['60204', '60122'],
      expectText: 'Rule 60122 (level 5) for each failure, then rule 60204 "Multiple Windows Logon Failures" (level 10) once 8 failures land within 4 minutes.',
      handoff: 'Hand over the 60204 alert. If it did not fire, hand over the last 60122 alert.',
      commands: [
        '# Scenario 1: 9 wrong passwords for soc.test (stays under the Windows 11 default lockout of 10).',
        "$bad  = ConvertTo-SecureString 'Not-The-Password-1' -AsPlainText -Force",
        "$cred = New-Object System.Management.Automation.PSCredential('soc.test', $bad)",
        '1..9 | ForEach-Object {',
        "  try { Start-Process cmd.exe -ArgumentList '/c exit' -Credential $cred -WindowStyle Hidden -ErrorAction Stop }",
        '  catch { Write-Host "Attempt $_ failed, as expected" }',
        '  Start-Sleep -Seconds 2',
        '}'
      ].join('\n'),
      query: 'agent.name:AI-SOC-WIN11 and rule.id:(60204 or 60122)'
    },
    {
      title: 'Unusual access',
      what: 'A successful logon for the account that was just under attack. Wazuh alone rates it Low, which is exactly the gap AI analysis and a human must close.',
      events: [['4624', 'Successful logon']],
      expectRules: ['60106', '67022', '67028'],
      expectText: 'A logon-success rule: 60106 "Windows Logon Success" or, on this Wazuh version, 67022 "Non network or service local logon" (level 3); 67028 marks admin privileges on the new logon.',
      handoff: 'Hand over the 60106 alert for soc.test, not the many SYSTEM logons around it.',
      commands: [
        '# Scenario 2: log on as soc.test with the real password, within 2 minutes of scenario 1.',
        "$cred = Get-Credential -UserName 'soc.test' -Message 'Enter the real soc.test password'",
        "Start-Process cmd.exe -ArgumentList '/c whoami' -Credential $cred -WindowStyle Hidden"
      ].join('\n'),
      query: 'agent.name:AI-SOC-WIN11 and rule.id:(60106 or 67022 or 67028) and data.win.eventdata.targetUserName:soc.test'
    },
    {
      title: 'Sensitive change',
      what: 'The attacked account gets local admin rights: the change that turns a guessed password into full control of the machine.',
      events: [['4732', 'Member added to a security-enabled local group']],
      expectRules: ['60154', '60110', '60109'],
      expectText: 'Rule 60154 "Administrators Group Changed" (level 12). Account changes also raise 60110 "User account changed" (level 8) and account creation 60109.',
      handoff: 'Hand over the 60154 alert.',
      commands: [
        '# Scenario 3: add soc.test to the local Administrators group, within 2 minutes of scenario 2.',
        "Add-LocalGroupMember -Group 'Administrators' -Member 'soc.test'"
      ].join('\n'),
      query: 'agent.name:AI-SOC-WIN11 and rule.id:60154'
    }
  ];

  // Optional local rule for scenario 2. Only Team 1 may add it, and only after testing.
  var CUSTOM_RULE = [
    '<!-- /var/ossec/etc/rules/local_rules.xml on ai-soc-server (Team 1 only) -->',
    '<group name="local,windows,authentication_success,">',
    '  <rule id="100110" level="10" timeframe="300">',
    '    <if_sid>60106</if_sid>',
    '    <if_matched_sid>60122</if_matched_sid>',
    '    <same_field>win.eventdata.targetUserName</same_field>',
    '    <description>Windows logon success after failed attempts for $(win.eventdata.targetUserName)</description>',
    '    <mitre><id>T1110</id><id>T1078</id></mitre>',
    '  </rule>',
    '</group>',
    '',
    '<!-- Then: sudo /var/ossec/bin/wazuh-analysisd -t  (syntax check)',
    '     and:  sudo systemctl restart wazuh-manager -->'
  ].join('\n');

  /* ---------- Team 4: response playbook ---------- */

  var SLA = { Critical: '15 minutes', High: '1 hour', Medium: '4 hours', Low: '1 working day' };

  var PLAYBOOKS = [
    {
      title: 'Failed logins',
      triage: ['Read the target account, logon type and source address in the alert.', 'Look for a 4624 success or a 4740 lockout for the same account right after.'],
      contain: ['If a success follows: disable the account.', 'If the source is remote: block it at the host firewall.'],
      eradicate: ['Reset the account password.'],
      recover: ['Re-enable the account once the owner confirms.'],
      learn: ['Lower the lockout threshold on lab endpoints.', 'Keep rule 60204 routed to Team 3.']
    },
    {
      title: 'Unusual access',
      triage: ['Ask the account owner whether they made the logon.', 'Check logon type, source and whether the token was elevated.'],
      contain: ['Log the session off (quser, then logoff <id>).', 'Disable the account if the owner did not log on.'],
      eradicate: ['Reset credentials and review processes started by the account.'],
      recover: ['Restore access with a new password.'],
      learn: ['Add a correlation rule for success after failures (rule 100110).']
    },
    {
      title: 'Sensitive change',
      triage: ['Find who made the change (subjectUserName) and whether it was approved.', 'Confirm which account was added (memberSid).'],
      contain: ['Remove the account from Administrators.', 'Disable the added account.'],
      eradicate: ['Review all account and group changes (4720, 4732, 4738) and new services or scheduled tasks.'],
      recover: ['Restore least privilege; keep admin membership to named admins only.'],
      learn: ['Require a ticket for admin group changes.', 'Page Team 4 on every level 12+ alert.']
    }
  ];

  var api = {
    SAMPLE_ALERTS: SAMPLE_ALERTS, EXAMPLE_ANALYSES: EXAMPLE_ANALYSES, BASELINE_DOC: BASELINE_DOC, BASELINE_ANALYSIS: BASELINE_ANALYSIS,
    REAL: [{ doc: BASELINE_DOC, analysis: BASELINE_ANALYSIS }, { doc: REAL_INC02_DOC, analysis: REAL_INC02_ANALYSIS }, { doc: REAL_INC03_DOC, analysis: REAL_INC03_ANALYSIS }],
    SAMPLE_TOKENS: SAMPLE_TOKENS,
    SETUP: SETUP, CLEANUP: CLEANUP, SCENARIOS: SCENARIOS, CUSTOM_RULE: CUSTOM_RULE,
    SLA: SLA, PLAYBOOKS: PLAYBOOKS
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.LabData = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
