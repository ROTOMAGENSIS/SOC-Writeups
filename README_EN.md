# BEC-KY — Business Email Compromise Investigation in Microsoft 365

> Blue Team Labs Online | BEC | Phishing | Microsoft 365 | Azure Audit Logs

[🇫🇷 Français](./README.md) | 🇬🇧 English

## Executive Summary

The organization suspects an incident involving **unauthorized but apparently legitimate bank transfers** from the company's pension fund to multiple external accounts. The **Chief Financial Officer (CFO)** account is particularly sensitive because it has the authority required to approve these transactions.

The investigation identified a **Business Email Compromise (BEC)** attack. The incident began with a **phishing email** containing a link to a fake Microsoft authentication portal.

The message came from the legitimate address: **sabastian@flanaganspensions[.]co[.]uk**

The malicious link redirected to a domain designed to imitate a legitimate Microsoft login portal: `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu`

The email was dated **July 2, 2025, at 15:40**. The collected evidence indicates that the CFO's credentials were compromised and subsequently used to access her account.

**Two IP addresses** were associated with the threat actor:

- `159.203.17[.]81`

- `95.181.232[.]30`

Following the compromise, the attacker performed two actions intended to conceal their activity:

- The first was an inbox rule looking for the word **Withdrawal** in the subject or body of messages before deleting them.

- The second involved the **History** folder, which was used to move selected emails away from the legitimate user's normal view.

The analysis of an email related to one transaction identified the destination bank as **First Bank of Nigeria LTD**.

The observed attack chain was:

1. Phishing
2. Credential theft through the fake portal
3. CFO account takeover
4. Mailbox access
5. Creation of concealment rules
6. Interception/deletion of financial alerts
7. Fraudulent bank transfer

The compromise was assessed as **Critical** because of the authority of the compromised account, the manipulation of mailbox rules, and the direct financial impact.

## Context and Scope

Over a period of approximately 48 hours, the organization identified a significant number of transfers processed from its pension fund. Funds had been transferred to several external bank accounts, including international accounts.

The transactions appeared to have been properly authorized. The organization therefore suspected the compromise of a user with sufficient privileges to approve payments, particularly the CFO.

The **main hypothesis** was:

A threat actor compromised the CFO's Microsoft 365 account and then used her identity and mailbox access to facilitate or conceal fraudulent financial transactions.

## Available Data Sources

The investigation was based on **four emails** and an **Azure activity log**.
- One phishing email: `No subject.eml`
- Two internal emails: `Re_PensionApproval.eml` and `Re_20250701-Pension Fund Withdrawals.eml`
- One fraudulent email sent from the compromised CFO account: `20250702-Withdrawal-Bernard.eml`

The Azure activity log contains detailed information in JSON format, including the affected user, operation performed, timestamps, IP addresses, identifiers, mailbox rules and parameters, and Exchange objects.

Several operations were particularly relevant to the investigation:
- `UserLoggedIn`: identify a successful authentication
- `UserLoginFailed`: identify a failed authentication
- `MailItemsAccessed`: detect access to mailbox items
- `New-InboxRule`: identify the creation of an inbox rule
- `Send`: identify an email being sent
- `New-MailboxFolder`: identify the creation of an Exchange mailbox folder

## Investigation Methodology

The initial email, received on **Wednesday, July 2, 2025, at 15:40:37 +0000**, provided the sender address, send time, embedded links, actual domains in use, and indicators of impersonation. The observed URL, `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu`, reveals that the actual registered domain is **`copilotweb[.]co`**. The additional terms `login`, `portal`, and `microsoft` are subdomains intended to mislead the victim. A legitimate Microsoft authentication portal would use a domain controlled by Microsoft rather than a subdomain of `copilotweb[.]co`.

The compromise then had to be detected and correctly classified. Unauthorized access to the account constitutes an **Account Takeover (ATO)**. However, because the attacker's ultimate objective was to perform and conceal fraudulent financial activity through a business email account, the incident is classified as a **Business Email Compromise (BEC)**.

**ATO** describes the technical compromise of the account, whereas **BEC** describes the broader fraud operation.

### Identification of Malicious IP Addresses

We used the `UserLoggedIn` and `UserLoginFailed` events to identify relevant IP addresses, focusing on Becky's account (`becky.lorray@tempestasenergy[.]com`) to filter the data.

Because the phishing email was received at **15:40:37**, we looked for `UserLoggedIn` events occurring shortly afterward. This would support the hypothesis that the attacker obtained Becky's credentials through the fake portal and then accessed her account. The IP address `159.203.17[.]81` was associated with `UserLoggedIn` events at **15:41:57** and **15:42:07** through fields such as `ClientIP`, `ClientIPAddress`, and `ActorIPAddress`.

A `UserLoginFailed` event associated with the same IP was also observed at **15:25:14**. We therefore hypothesize that the attacker attempted to access Liam's account (`liam.fray@tempestasenergy[.]com`) before successfully accessing Becky's account.

The second malicious IP address, **`95.181.232[.]30`**, was first identified through `UserLoggedIn` events associated with Becky at **15:45:05, 15:45:09, 15:45:10, and 15:49:39**. It was then corroborated by `New-InboxRule` events at **15:48:39** and **15:58:42**, which show that the attacker manipulated Becky's mailbox rules.

We used **Notepad++** to review the data, although **grep** through WSL can also be used to search and isolate specific terms, especially when working with a large activity log.

For example:

```bash
grep -E 'UserLoggedIn|UserLoginFailed' azure-export-audit-dfir.csv \
  | grep -oE '"ClientIP":"[^"]*"' \
  | sort -u
```

**Real-world environment:** With access to the organization's normal network information, an analyst could establish a baseline and identify unknown IP addresses and abnormal activity more efficiently.

IP enrichment associated `95.181.232[.]30` with Morocco and `159.203.17[.]81` with the United States. This information should only be treated as contextual enrichment and does not establish the attacker's physical location, especially because VPNs, proxies, hosted infrastructure, or other intermediaries may have been used.

### Inbox Rule Analysis

We filtered `New-InboxRule` events to identify rules created during the compromise. Two relevant events were observed.
1. At **15:48:39**, a rule was created to delete messages containing the word **Withdrawal** in the subject or body (`SubjectOrBodyContainsWords`) when they were sent by (`From`) **Sabastian** (`sabastian@flanaganspensions[.]co[.]uk`).
2. At **15:58:42**, a second rule moved messages sent to (`SentTo`) **Sabastian** into the **History** folder (`MoveToFolder`).

### Compromise Hypothesis

**Becky** is the CFO of **Tempestas Energy**. As CFO, any withdrawal from the pension fund requires her direct approval, as indicated in the `Re_20250701-Pension Fund Withdrawals` email. **Sabastian** is the Director of **Flanagans Pensions**. The two agreed by phone on July 2 at 12:54 on a formal withdrawal approval process, as confirmed in the `PensionApproval` email.

Analysis of the phishing email headers shows that **SPF** and **DMARC** passed for `flanaganspensions.co.uk`. This leads us to hypothesize that Sabastian's account **may already have been compromised**. The attacker could then have used this trusted account to send the spearphishing email to Becky. This hypothesis is plausible because it could explain why the attacker targeted **Becky**, as well as **Liam**, who was copied on the `PensionApproval` email and later appeared in a `UserLoginFailed` event.

After compromising Becky's account, the attacker created a rule to delete messages from Sabastian containing the term **Withdrawal**. This would allow the attacker to control the communication flow and prevent Becky from seeing confirmations, verification requests, or alerts related to fraudulent withdrawals sent from her own account.

Importantly, the rule did not delete every message from Sabastian, making the concealment mechanism more discreet.

This explains why Sabastian's address appears in three different roles:
- as the apparent source of the phishing email;
- as the sender targeted by the deletion rule;
- as the recipient of the fraudulent withdrawal request sent from Becky's account.

### Correlation with the Financial Email

The `20250702-Withdrawal-Bernard` email, dated **July 2, 2025, at 15:57:23**, contains information related to a transaction. This artifact identifies the destination bank as **First Bank of Nigeria LTD** through the SWIFT/BIC code `FBNINGLA`. Other artifacts in the message include the employee's name and account number.

## Attack Timeline

The email timestamps, authentication events, and mailbox rule creation events allow us to reconstruct the attack on Wednesday, July 2, 2025, with a high level of confidence.
- **15:40:37**: Becky receives the phishing email appearing to come from Sabastian (`sabastian@flanaganspensions[.]co[.]uk`)
- **Between 15:40:37 and 15:41:57**: The evidence suggests that Becky entered her credentials into the fake `copilotweb[.]co` login portal
- **15:41:57, 15:42:07, 15:45:05, 15:49:39**: The attacker authenticates to Becky's account using `159.203.17[.]81` and `95.181.232[.]30`
- **15:48:39**: The attacker creates the first rule targeting **Withdrawal**
- **15:57:23**: Fraudulent financial email `20250702-Withdrawal-Bernard`
- **15:58:42**: The attacker creates the second rule, moving messages sent to Sabastian into the **History** folder

## Technical Analysis

Correlation of the available artifacts reveals a coherent sequence between the initial phishing email, the compromise of Becky's account, and the concealment actions performed in her Microsoft 365 mailbox.

The phishing email was received at **15:40:37** and contained a link to the fake Microsoft portal hosted on `copilotweb[.]co`. The first suspicious authentication to Becky's account occurred only **1 minute and 20 seconds later**, at **15:41:57**, from `159.203.17[.]81`. A second IP address, `95.181.232[.]30`, was then observed from **15:45:05** onward.

This close temporal relationship provides strong supporting evidence that the account compromise followed the phishing event, although the available logs do not directly prove that Becky entered her credentials into the fake portal.

At **15:48:39**, a `New-InboxRule` was created from a session associated with `95.181.232[.]30`. The rule targeted messages from Sabastian containing the term **Withdrawal** in their subject or body and deleted them. This action appears intended to prevent Becky from seeing replies or confirmations from Sabastian regarding financial withdrawals.

At **15:57:23**, Becky's compromised account was used to **send a fraudulent withdrawal request to Sabastian**. The message contained banking details identifying **First Bank of Nigeria LTD** as the destination bank.

Finally, at **15:58:42**, a second rule was created to move messages matching the attacker's criteria into the **History** folder. This further supports the hypothesis that the attacker intended to control which communications remained visible to Becky and conceal the fraudulent activity.

The observed sequence can be summarized as follows:
- 15:40:37 — Phishing email received
- 15:41:57 — First suspicious authentication
- 15:45:05 — Second IP address observed
- 15:48:39 — **Withdrawal** deletion rule created
- 15:57:23 — Fraudulent withdrawal request sent
- 15:58:42 — Rule created to move messages to **History**

The correlation between emails, authentication events, and mailbox modifications establishes with a high level of confidence that Becky's account was used by a third party to carry out and conceal financial fraud.

## Indicators of Compromise

| **Type** | **Defanged value** | **Context** |
|---|---|---|
| Sender address | `sabastian@flanaganspensions[.]co[.]uk` | Sender shown in the initial phishing email |
| URL | `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu` | Phishing link |
| Domain | `copilotweb[.]co` | Domain hosting the fake portal |
| IP address | `159.203.17[.]81` | Infrastructure used during the compromise |
| IP address | `95.181.232[.]30` (Morocco) | Infrastructure used during the compromise |
| Rule keyword | `Withdrawal` | Trigger used by the first malicious rule |
| Mailbox folder | `History` | Folder used to conceal messages |

### Behavioral Indicators

- CFO authentication from a new IP address;
- authentication from multiple countries within a short period;
- sudden creation of inbox rules;
- mailbox rule using financial terminology;
- automatic deletion of messages;
- movement of messages into an unusual folder;
- unusual access to mailbox content;
- payment requests sent from an executive account;
- modification of banking information;
- transfer to a new beneficiary;
- use of a cloud account from hosting, VPN, or proxy infrastructure.

## MITRE ATT&CK Mapping

| **Tactic** | **Technique** | **ID** | **Application to the Incident** |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | The initial email contained a link to a fake Microsoft portal |
| Credential Access | Input Capture: Web Portal Capture | T1056.003 | The fake portal appears to have been used to collect the victim's credentials |
| Initial Access / Persistence / Defense Evasion | Valid Accounts: Cloud Accounts | T1078.004 | The CFO's Microsoft 365 credentials were used to access the tenant |
| Collection | Email Collection: Remote Email Collection | T1114.002 | The actor accessed an Exchange Online mailbox using the compromised account |
| Defense Evasion | Indicator Removal: Clear Mailbox Data | T1070.008 | A rule was created to delete emails matching the term **Withdrawal** |
| Impact | Financial Theft | T1657 | The ultimate objective was to divert funds to external accounts |

## Severity Assessment

Severity: **Critical**

Justification: compromise of a CFO account, creation of concealment rules, and confirmed financial fraud.

## Recommended Response Actions

To remove unauthorized access obtained through this attack, we recommend:
- reset the compromised account password;
- revoke active sessions;
- verify MFA methods;
- remove malicious inbox rules;
- review forwarding rules and mailbox delegations;
- search for the same IOCs across the tenant;
- identify any additional affected accounts;
- block or monitor the malicious domain and IP addresses where appropriate;
- create or propose detections for `New-InboxRule`, unusual authentication activity, and `MailItemsAccessed`.

### Detection Scenarios

| **Alert Type** | **Logic / Conditions** |
|---|---|
| Message deletion | `New-InboxRule AND DeleteMessage = True` |
| Concealment through folder movement | `New-InboxRule AND MoveToFolder != empty AND User in (Finance, Executive)` |
| Financial keywords | `New-InboxRule AND SubjectOrBodyContainsWords (financial vocabulary)` |
| Immediate post-compromise activity | `UserLoggedIn (new country) FOLLOWED BY New-InboxRule (60 min)` |
| Suspicious BEC activity | `UserLoggedIn (new IP) FOLLOWED BY MailItemsAccessed FOLLOWED BY Send` |
| Brute-force attempt | `Multiple failed logins FOLLOWED BY successful login (same IP)` |

## Conclusion

The BEC-KY investigation highlights a **Business Email Compromise** targeting an account with significant financial privileges.

The threat actor used a phishing email and a fake Microsoft portal to gain access to the CFO's account. The actor then authenticated from two distinct IP addresses, accessed the mailbox, and created rules to delete or move messages related to financial withdrawals.

The mailbox compromise enabled the attacker to conceal fraudulent activity involving several transfers, including one confirmed transaction to **First Bank of Nigeria**.

Beyond the technical indicators, this incident demonstrates that BEC detection requires correlation across multiple data sources:
- Emails
- Authentication events
- Sessions
- Mailbox rules
- Mail access events
- Financial context

The main methodological lesson from this lab is that an IP address alone is not enough to classify activity as malicious.

The investigation followed a chain of evidence:

**abnormal or malicious action → authentication → IP address**
