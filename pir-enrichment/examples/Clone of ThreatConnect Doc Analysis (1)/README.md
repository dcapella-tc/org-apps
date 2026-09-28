# ThreatConnect Doc Analysis

## Release Notes

### 1.0.6 (2026-01-29)

-   APP-5083 - Additional features null check

### 1.0.5 (2026-01-14)

-   APP-4847 - Zero-Day topic detector and summary

### 1.0.4 (2025-05-27)

-   APP-4842 - Add default values for Features

### 1.0.3 (2025-04-28)

-   APP-4767 - Text Summary and Industry Extractor features added.

### 1.0.2 (2024-11-01)

-   APP-4631 - File Array output by MD5, SHA1, SHA256

### 1.0.1 (2024-10-10)

-   APP-4630 - Update CAL dev URL to production URL

### 1.0.0 (2024-04-12)

-   Initial release with support for Analyze Document action.

# Category

-   Utility

# Description

Use the CAL Document Analysis API to identify and extract Indicators, MITRE ATT&CK patterns, Intrusion Sets, and Malware families that are potentially referenced within a document.<br /> This application specifically requires **TEXT** input for its analysis process.<br /><br /> Therefore, if you have binary files as input, such as PDFs, DOCX files, or other formats, you must first convert these files into plain text.<br /> To do this, use a separate text extraction application (such as a \"Content Parser\" Playbook App) to extract the readable text from the binary file, and only then can the document be analyzed using the CAL Document Analysis API.<br /><br /> Some Apps have binary outputs that contain text, this App will accept these binary inputs and process them.<br /><br />The ThreatConnect Doc Analysis App has an initial limit of 1000 API calls per day per instance. Please reach out to your Customer Success Manager if additional calls are needed. <br /><br />If a document is larger than 100 000 characters, the first 100 000 will be used. <br /><br />There are five features available for analysis:<br /><br />* **Alias Extraction**  - Extracts explicit <a href="https://attack.mitre.org/matrices/enterprise/" target="_blank">MITRE ATT&CK Enterprise techniques</a>, sub-techniques, tactics, malware, tools, intrusion sets, and courses of action, as well as CVEs, from the provided content.<br /> * **IOC Extraction** - Extracts explicit indicators within the content, including addresses, file hashes (MD5, SHA256, and SHA1), CIDRs, email addresses, ASNs, hosts, and URLs. To reduce noise, items from the CAL Safelist (that is, items marked with the <a href="https://knowledge.threatconnect.com/docs/cal-classifiers-glossary" target="_blank">Status.Safelist CAL classifier</a>) are excluded. Only hosts and email addresses with valid top-level domains (TLDs) from the Internet Assigned Numbers Authority (IANA) are included.<br /> * **AI MITRE ATT&CK Classification** - Labels report text identified as MITRE ATT&CK techniques and sub-techniques by <a href="https://knowledge.threatconnect.com/docs/mitre-attack-ai-classification-in-threatconnect" targe="_blank">ThreatConnect MITRE ATT&CK AI classification feature</a>.<br /> * **AI Summary Generation** - Uses an artificial intelligence (AI) large language model (LLM) to summarize reports into 200-word summaries and three to five bullet points.<br /> * **AI NAICS Industry Classification** - Uses <a href="https://knowledge.threatconnect.com/docs/cal-atl-industry-classification">ThreatConnect MITRE ATT&CK AI classification</a> feature to classify subsector-related industries and their related sectors based on document content.



The following actions are included:

-   **Analyze Document** - Use CAL Document Analysis API in order to identify Indicators, MITRE Attack Patterns, Intrusion Sets and Malware families that might be referenced within a document.

# Actions

---

## Analyze Document

Use CAL Document Analysis API in order to identify Indicators, MITRE Attack Patterns, Intrusion Sets and Malware families that might be referenced within a document.

### Inputs

### *Configure*

**Document** *(TypeEnum.String)*

The document to analyze in order to identify Indicators, MITRE Attack Patterns, Intrusion Sets, Malware families and Text Industries, as well as an A.I. summary

> **Allows:** Binary, String, TCEntity

**Features** *(MultiChoice, Default: Alias Extraction, IOC Extraction, AI Summary Generation)*

The features that will be used to analyze the document. At least one is required.

> **Allows:** StringArray

> **Valid Values:** Alias Extraction, IOC Extraction, AI MITRE ATT&CK Classification, AI NAICS Industry Classification, AI Summary Generation

_**Additional Features**_ *(Choice, Optional, Default: None)*

Additional features for Doc Analysis

> **Valid Values:** None, Zero Day (topic detector), Zero Day Summary (includes topic detector)

### *Advanced*

**Fail on error** *(Boolean, Default: Unselected)*

If not selected, the app will attempt to continue when an error is encountered.

### Outputs

-   tc.input_length *(String)*
-   tc.input_truncated *(String)*
-   tc.json.raw *(String)*
-   tc.naics.codes *(StringArray)*
-   tc.parsed.address_array *(StringArray)*
-   tc.parsed.address_array.count *(String)*
-   tc.parsed.asn_array *(StringArray)*
-   tc.parsed.asn_array.count *(String)*
-   tc.parsed.attack_pattern_descriptions *(StringArray)*
-   tc.parsed.attack_pattern_descriptions.aliasextractor *(StringArray)*
-   tc.parsed.attack_pattern_descriptions.aliasextractor.count *(String)*
-   tc.parsed.attack_pattern_descriptions.attackanalyzer *(StringArray)*
-   tc.parsed.attack_pattern_descriptions.attackanalyzer.count *(String)*
-   tc.parsed.attack_pattern_descriptions.count *(String)*
-   tc.parsed.attack_pattern_tags *(StringArray)*
-   tc.parsed.attack_pattern_tags.aliasextractor *(StringArray)*
-   tc.parsed.attack_pattern_tags.aliasextractor.count *(String)*
-   tc.parsed.attack_pattern_tags.attackanalyzer *(StringArray)*
-   tc.parsed.attack_pattern_tags.attackanalyzer.count *(String)*
-   tc.parsed.attack_pattern_tags.count *(String)*
-   tc.parsed.cidr_array *(StringArray)*
-   tc.parsed.cidr_array.count *(String)*
-   tc.parsed.course_of_action_descriptions *(StringArray)*
-   tc.parsed.course_of_action_descriptions.count *(String)*
-   tc.parsed.course_of_action_names *(StringArray)*
-   tc.parsed.course_of_action_names.count *(String)*
-   tc.parsed.cve_array *(StringArray)*
-   tc.parsed.cve_array.count *(String)*
-   tc.parsed.email_address_array *(StringArray)*
-   tc.parsed.email_address_array.count *(String)*
-   tc.parsed.email_subject_array *(StringArray)*
-   tc.parsed.email_subject_array.count *(String)*
-   tc.parsed.file_array *(StringArray)*
-   tc.parsed.file_array.count *(String)*
-   tc.parsed.hashtag_array *(StringArray)*
-   tc.parsed.hashtag_array.count *(String)*
-   tc.parsed.host_array *(StringArray)*
-   tc.parsed.host_array.count *(String)*
-   tc.parsed.intrusion_set_descriptions *(StringArray)*
-   tc.parsed.intrusion_set_descriptions.count *(String)*
-   tc.parsed.intrusion_set_names *(StringArray)*
-   tc.parsed.intrusion_set_names.count *(String)*
-   tc.parsed.malware_descriptions *(StringArray)*
-   tc.parsed.malware_descriptions.count *(String)*
-   tc.parsed.malware_names *(StringArray)*
-   tc.parsed.malware_names.count *(String)*
-   tc.parsed.md5_array *(StringArray)*
-   tc.parsed.md5_array.count *(String)*
-   tc.parsed.mutex_array *(StringArray)*
-   tc.parsed.mutex_array.count *(String)*
-   tc.parsed.registry_key_array *(StringArray)*
-   tc.parsed.registry_key_array.count *(String)*
-   tc.parsed.sha1_array *(StringArray)*
-   tc.parsed.sha1_array.count *(String)*
-   tc.parsed.sha256_array *(StringArray)*
-   tc.parsed.sha256_array.count *(String)*
-   tc.parsed.tactic_descriptions *(StringArray)*
-   tc.parsed.tactic_descriptions.count *(String)*
-   tc.parsed.tactic_names *(StringArray)*
-   tc.parsed.tactic_names.count *(String)*
-   tc.parsed.tools_descriptions *(StringArray)*
-   tc.parsed.tools_descriptions.count *(String)*
-   tc.parsed.tools_names *(StringArray)*
-   tc.parsed.tools_names.count *(String)*
-   tc.parsed.url_array *(StringArray)*
-   tc.parsed.url_array.count *(String)*
-   tc.parsed.user_agent_array *(StringArray)*
-   tc.parsed.user_agent_array.count *(String)*
-   tc.parsed.zeroday.summary *(String)*
-   tc.parsed.zeroday.topic *(String)*
-   tc.summary *(String)*
-   tc.summary.bullets *(StringArray)*
-   tc.tc_action *(String)*

---

# Labels

-   analysis
