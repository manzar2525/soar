# Detailed IOC-Based Threat Hunting Playbook - Granular Steps

## 1. IOC Collection and Processing

### Initial IOC Receipt
1. Document source of IOCs
2. Record date/time received
3. Assign case/hunt ID
4. Document context/intelligence report details
5. Record priority level
6. Document associated threat actors
7. Record related campaigns/malware

### IOC Validation and Organization
1. Categorize IOCs by type (hash, domain, IP, etc.)
2. Validate format of each IOC
3. Remove duplicates
4. Normalize formats (lowercase, standardize)
5. Check for obvious false positives
6. Organize IOCs in structured format
7. Prepare IOCs for hunting tools

### IOC Enrichment
1. Check file hashes against VirusTotal
2. Perform WHOIS lookups on domains
3. Check IP reputation
4. Gather ASN information
5. Check passive DNS data
6. Research certificate information
7. Add contextual data to each IOC
8. Research known TTPs associated with IOCs

### IOC Prioritization
1. Score IOCs by reliability of source
2. Rank by recency/age of indicator
3. Prioritize based on potential impact
4. Consider prevalence (rare vs. common)
5. Evaluate contextual risk factors
6. Assess organizational relevance
7. Create tiered hunting approach based on priority

## 2. Search Strategy Development

### Query Development for Endpoint Tools
1. Develop EDR search queries
2. Create host-based IOC search patterns
3. Format queries for specific endpoint platforms
4. Develop file hash search mechanisms
5. Create filename/path search queries
6. Develop registry search parameters
7. Create process command line search queries
8. Test query performance and accuracy

### Network Search Strategy
1. Develop network sensor queries
2. Create firewall log search parameters
3. Develop IDS/IPS alert search queries
4. Create proxy log search patterns
5. Develop DNS query search parameters
6. Format queries for network traffic analysis
7. Create NetFlow/packet capture search strategies
8. Test network query effectiveness

### SIEM Query Development
1. Develop SIEM search syntax
2. Create correlation rules
3. Define time windows for searches
4. Develop aggregation queries
5. Create visualization queries
6. Test query performance
7. Optimize query efficiency
8. Document all SIEM queries

### Log Analysis Strategy
1. Identify relevant log sources
2. Create authentication log search patterns
3. Develop application log search queries
4. Create email security log queries
5. Develop cloud service log search patterns
6. Format searches for specific log formats
7. Test log search effectiveness
8. Document log analysis approach

## 3. Historical Data Hunting

### Endpoint Historical Search
1. Execute file hash searches across enterprise
2. Search for suspicious file paths
3. Query for known malicious process names
4. Search command line parameters
5. Look for suspicious registry modifications
6. Query for known persistence mechanisms
7. Search for unusual file creation timestamps
8. Document all endpoint findings

### Network Historical Search
1. Search for connections to suspicious IPs
2. Query DNS logs for malicious domains
3. Search proxy logs for suspicious URLs
4. Analyze NetFlow data for unusual patterns
5. Search for data exfiltration indicators
6. Analyze encrypted traffic patterns
7. Look for unusual protocol behavior
8. Document all network findings

### SIEM Historical Analysis
1. Run correlation searches across events
2. Look for event sequences matching attack patterns
3. Search for anomalies during relevant timeframes
4. Analyze user behavior around IOC timeframes
5. Correlate alerts across different systems
6. Search for related events across data sources
7. Look for evidence of defense evasion
8. Document all SIEM findings

### Authentication and Access Analysis
1. Search for suspicious login activities
2. Analyze authentication failures
3. Look for unusual access patterns
4. Search for privilege escalation indicators
5. Analyze user account modifications
6. Check for unusual account creation
7. Look for after-hours authentication
8. Document all authentication findings

## 4. Real-time Monitoring Configuration

### EDR Alert Configuration
1. Deploy IOC watchlists to EDR
2. Configure real-time file hash monitoring
3. Set up process monitoring rules
4. Deploy registry change monitoring
5. Configure file creation alerts
6. Set up command line monitoring
7. Configure network connection monitoring
8. Test and validate EDR alert configuration

### Network Monitoring Setup
1. Configure IDS/IPS with IOC rules
2. Set up firewall alerts for suspicious connections
3. Deploy DNS monitoring for malicious domains
4. Configure proxy alerts for suspicious URLs
5. Set up NetFlow anomaly detection
6. Configure DLP alerts for data exfiltration
7. Deploy packet inspection rules
8. Test and validate network monitoring

### SIEM Alert Configuration
1. Create real-time correlation rules
2. Configure IOC matching alerts
3. Set up behavioral anomaly alerts
4. Deploy user activity monitoring
5. Configure asset interaction monitoring
6. Set up multi-stage attack detection
7. Create alert prioritization rules
8. Test and validate SIEM alerting

### Honeypot/Deception Configuration
1. Deploy decoy files matching IOC patterns
2. Set up credential honeypots
3. Configure network honeypots
4. Deploy service honeypots
5. Set up deception breadcrumbs
6. Configure high-interaction honeypots
7. Deploy canary tokens
8. Test and validate deception environment

## 5. Finding Analysis and Validation

### Initial Finding Triage
1. Collect all positive matches
2. Group findings by host/system
3. Organize findings chronologically
4. Correlate across data sources
5. Prioritize findings by confidence
6. Evaluate context of each finding
7. Document initial assessment
8. Assign validation priority

### False Positive Analysis
1. Check against known good activity
2. Validate pattern match accuracy
3. Analyze surrounding context
4. Check for benign software matches
5. Evaluate baseline normal behavior
6. Test alternative explanations
7. Document false positive findings
8. Update detection rules

### True Positive Validation
1. Gather additional context for each match
2. Collect supporting evidence
3. Verify IOC presence directly when possible
4. Perform deeper analysis of affected systems
5. Correlate with other suspicious activities
6. Check for associated TTPs
7. Document validated findings
8. Prepare for escalation if confirmed

### Timeline Development
1. Create chronological event timeline
2. Identify initial access timestamp
3. Document persistence establishment
4. Map lateral movement activities
5. Record data collection/exfiltration times
6. Document defense evasion activities
7. Create visual timeline representation
8. Identify key attack progression points

## 6. Scope and Impact Analysis

### Affected Asset Identification
1. Inventory all compromised systems
2. Identify affected user accounts
3. Document impacted applications
4. Map affected network segments
5. Identify compromised data
6. Document impacted services
7. Assess business function impact
8. Create comprehensive asset inventory

### Lateral Movement Analysis
1. Map connections between compromised systems
2. Analyze authentication logs between systems
3. Check for credential dumping evidence
4. Look for administrative tool usage
5. Analyze remote access patterns
6. Check for unusual remote service creation
7. Document movement timeline
8. Create lateral movement graph

### Data Impact Assessment
1. Identify accessed sensitive data
2. Determine potential data exfiltration
3. Quantify data exposure
4. Assess regulatory impact
5. Determine intellectual property exposure
6. Document customer data impact
7. Assess business impact of data compromise
8. Prepare preliminary impact report

### Attack Vector Analysis
1. Identify initial entry point
2. Determine exploitation methods
3. Document phishing/social engineering evidence
4. Analyze vulnerability exploitation
5. Check for supply chain compromise
6. Document credential compromise methods
7. Identify zero-day exploitation if present
8. Create attack vector assessment

## 7. Expanded Hunting

### TTP-based Expansion
1. Identify associated techniques from confirmed findings
2. Develop searches based on MITRE ATT&CK techniques
3. Hunt for additional instances of identified TTPs
4. Search for related persistence mechanisms
5. Hunt for similar defense evasion techniques
6. Look for alternate C2 channels
7. Search for additional exfiltration methods
8. Document all TTP-based findings

### Lateral Hunting Expansion
1. Identify systems with similar functions
2. Hunt across systems with network connections
3. Expand search to related user accounts
4. Check systems with shared credentials
5. Search similar application stacks
6. Hunt across common administrative boundaries
7. Expand to cloud environments if relevant
8. Document expanded lateral findings

### Temporal Expansion
1. Expand timeframe of investigation
2. Look for precursor activities
3. Hunt for earlier reconnaissance
4. Search for staging activities
5. Look for previous compromise attempts
6. Check for dormant persistence
7. Search for historical variants of techniques
8. Document timeline expansion findings

### New IOC Development and Hunting
1. Extract new IOCs from confirmed findings
2. Develop YARA rules from malware samples
3. Create new behavioral indicators
4. Identify unique attacker patterns
5. Develop new detection rules
6. Hunt using newly generated IOCs
7. Search for variations of identified patterns
8. Document new IOC hunting results

## 8. Reporting and Intelligence

### Technical Finding Documentation
1. Document all confirmed findings
2. Record hunting methodology
3. Detail true positive validations
4. Document false positives and reasons
5. Record timeline of events
6. Document affected systems and accounts
7. Record all observed TTPs
8. Create technical evidence inventory

### IOC Refinement
1. Document all validated IOCs
2. Record IOC detection effectiveness
3. Note IOC false positive rates
4. Create confidence ratings for IOCs
5. Document IOC lifespan observations
6. Identify most valuable IOC types
7. Create refined IOC set
8. Prepare IOCs for sharing

### Detection Improvement
1. Create new detection rules
2. Update existing SIEM rules
3. Develop new YARA signatures
4. Create updated Snort/Suricata rules
5. Develop EDR detection improvements
6. Create behavioral detection rules
7. Test and validate new detection methods
8. Document detection enhancement recommendations

### Intelligence Sharing
1. Prepare sanitized findings
2. Create shareable IOC packages
3. Develop intelligence reports
4. Share with trusted communities
5. Update internal threat database
6. Contribute to information sharing platforms
7. Notify relevant stakeholders
8. Document intelligence sharing activities

## 9. Response Integration

### Incident Response Handoff
1. Brief incident response team
2. Transfer all evidence and findings
3. Conduct technical walkthrough
4. Provide hunting methodology details
5. Transfer timeline documentation
6. Brief on impact assessment
7. Provide remediation recommendations
8. Document handoff completion

### Containment Recommendation
1. Identify critical containment actions
2. Develop system isolation plan
3. Create account lockdown recommendations
4. Develop network containment strategy
5. Identify lateral movement blockers
6. Create data protection recommendations
7. Develop communications plan
8. Document containment strategy

### Remediation Planning Support
1. Identify required remediation actions
2. Develop eradication recommendations
3. Create recovery prioritization
4. Identify verification methods
5. Develop post-remediation testing
6. Create re-hunting strategy post-remediation
7. Support tactical remediation planning
8. Document remediation support activities

## 10. Hunt Process Improvement

### Hunt Effectiveness Review
1. Analyze IOC detection effectiveness
2. Review query performance metrics
3. Evaluate false positive rates
4. Assess time to detection
5. Review resource utilization
6. Calculate coverage metrics
7. Identify detection gaps
8. Document effectiveness metrics

### Playbook Enhancement
1. Update hunting playbook based on findings
2. Improve IOC processing methods
3. Enhance query development techniques
4. Update validation procedures
5. Improve scope analysis methods
6. Enhance reporting templates
7. Update integration procedures
8. Document playbook improvements

### Capability Improvement
1. Identify tooling gaps
2. Recommend data source improvements
3. Suggest retention period adjustments
4. Identify automation opportunities
5. Recommend new hunting technologies
6. Develop training requirements
7. Suggest process improvements
8. Document capability enhancement plan