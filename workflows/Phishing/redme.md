# Detailed Phishing Analysis Playbook - Granular Steps

## 1. Initial Receipt and Automated Triage

### Email Metadata Extraction
1. Capture email source IP address
2. Extract sender email address and display name
3. Extract sender domain
4. Extract recipient(s) email addresses
5. Capture date/time received
6. Extract email subject
7. Calculate email size
8. Identify email client/user agent

### Email Header Analysis
1. Parse all header fields
2. Check Received-From chain for anomalies
3. Validate X-Originating-IP against known ranges
4. Verify Return-Path matches sender
5. Check for header inconsistencies
6. Extract Message-ID for correlation
7. Calculate header entropy score

### Authentication Verification
1. Check SPF record alignment
2. Verify DKIM signature validity
3. Check DMARC policy and alignment
4. Verify BIMI record if present
5. Check for ARC validation if forwarded
6. Calculate authentication pass/fail score

### Sender Reputation Analysis
1. Check sender against known phishing actors
2. Verify sender domain age
3. Check domain registration details against WHOIS
4. Compare sender to internal trusted senders list
5. Check sender IP against IP reputation services
6. Check for recent similar sender patterns
7. Calculate sender reputation score

## 2. Email Content Analysis

### Body Extraction and Preparation
1. Extract plain text version
2. Extract HTML version
3. Convert HTML to DOM structure
4. Identify character encoding
5. Detect language
6. Calculate text-to-HTML ratio
7. Measure content entropy

### Linguistic Analysis
1. Check for urgent language patterns
2. Detect threatening content
3. Identify financial/payment requests
4. Check for credential request indicators
5. Detect brand-specific terminology
6. Analyze grammar and spelling quality
7. Check for personalization attempts
8. Measure overall linguistic risk score

### Template Matching
1. Compare against known phishing templates
2. Check for brand logo usage
3. Identify form fields in content
4. Compare layout to legitimate communications
5. Check email signature against known formats
6. Calculate template similarity score

### Brand Impersonation Detection
1. Check for brand names in content
2. Identify brand logos in images
3. Compare to legitimate brand email templates
4. Check for brand color schemes
5. Detect brand-specific formatting
6. Calculate brand impersonation score

## 3. URL Analysis

### URL Extraction
1. Extract all URLs from plain text
2. Extract all URLs from HTML href attributes
3. Extract all URLs from HTML src attributes
4. Extract URLs from encoded content
5. Extract redirected URLs
6. Identify URL shortener services
7. Count total URLs present

### URL Deobfuscation
1. Decode URL-encoded characters
2. Resolve shortened URLs
3. Decode base64-encoded URLs
4. Convert hex-encoded characters
5. Extract domains from obfuscated URLs
6. Identify evasion techniques used
7. Record all redirects in chain

### Domain Analysis
1. Verify domain age
2. Check domain registration details
3. Verify SSL certificate details
4. Check domain against phishing feeds
5. Analyze domain similarity to legitimate domains
6. Check for typosquatting patterns
7. Calculate domain risk score

### Landing Page Analysis
1. Capture full page screenshot in sandbox
2. Check for login forms
3. Detect brand impersonation elements
4. Check for credential harvesting indicators
5. Analyze page content for phishing language
6. Check for malicious scripts
7. Calculate landing page risk score

## 4. Attachment Analysis

### Attachment Extraction
1. Extract all attachments
2. Identify file types
3. Verify file extensions match content
4. Check for double extensions
5. Identify embedded objects
6. Extract OLE objects from Office documents
7. Record file metadata

### Static Analysis
1. Calculate file hashes (MD5, SHA1, SHA256)
2. Check hashes against threat intelligence
3. Check for known malicious signatures
4. Analyze file structure
5. Check for obfuscation techniques
6. Scan for known exploit indicators
7. Extract embedded URLs and IP addresses

### Dynamic Analysis
1. Execute file in sandbox environment
2. Monitor for suspicious API calls
3. Track file system modifications
4. Monitor registry changes
5. Record network connections
6. Capture screenshots during execution
7. Identify persistence mechanisms
8. Calculate overall malicious behavior score

## 5. Risk Scoring and Prioritization

### Composite Scoring
1. Calculate header-based risk score (0-100)
2. Calculate content-based risk score (0-100)
3. Calculate URL-based risk score (0-100)
4. Calculate attachment-based risk score (0-100)
5. Apply organization-specific weighting factors
6. Calculate final composite score
7. Assign risk level (Low, Medium, High, Critical)

### Contextual Enrichment
1. Check recipient's department/role
2. Identify if target is high-value/executive
3. Check for timing correlation with events
4. Identify if sender has previously communicated with recipient
5. Determine if email type is expected for recipient
6. Check for similar recent phishing attempts
7. Apply contextual risk modifiers

## 6. Analyst Investigation

### Manual Review
1. Examine full email content and structure
2. Verify automated analysis results
3. Check for false positive indicators
4. Identify evasion techniques missed by automation
5. Correlate with recent threat intelligence
6. Determine attack objective
7. Update classification

### Advanced Analysis
1. Perform manual URL investigation
2. Conduct deeper analysis of suspicious attachments
3. Research campaign attribution indicators
4. Check for indicators of targeted attack
5. Analyze timing and targeting patterns
6. Correlate with external threat intelligence
7. Document novel techniques identified

## 7. Containment and Response

### Email Containment
1. Identify all instances of email across organization
2. Apply quarantine actions to all copies
3. Remove email from user inboxes
4. Block sender at email gateway
5. Create email gateway rule for similar emails
6. Document containment actions
7. Verify containment effectiveness

### URL/Domain Blocking
1. Add malicious URLs to web proxy block list
2. Add domains to DNS sinkhole
3. Update firewall rules for C2 domains
4. Add domains to CASB blocklist
5. Update email security URL filters
6. Document all blocking actions
7. Verify blocking effectiveness

### Exposure Analysis
1. Query email logs for all recipients
2. Check mail server logs for interactions
3. Query web proxy logs for URL access
4. Check endpoint logs for attachment execution
5. Analyze VPN/remote access logs
6. Correlate with authentication logs
7. Document all exposure findings

## 8. Incident Handling (If Compromise Confirmed)

### Compromise Assessment
1. Identify affected users and systems
2. Determine compromise timeline
3. Collect affected system logs
4. Identify stolen credentials
5. Determine data exposure scope
6. Check for persistence mechanisms
7. Document full compromise assessment

### Remediation
1. Reset compromised credentials
2. Force multi-factor authentication
3. Isolate affected endpoints
4. Remove malware and persistence mechanisms
5. Block all associated C2 infrastructure
6. Restore from clean backups if needed
7. Monitor for reinfection attempts
8. Document all remediation actions

## 9. Notification and Communication

### User Notification
1. Create specific notification template
2. Include incident details and IOCs
3. Provide clear user action items
4. Include prevention guidance
5. Set up acknowledgment tracking
6. Distribute to affected users
7. Track notification effectiveness

### Organization Communication
1. Determine need for broader communication
2. Create organization-wide alert if needed
3. Develop executive briefing
4. Coordinate with corporate communications
5. Provide awareness materials
6. Schedule follow-up communications
7. Document all communications

## 10. Documentation and Reporting

### Incident Documentation
1. Record full email analysis details
2. Document all IOCs discovered
3. Record timeline of detection and response
4. Document all actions taken
5. Record affected users and systems
6. Document remediation actions
7. Calculate incident metrics

### Intelligence Updates
1. Update internal IOC database
2. Share intelligence with trusted partners
3. Submit samples to analysis platforms
4. Update detection rules
5. Create YARA/Sigma rules based on findings
6. Document lessons learned
7. Update phishing playbooks

## 11. Post-Incident Activities

### Security Improvement
1. Update email security rules
2. Enhance web filtering controls
3. Improve endpoint detection capabilities
4. Update security awareness content
5. Review and update response procedures
6. Implement additional preventive controls
7. Document all security improvements

### Metrics and Reporting
1. Calculate time to detection
2. Measure time to containment
3. Calculate time to remediation
4. Measure user reporting effectiveness
5. Track false positive/negative rates
6. Analyze overall incident impact
7. Generate executive summary report