# CyberShield Flow Diagrams

This file contains all flow diagrams extracted from the main documentation in a single place.

## 1. URL Phishing Detection Flow

### 1.1 Mermaid

```mermaid
flowchart TD
      U[User / Frontend] --> A[User enters URL]
      A --> B[System validates URL]
      B --> C[Check URL reputation via VirusTotal]
      B --> D[Optional URLhaus intelligence check]
      B --> E[Extract 12 URL risk indicators]
      E --> F[Compute custom phishing score]
      C --> G[Map external API score]
      F --> H[Fuse scores with 65/35 weighting]
    G --> H
      D --> I[Apply URLhaus escalation logic]
    H --> I
      I --> J[Enrich result with domain details]
      J --> K[Store summary in ScanResult]
      K --> L[Return result to user]
```

### 1.2 Boxed ASCII

```text
+-----------------------+
| User / Frontend       |
+-----------+-----------+
            |
            v
+-----------------------+
| User enters URL       |
+-----------+-----------+
            |
            v
+-----------------------+
| System validates URL  |
+-----+-----------+-----+
      |           |
      v           v
+-----------+   +-------------------+
| VirusTotal|   | URLhaus optional  |
| URL scan  |   | intelligence check|
+-----+-----+   +---------+---------+
      |                   |
      v                   v
+-----------------------+ +----------------------+
| ThreatIntelligence    | | URLhaus escalation   |
| Mapper api score      | | logic                |
+-----------+-----------+ +----------+-----------+
            ^                       ^
            |                       |
+-----------+-----------+           |
| URLFeatureExtractor   |           |
| 12 indicators         |           |
+-----------+-----------+           |
            |                       |
            v                       |
+-----------------------+           |
| PhishingScorer        |-----------+
| custom score          |
+-----------+-----------+
            |
            v
+-----------------------+
| HybridDecisionEngine  |
| final score 65/35     |
+-----------+-----------+
            |
            v
+-----------------------+
| Domain enrichment     |
+-----------+-----------+
            |
            v
+-----------------------+
| Persist ScanResult    |
+-----------+-----------+
            |
            v
+-----------------------+
| JSON response         |
+-----------------------+
```

## 2. IP Reputation Analysis Flow

### 2.1 Mermaid

```mermaid
flowchart TD
      U[User / Frontend] --> A[User enters IP address]
      A --> B[System validates public routable IP]
      B --> C[Check IP reputation via VirusTotal]
      B --> D[Lookup geolocation]
    D --> D1[WhoisXML API]
    D --> D2[ip-api fallback]
      D1 --> E[Compute custom risk score]
    D2 --> E
      C --> F[Map external API score]
      E --> G[Fuse scores with 40/60 weighting]
    F --> G
      G --> H[Generate recommendation]
      H --> I[Store summary in ScanResult]
      I --> J[Return result to user]
```

### 2.2 Boxed ASCII

```text
+-----------------------+
| User / Frontend       |
+-----------+-----------+
            |
            v
+-----------------------+
| User enters IP        |
+-----------+-----------+
            |
            v
+-----------------------+
| System validates      |
| public IP             |
+-----+-----------+-----+
      |           |
      v           v
+-----------+   +-----------------------+
| VirusTotal|   | Geolocation lookup    |
| IP scan   |   +-----------+-----------+
+-----+-----+               |
      |                     v
      |          +----------+-----------+
      |          | WhoisXML API         |
      |          +----------+-----------+
      |                     |
      |          +----------+-----------+
      |          | ip-api fallback      |
      |          +----------+-----------+
      |                     |
      |                     v
      |          +----------+-----------+
      |          | CustomRiskAnalyzer   |
      |          | custom score         |
      |          +----------+-----------+
      v                     |
+-----------------------+   |
| ThreatIntelligence    |   |
| Mapper api score      |   |
+-----------+-----------+   |
            |               |
            v               v
+-----------------------+---+--+
| HybridScoringEngine 40/60      |
| final score + severity         |
+-----------+--------------------+
            |
            v
+-----------------------+
| Recommendation        |
| generation            |
+-----------+-----------+
            |
            v
+-----------------------+
| Persist ScanResult    |
+-----------+-----------+
            |
            v
+-----------------------+
| JSON response         |
+-----------------------+
```

## 3. Unified Recon Async Lifecycle

### 3.1 Mermaid

```mermaid
flowchart TD
      U[User / Frontend] --> A[User starts unified recon scan]
    A --> B{Cache hit}
      B -->|Yes| C[Return completed result from cache]
      B -->|No| D[Create running job with pending modules]
    D --> E[Start background worker thread]
    E --> F[Run modules in parallel]
    F --> G[Update module states pending/running/ok/error]
    G --> H[Store final result and mark completed]
      U --> I[User checks scan status]
      I --> J[Return progress update]
      H --> K[Return full result when completed]
```

### 3.2 Boxed ASCII

```text
+-------------------------------+
| User / Frontend               |
+---------------+---------------+
                |
                v
+-------------------------------+
| User starts unified recon scan|
+---------------+---------------+
                |
                v
+-------------------------------+
| Cache hit?                    |
+----------+--------------------+
           |Yes                      No|
           v                           v
+---------------------------+   +------------------------------+
| Return completed job      |   | Create running job           |
| with cached result        |   | modules = pending            |
+---------------------------+   +---------------+--------------+
                                              |
                                              v
                                  +-----------+---------------+
                                  | Start background worker    |
                                  +-----------+---------------+
                                              |
                                              v
                                  +-----------+---------------+
                                  | Execute modules in parallel|
                                  +-----------+---------------+
                                              |
                                              v
                                  +-----------+---------------+
                                  | Update states              |
                                  | pending/running/ok/error   |
                                  +-----------+---------------+
                                              |
                                              v
                                  +-----------+---------------+
                                  | Mark completed + store     |
                                  | final result               |
                                  +-----------+---------------+
                                              |
                +-----------------------------+-----------------------------+
                |                                                           |
                v                                                           v
+-------------------------------+                          +-------------------------------+
| User checks scan status       |                          | Completed status includes      |
| and gets live progress        |                          | full result payload            |
+-------------------------------+                          +-------------------------------+
```
