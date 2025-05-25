# Domain Extractor

A powerful and lightweight Python tool that extracts, validates, and resolves domain names from text files.

![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)

## 📋 Overview

Domain Extractor is a command-line and GUI utility that scans text files for domain names, validates their format according to DNS standards, and checks if they resolve to IP addresses. It provides a comprehensive solution for identifying and verifying domains in any text content.

## ✨ Features

- 🔍 **Robust Domain Detection**: Finds domains embedded in text, URLs, HTML, code, and more
- ✅ **DNS Format Validation**: Validates domains according to official DNS naming standards
- 🌐 **IP Resolution**: Checks if domains resolve to IP addresses

- 🔄 **Format Normalization**: Handles mixed case, surrounding punctuation, and more
- 🧪 **Edge Case Support**: Handles subdomains, IDNs, new TLDs, and challenging formats
- 📊 **Detailed Results**: Provides comprehensive output with IP addresses when available

## 🚀 Installation

### Prerequisites

- Python 3.6 or higher

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/AmitBerger/domain_extractor.git
   cd domain-extractor
   ```

2. Install requirements:
```bash
$ pip install -r requirements.txt
```

## 🖥️ Usage

### Basic Usage

```bash
python domain_extractor.py input.txt output.txt
```

### Example

```bash
$ python domain_extractor.py webpages.txt domains.txt
Found 115 potential domains. Checking...
Checking google.com... RESOLVES TO 142.250.72.142
Checking example.org... VALID FORMAT (NO IP)
...
Complete! Found 115 valid domains.
- 75 domains resolve to an IP address
- 40 domains have valid format but no IP
```

### Output Format

The output file contains one domain per line:
- Domains that resolve to an IP address include the IP: `google.com 142.250.72.142`
- Domains with valid format but no IP resolution: `example.org`

### Desktop GUI <a id="desktop-gui"></a>
```bash
$ python GUI.py            # launches a themable drag‑and‑drop window
```

1. Click **Select Text Files** or paste a URL.  
2. Press **Extract** and watch the progress bar.  
3. Copy or save results from the output pane.

![GUI](https://github.com/user-attachments/assets/b4b0f906-b0f0-4c3c-a06d-24ee16189a0d)

### Web interface <a id="web-interface"></a>
```bash
# Start the Flask back‑end (serves index.html on http://127.0.0.1:5000)
$ python domain_extractor_server.py
```
Then open your browser ➜ **http://127.0.0.1:5000**.

![web](https://github.com/user-attachments/assets/a2a536e3-038e-4b22-8c49-1c1a6d75efe0)


## 🔧 How It Works

The Domain Extractor follows a three-step process:

1. **Extraction**: Uses regex pattern matching to find potential domains in text
2. **Validation**: Applies DNS naming rules to validate domain format:
   - Checks label length (max 63 chars)
   - Verifies character set (letters, numbers, hyphens)
   - Validates label start/end characters
   - Ensures proper TLD format
   - Confirms overall domain length (max 253 chars)
3. **Resolution**: Attempts to resolve domains to IP addresses

## 🌟 Examples

### Example 1: Extract domains from a web page

```bash
$ python domain_extractor.py webpage.html domains.txt
```

### Example 2: Process log files

```bash
$ python domain_extractor.py server_logs.txt domains.txt
```


## ⚠️ Limitations

- The tool does not validate the existence of domains beyond DNS resolution
- Some valid domains may not resolve to IP addresses (e.g., newly registered domains)
- DNS resolution may be affected by network conditions and DNS server configuration
- Very large files may require significant processing time

## 📊 Performance

- Processes approximately 1000 domains per minute on average hardware
- Memory usage scales linearly with input file size
- DNS resolution is the primary performance bottleneck

## 🔍 Edge Cases Handled

- Domains with multiple subdomains
- Internationalized Domain Names (IDNs)
- Domains with unusual TLDs (.travel, .museum, etc.)
- Domains embedded in complex contexts (HTML, code, etc.)
- Domains with maximum length labels
- Mixed case domains


## 📬 Contact

Project Link: [https://github.com/yourusername/domain-extractor](https://github.com/AmitBerger/domain_extractor)


---
