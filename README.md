# Domain Extractor

A powerful and lightweight Python tool that extracts, validates, and resolves domain names from text files, with advanced analysis and multiple interfaces.

![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)  ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Overview

Domain Extractor is a command-line, GUI, and web utility that scans text files for domain names, validates their format according to DNS standards, and checks if they resolve to IP addresses. It can optionally query the VirusTotal API to flag domains as malicious, suspicious, or clean. It also provides ASN (Autonomous System Number) and organization info for resolved IPs in the output file. It provides a comprehensive solution for identifying and verifying domains in any text content.

## ✨ Features

- 🔍 **Robust Domain Detection**: Finds domains embedded in text, URLs, HTML, code, and more
- ✅ **DNS Format Validation**: Validates domains according to official DNS naming standards
- 🌐 **IP Resolution**: Checks if domains resolve to IP addresses
- 🛡️ **VirusTotal Integration**: Optionally queries the VirusTotal API to mark domains as malicious, suspicious, or clean (API key required)
- 🛰️ **ASN Info in Output**: Adds ASN (Autonomous System Number) and organization info for resolved IPs (in output.txt and web export)
- 🔄 **Format Normalization**: Handles mixed case, surrounding punctuation, and more
- 🧪 **Edge Case Support**: Handles subdomains, IDNs, new TLDs, and challenging formats
- 📊 **Detailed Results**: Provides comprehensive output with IP addresses, VirusTotal status, and ASN info (in output.txt)
- 💾 **Download Full Results**: Download the full output.txt (with ASN info) from both the GUI and web interface
- 🖥️ **Multiple Interfaces**: Command-line, modern desktop GUI, and a rich web interface

## 🚀 Installation

### Prerequisites

- Python 3.6 or higher

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/AmitBerger/domain_extractor.git
   cd domain_extractor
   ```

2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## 🖥️ Usage

### Command-Line

```bash
python domain_extractor.py input.txt output.txt [virustotal_api_key]
# optional: include your VirusTotal API key to flag malicious domains
```

#### Example

```bash
$ python domain_extractor.py webpages.txt domains.txt YOUR_VT_API_KEY
Found 115 potential domains. Checking...
Checking google.com... RESOLVES TO 142.250.72.142
Checking example.org... VALID FORMAT (NO IP)
...
Complete! Found 115 valid domains.
- 75 domains resolve to an IP address
- 40 domains have valid format but no IP
```

#### Output Format

The output file contains one domain per line:
- Domains that resolve to an IP address include the IP, VirusTotal status, and **detailed ASN info**:  
  `google.com 142.250.72.142 VT:clean ASN:AS15169 | ASNName:Google LLC | ASNCountry:US | ...`
- Domains with valid format but no IP resolution:  
  `example.org VT:clean`
- **Note:** ASN info is only present in the downloaded output.txt file and in the web export, not in the GUI or web table display.

---

### Desktop GUI

- **VirusTotal API Key:** Enter your key in the GUI (top bar) or set the `VIRUSTOTAL_API_KEY` environment variable.
- **How to use:**
  1. Click **Select Text Files** or paste a URL.
  2. Press **Extract** and watch the progress bar.
  3. Copy or save results from the output pane (ASN info is hidden here).
  4. **Download the full output.txt** (with ASN info) using the "Download output.txt" button, enabled after extraction.

**Launch:**
- Linux/macOS:
  ```bash
  export VIRUSTOTAL_API_KEY="YOUR_API_KEY"  # optional
  python GUI.py
  ```
- Windows PowerShell:
  ```powershell
  $Env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"  # optional
  python GUI.py
  ```

![gi](https://github.com/user-attachments/assets/2f0c4a29-8d6a-49e7-a058-376508ada4cd)


---

### Web Interface

- **VirusTotal API Key:** Enter your key in the advanced settings panel or set the `VIRUSTOTAL_API_KEY` environment variable.
- **How to use:**
  1. Start the Flask backend:
     - Linux/macOS:
       ```bash
       export VIRUSTOTAL_API_KEY="YOUR_API_KEY"  # optional
       python domain_extractor_server.py
       ```
     - Windows PowerShell:
       ```powershell
       $Env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"  # optional
       python domain_extractor_server.py
       ```
  2. Open your browser ➜ **http://127.0.0.1:5000**
  3. Paste text or upload a file.
  4. Click **Extract & Analyze**.
  5. View results in the browser (ASN info is shown in a collapsible section for each domain).
  6. **Download the full output.txt** (with detailed ASN info) using the "Download Full Report" button, enabled after extraction.

![index](https://github.com/user-attachments/assets/be1dd5db-706f-46ec-94d9-8a07c9ec29ef)

  

#### **Web Dashboard Features**
- **Stats & Charts:** Visualize total, resolved, valid, and clean domains.
- **History:** See your last 10 extractions.
- **Bulk Actions:** Select, export, or delete multiple domains.
- **Advanced Settings:** Toggle DNS, VirusTotal.
- **Search & Filter:** Quickly find domains by status or text.
- **Export:** Download all or selected results as TXT (CSV/JSON planned).

---


## 🔧 How It Works

1. **Extraction:** Uses regex pattern matching to find potential domains in text.
2. **Validation:** Applies DNS naming rules to validate domain format:
   - Checks label length (max 63 chars)
   - Verifies character set (letters, numbers, hyphens)
   - Validates label start/end characters
   - Ensures proper TLD format
   - Confirms overall domain length (max 253 chars)
3. **Resolution:** Attempts to resolve domains to IP addresses and fetches **detailed ASN info** for resolved IPs (in output.txt and web export only).
4. **VirusTotal:** If enabled and API key is provided, checks each domain for malicious/suspicious/clean status.

---

## 🌟 Examples

### Extract domains from a web page

```bash
$ python domain_extractor.py webpage.html domains.txt
```

### Process log files

```bash
$ python domain_extractor.py server_logs.txt domains.txt
```

---

## ⚠️ Limitations

- The tool does not validate the existence of domains beyond DNS resolution.
- Some valid domains may not resolve to IP addresses (e.g., newly registered domains).
- DNS resolution may be affected by network conditions and DNS server configuration.
- Very large files may require significant processing time.
- **VirusTotal Integration:** Maliciousness checks require a valid API key; without it, domains are still extracted but not flagged.
- **Performance Impact:** Querying VirusTotal for each domain adds network latency and may slow down processing on large lists.
- **Daily 500 requests limitation** from VirusTotal API (for a free user).

---

## 📊 Performance

- Processes approximately 100 domains per minute on average hardware.
- Memory usage scales linearly with input file size.
- DNS resolution is the primary performance bottleneck.

---

## 🔍 Edge Cases Handled

- Domains with multiple subdomains
- Internationalized Domain Names (IDNs)
- Domains with unusual TLDs (.travel, .museum, etc.)
- Domains embedded in complex contexts (HTML, code, etc.)
- Domains with maximum length labels
- Mixed case domains

---

## 📬 Contact

Project Link: [https://github.com/AmitBerger/domain_extractor](https://github.com/AmitBerger/domain_extractor)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Notes:**  
- ASN info is only included in the downloaded output.txt file and web export, not in the GUI or web table display.
- The "Download output.txt" and "Download Full Report" buttons are enabled only after a successful extraction in both GUI and web interfaces.


