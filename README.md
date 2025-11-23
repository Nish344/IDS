# **DFA-Based Intrusion Detection System (IDS)**

*A Snort-style, real-time, automata-powered IDS with dashboard visualization*

---

## 🚀 **Overview**

This project implements a **Snort-like Intrusion Detection System (IDS)** built from scratch using:

* **Deterministic Finite Automata (DFA)** for fast multi-pattern matching
* **PCRE regex engine** for advanced signatures
* **TCP stream reassembly**
* **Normalization layer**
* **Rule parser & rule compiler**
* **Live packet capture using Scapy**
* **Real-time dashboard (Socket.IO + Flask)**
* **Unit-tested end-to-end pipeline**

The goal is to demonstrate **Theory of Computation (ToC)** concepts (DFA/NFA/RegEx) applied to **real intrusion detection**, similar to Snort/Suricata.

---

## 📁 **Project Structure**

```
src/ids/
    matcher/           # DFA engine, hybrid detector, regex PCRE engine
    rules/             # Snort-like rule parser + compiler
    reassembly/        # TCP stream reassembly
    pcap_reader.py     # Reads packets from PCAP
    live_capture.py    # Realtime IDS engine
    dashboard/         # HTML dashboard (Flask + Socket.IO)
    dashboard_runner.py
    normalizer.py
    utils.py
data/
    sample_rules.rules # Rule signatures
    sample_pcaps/      # Test PCAPs
tests/
    ...                # Full pytest suite
```

---

# 🛠️ **1. Installation**

### Clone your GitHub repo:

```bash
git clone https://github.com/Nish344/IDS.git
cd IDS/ids
```

---

### Create a virtual environment:

```bash
python3 -m venv penv
source penv/bin/activate
```

---

### Install dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

You should now have the `ids` package installed locally.

---

# 🧪 **2. Run All Tests (Optional)**

To ensure everything is working:

```bash
pytest -q
```

You should see:

```
11 passed in X.XXs
```

---

# 📡 **3. Live IDS Capture**

To start IDS and listen on **loopback (lo)**:

```bash
sudo PYTHONPATH=$(pwd)/src penv/bin/python3 -m ids.dashboard_runner --iface lo --rules data/sample_rules.rules
```

You will see:

```
[+] Listening on lo...
[+] Starting dashboard at http://127.0.0.1:5000
```

Now open your browser:

👉 **([http://127.0.0.1:5000](http://127.0.0.1:5000))**

This is the live dashboard UI.

---

# 🧨 **4. Sending Test Attacks (Scapy)**

Use Scapy to inject packets directly into loopback:

### Example: UNION SELECT SQLi

```bash
sudo penv/bin/python3 - << 'EOF'
from scapy.all import *
from scapy.layers.l2 import CookedLinux

pkt = CookedLinux()/IP(dst="127.0.0.1")/TCP(sport=5555,dport=80,flags="PA")/b"UNION SELECT DEMO"
sendp(pkt, iface="lo")
EOF
```

---

### Example: Multiple SQLi Variants

```bash
sudo penv/bin/python3 - << 'EOF'
from scapy.all import *
from scapy.layers.l2 import CookedLinux

seq = 1
payloads = [
    b"select * from users",
    b"; drop table accounts",
    b"' OR '1'='1",
    b"sqlmap", 
]

for p in payloads:
    pkt = CookedLinux()/IP(dst="127.0.0.1")/TCP(dport=80,sport=5555,flags="PA",seq=seq)/p
    sendp(pkt, iface="lo")
    seq += len(p)
EOF
```

---

### Example: XSS Attacks

```bash
sudo penv/bin/python3 - << 'EOF'
from scapy.all import *
from scapy.layers.l2 import CookedLinux

pkt = CookedLinux()/IP(dst="127.0.0.1")/TCP(sport=4444,dport=80,flags="PA")/b"<script>alert(1)</script>"
sendp(pkt, iface="lo")
EOF
```

---

### Example: Command Injection

```bash
sudo penv/bin/python3 - << 'EOF'
from scapy.all import *
from scapy.layers.l2 import CookedLinux

pkt = CookedLinux()/IP(dst="127.0.0.1")/TCP(dport=80,sport=5555,flags="PA")/b";cat /etc/passwd"
sendp(pkt, iface="lo")
EOF
```

---

# 📝 **5. Rules: Adding / Editing Signatures**

Rules are stored in:

```
data/sample_rules.rules
```

Format (Snort-like):

```
alert tcp any any <> any 80 (msg:"SQLi SELECT *"; content:"select * from"; nocase; sid:1006;)
```

Supports:

* `content:"..."`
* `nocase`
* `pcre:"/.../i"`
* any TCP direction using `<>`

### After editing rules:

**Just restart the IDS**, no compilation step required.

---

# 📊 **6. Dashboard Details**

Real-time alerts are pushed via Socket.IO:

Each alert includes:

```json
{
  "sid": 1001,
  "msg": "SQLi Test",
  "pattern": "union select",
  "src": "127.0.0.1:5555",
  "dst": "127.0.0.1:80",
  "direction": "b2a"
}
```

Dashboard shows:

* SID
* Alert name
* Pattern matched
* Source → Destination
* Timestamp

---

# 🧠 **7. How Detection Works (Technical)**

### 🔹 Aho-Corasick DFA

Used for ultra-fast detection of all `content` patterns simultaneously.

### 🔹 PCRE Engine

Handles complex signatures like:

```
pcre:"/(insert|update|delete)[[:space:]]+/i"
```

### 🔹 Stream Reassembly

TCP segments reassembled in correct order (`reassembly.py`).

### 🔹 Normalization Layer

Lowercases, strips control chars, handles encoding.

### 🔹 Hybrid Detector

Matches:

* DFA hits
* PCRE evaluation
* Direction constraints
* Port checks
* Flow metadata

---

# 🛠️ **8. Running With PCAP Files**

```bash
python3 -m ids.main --pcap data/sample_pcaps/http_get_small.pcap --rules data/sample_rules.rules
```

---

# 🤝 **Contributing**

Pull requests welcome!
Feel free to add new rule sets, datasets, dashboards, or optimization.

---

# 🏁 **Summary**

You now have:

* A **real** intrusion detection engine
* With **DFA/NFA/Regex automata components**
* Capable of **real-time detection on live traffic**
* With a visual **dashboard**
* And full **test suite**

This is a great ToC + Cybersecurity project.
