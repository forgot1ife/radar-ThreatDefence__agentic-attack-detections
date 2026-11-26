# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Shell setup on the Kali host it drives | EDR on the Kali host | S | A, N | | | |
| `/etc/legal` created on a non-Ubuntu host | EDR, file audit | S | N | | | |
| VulnBot CLI on the controller | EDR | S | N | | | |
| Run log and config files | EDR, disk | | N | | | Y |
| Source tree on disk | Disk | | | | | Y |
| Prompts in model requests | AI gateway, TLS inspection, plain-HTTP model servers | | | N | | |
| Open knowledge base API (7861) and Streamlit page (8501) | Network, proxy, exposure searches | | N | N | | |
| Hugging Face model downloads for RAG | Proxy | | N | | | |
| Model traffic from the controller | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

S = Sigma rule, A = analytics rule, N = hunting query, Y = YARA rule.
