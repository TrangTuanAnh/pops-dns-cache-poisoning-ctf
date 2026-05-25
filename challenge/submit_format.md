# Submit Format

Submit a single JSON object to the checker.

Required fields:

```json
{
  "victim_domain": "domain that received the poisoned delegation",
  "malicious_ns": "nameserver injected by the malicious response",
  "malicious_ns_ip": "A record/glue address for that nameserver",
  "trigger_qname": "query name that caused the resolver to ask attacker-controlled auth",
  "poison_packet_number": 0,
  "poison_dns_txid": "0x0000",
  "first_cache_seen": "YYYY-MM-DDTHH:MM:SSZ",
  "first_victim_query": "YYYY-MM-DDTHH:MM:SSZ"
}
```

Notes:

- `poison_packet_number` is the Wireshark/tshark frame number in the full
  capture, starting at 1, without a display filter.
- `poison_dns_txid` is accepted as a cross-check and should come from the same
  DNS response.
- Normalize domain names to lowercase and omit the trailing dot.
- TXT records containing `CTF{...}` are canaries, not the final answer.
