# Undead-Tunnel

A tunnel Idea for  lightless days, here is the road map


<img width="612" height="1280" alt="image" src="https://github.com/user-attachments/assets/2e6d69e4-dc71-47d3-90fe-8230d706a110" />









tunnel_core.py — symmetric encode/decode engine : 
                   encode_payload() and decode_labels() are now fully symmetric — both sides use the same _xor32() function with the same block_offset. ntp_encode_chunk() and ntp_decode_chunk() are identical under the hood because XOR is its own inverse. The block_offset parameter advances across bursts so the TX           key positions never overlap with RX key positions, preventing any XOR collision between a sent payload and its reply.



dns_tunnel_client.py :
   NS records now carry ~60% of the labels (the vital primary data). TXT/CNAME/MX/SRV share the remaining 40% as supporting shards. Every covert query name uses the format <b32data>-<sid8hex><seq3hex><total3hex>.<domain> — the first component looks like a real hostname label to any resolver. Decoy A/AAAA queries   (30% ratio) are interleaved with covert ones. The resolver pool is ResolverPool — weighted round-robin across up to 100 entries, with failure tracking that reduces a bad resolver's probability. Every send_query() call applies a 20–120 ms uniform random delay before the send, and automatically retries via TCP/53   if UDP times out or the response has TC=1 set.



dns_tunnel_server.py:

 Runs two listeners in parallel threads: run_udp_server() for UDP/53 and run_tcp_server() for TCP/53. The TCP handler implements the RFC 1035 §4.2.2 two-byte length-prefix framing. Reply chunks are returned as NS RDATA entries (<b32label>-<seq3hex><total3hex>.<domain>) — the same format the client parses in 
 receive_reply(). A background straggler_checker thread force-completes sessions that stopped receiving chunks after REASSEMBLE_WAIT_S seconds, handling packet loss gracefully. Per-response delays of 30–80 ms mimic real authoritative server latency.

 

ntp_tunnel_client.py: 

   send_payload() now returns (session, responses) — the list of server responses collected during the burst. decode_replies() is a proper receive-path function that extracts the server's covert reply from those responses (or polls with bare NTP packets for any that didn't arrive), calls ntp_decode_chunk() per      packet, unpacks the resulting plaintext blocks, and deframe()s the result. The NTP server pool mirrors the DNS resolver pool. UDP/123 is tried first; _send_tcp_ntp() provides TCP/123 fallback with 2-byte length framing. Per-packet send delay is 5–30 ms uniform random.


ntp_tunnel_server.py:

   CovertSession.decode_rx() implements the full 32-bit receive-path decode: for each collected 20-byte chunk it calls ntp_decode_chunk() at the correct block_offset, unpacks 5 × 4-byte plaintext blocks, reassembles, and deframe()s. CovertSession.encode_reply() implements the full 32-bit send-path encode: calls     encode_payload() at tx_block_off (which starts past all RX label positions), packs groups of 5 labels into 20-byte chunks, and calls ntp_encode_chunk() per packet. Both paths use tx_block_off and rx_block_off separately so the key stream is never reused between directions.
