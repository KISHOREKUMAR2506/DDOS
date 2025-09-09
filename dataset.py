import pyshark
import pandas as pd

cap = pyshark.FileCapture('ipv6_traffic.pcap')
rows = []

for pkt in cap:
    if 'IPV6' in pkt:
        try:
            src = pkt.ipv6.src
            dst = pkt.ipv6.dst
            length = int(pkt.length)
            rows.append([src, dst, 1, length])
        except:
            continue

df = pd.DataFrame(rows, columns=['src','dst','packet_count','byte_count'])
df['label'] = df['src'].apply(lambda x: 1 if 'attacker' in x else 0)  # adjust labels
df.to_csv('ipv6_dataset.csv', index=False)
print("✅ Dataset created!")
