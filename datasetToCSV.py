import os
import pandas as pd
from scapy.all import rdpcap, Dot11ProbeReq, Dot11Elt, Dot11EltVendorSpecific

def get_rates_str(info_bytes):
    rates = []
    for b in info_bytes:
        val = b & 0x7f
        rate = val * 0.5
        basic = '(B)' if b & 0x80 else ''
        rates.append(f"{rate:.1f}{basic}")
    return ','.join(rates)

data_dir = './Data'
output_csv = 'dataset_tabular.csv'

allowed_ids = [1, 3, 45, 50, 59, 70, 107, 127, 191, 221]

rows = []

pcap_files = [f for f in os.listdir(data_dir)]

for file in pcap_files:
    device_id = file[:-5]  # Remove '.pcap'
    full_path = os.path.join(data_dir, file)
    try:
        packets = rdpcap(full_path)
    except Exception as e:
        print(f"Error reading {file}: {e}")
        continue

    for pkt in packets:
        if pkt.haslayer(Dot11ProbeReq):
            row = {
                'Device_ID': device_id,
                'MAC': pkt.addr2,
                'Timestamp': pkt.time,
                'Sequence_Number': pkt.SC >> 4
            }

            vendor_infos = []
            elt = pkt[Dot11ProbeReq].payload
            while elt and isinstance(elt, Dot11Elt):
                if elt.ID in allowed_ids:
                    cls_name = elt.__class__.__name__.replace('Dot11Elt', '')
                    prefix = f'IE_{cls_name}_'

                    if elt.ID == 1:
                        row['IE_SupportedRates_rates'] = get_rates_str(elt.info)
                    elif elt.ID == 50:
                        row['IE_ExtendedSupportedRates_rates'] = get_rates_str(elt.info)
                    elif elt.ID == 221:  # Vendor Specific
                        oui_str = ':'.join(f'{b:02x}' for b in elt.oui.to_bytes(3, 'big'))
                        info_hex = elt.info.hex()
                        vendor_infos.append(f'{oui_str}:{info_hex}')
                    else:
                        for k, v in elt.fields.items():
                            if k in ['ID', 'len']:
                                continue
                            if k == 'info' and isinstance(v, bytes):
                                row[prefix + k] = v.hex()
                            elif k == 'classes' and isinstance(v, list):
                                row[prefix + k] = ','.join(map(str, v))
                            else:
                                row[prefix + k] = v

                elt = elt.payload

            if vendor_infos:
                row['IE_VendorSpecific_infos'] = ';'.join(vendor_infos)

            rows.append(row)

df = pd.DataFrame(rows)

# For ML purposes: Fill NaN in numeric columns with 0, strings with ''
numeric_cols = df.select_dtypes(include=['number']).columns
df[numeric_cols] = df[numeric_cols].fillna(0)

object_cols = df.select_dtypes(include=['object']).columns
df[object_cols] = df[object_cols].fillna('')

df.to_csv(output_csv, index=False)

print(f"CSV saved to {output_csv}")