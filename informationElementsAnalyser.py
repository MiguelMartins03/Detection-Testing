import os
import datetime as dt
import sys
from simple_colors import *
from scapy.all import rdpcap, Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
from _t1ha0_module import ffi, lib
import binascii
import pandas as pd
from collections import defaultdict

write_file = 0
show_bytes_variation = 0
show_bits_variation = 0
if(len(sys.argv) < 3 ) :
    print("Sem os argumentos necessarios!")
    exit(0)
show_bytes_bits_vari = str(sys.argv[1])
if(show_bytes_bits_vari == "show-bits-variation"):
    show_bytes_variation = 1
    show_bits_variation = 1
elif (show_bytes_bits_vari == "show-bytes-variation"):
    show_bytes_variation = 1
    show_bits_variation = 0
elif (show_bytes_bits_vari == "no-variation"):
    show_bytes_variation = 0
else:
    print("Argumento 1 invalido! Escolher entre: 'no-variation' ou 'show-bytes-variation' ou 'show-bits-variation' se pretender ou nao visualizar variacao, e a que nivel (bytes ou dos bits) para cada Information Element.")
    exit(0)
write_to_file=str(sys.argv[2])
if(write_to_file == "write"):
    write_file = 1
elif (write_to_file == "no-write"):
    write_file = 0
else:
    print("Argumento 2 invalido! Escolher entre: 'write' ou 'no-write' se pretender ou nao a escrita para o ficheiro de texto.")
    exit(0)

# Load OUI_DICT
OUI_DICT = {}
with open("/home/kali/Desktop/wireshark-oui-list.txt", 'r') as file:
    for line in file:
        if '\t' in line:
            oui, manuf = line.split('\t', 1)
            OUI_DICT[oui.strip().upper()] = manuf.strip()

# Manufacturer per pcap file
manuf_per_file = {
    'CF': 'TCL',
    'AX': 'Realme',
    'AP': 'BlackView',
    'CP': 'OPPO',
    'BT': 'Samsung',
    'BN': 'Samsung',
    'AQ': 'Samsung',
    'AF': 'Samsung',
    'AG': 'Samsung',
    'R': 'Samsung',
    'AK': 'Samsung',
    'BU': 'Samsung',
    'BA': 'Samsung',
    'CH': 'Samsung',
    'CR': 'Samsung',
    'T': 'Samsung',
    'BS': 'Samsung',
    'AT': 'Samsung',
    'BH': 'Samsung',
    'AM': 'Samsung',
    'BL': 'Samsung',
    'AA': 'Samsung',
    'BK': 'Apple',
    'CL': 'Apple',
    'AB': 'Apple',
    'BC': 'Apple',
    'AV': 'Apple',
    'AW': 'Apple',
    'BI': 'Apple',
    'BJ': 'Apple',
    'CD': 'Apple',
    'CQ': 'Apple',
    'CS': 'Apple',
    'CO': 'Apple',
    'BX': 'Apple',
    'A': 'Apple',
    'AD': 'Apple',
    'BB': 'Apple',
    'BM': 'Apple',
    'CC': 'Apple',
    'CI': 'Apple',
    'CE': 'Apple',
    'Z': 'Apple',
    'BR': 'Apple',
    'CT': 'Apple',
    'U': 'Apple',
    'BG': 'Apple',
    'BD': 'Apple',
    'CU': 'Apple',
    'CV': 'Apple',
    'S': 'Apple',
    'AC': 'Apple',
    'BV': 'Apple',
    'BO': 'Apple',
    'X': 'Apple',
    'CG': 'Xiaomi',
    'AU': 'Samsung',
    'AR': 'Huawei',
    'AI': 'Huawei',
    'AJ': 'Huawei',
    'CN': 'POCO',
    'BQ': 'Huawei',
    'AE': 'Xiaomi',
    'CM': 'Xiaomi',
    'AH': 'Xiaomi',
    'CB': 'Xiaomi',
    'W': 'OPPO',
    'BP': 'SPC',
    'CJ': 'POCO',
    'BW': 'Asus'
}

# Collect data from pcap files
data = []
folder = '/home/kali/Detection_Testing/Data'
for filename in os.listdir(folder):
    if filename.endswith('.pcap'):
        filepath = os.path.join(folder, filename)
        try:
            packets = rdpcap(filepath)
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue
        device = filename[:-5]
        manufacturer = manuf_per_file.get(device, 'Unknown')
        for pkt in packets:
            if pkt.haslayer(Dot11ProbeReq):
                mac = pkt.addr2.upper()
                timestamp = dt.datetime.fromtimestamp(float(pkt.time)).replace(second=0, microsecond=0)
                power = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and 'dBm_AntSignal' in pkt[RadioTap].fields else ''
                if power:
                    power = f"{power} dB"
                seq = pkt[Dot11].SC >> 4
                channel = pkt[RadioTap].Channel if pkt.haslayer(RadioTap) and 'Channel' in pkt[RadioTap].fields else ''
                mode = 'S'  # Assuming from example
                elt = pkt[Dot11Elt]
                ie_dict = {}
                vendor_list = []
                ie_ids = []
                vendor_count = 0
                array_v = []
                while isinstance(elt, Dot11Elt):
                    id_ = elt.ID
                    content = binascii.hexlify(elt.info).decode('ascii').upper()
                    if id_ == 1:
                        ie_dict['Supp_Rates'] = content
                        ie_ids.append('1')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 50:
                        ie_dict['Extended_Supp_Rates'] = content
                        ie_ids.append('50')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 3:
                        ie_dict['DS_Parameter'] = content
                        ie_ids.append('3')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 45:
                        ie_dict['HT_Capabilities'] = content
                        ie_ids.append('45')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 127:
                        ie_dict['Extended_Capabilities'] = content
                        ie_ids.append('127')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 191:
                        ie_dict['VHT_Capabilities'] = content
                        ie_ids.append('191')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 70:
                        ie_dict['RM_enabled_Capabilities'] = content
                        ie_ids.append('70')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 107:
                        ie_dict['Interworking'] = content
                        ie_ids.append('107')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 59:
                        ie_dict['Supp_Operating_Classes'] = content
                        ie_ids.append('59')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elif id_ == 221:
                        vendor_count += 1
                        vendor_list.append(content)
                        ie_ids.append(f'221({vendor_count})')
                        array_v.append(elt.ID)
                        array_v.append(elt.len)
                        for c in elt.info:
                            array_v.append(c)
                    elt = elt.payload
                def sort_key(x):
                    if '(' in x:
                        return (221, int(x.split('(')[1][:-1]))
                    else:
                        return (int(x), 0)
                ie_array = ' '.join(sorted(ie_ids, key=sort_key))
                hash_val = lib.t1ha0(bytes(array_v), len(array_v), 3)
                footprint = format(hash_val, '016X')
                vendors = [''] * 4
                for i, v in enumerate(vendor_list):
                    if i < 4:
                        vendors[i] = v
                entry = {
                    'MAC_Address': mac,
                    'Footprint': footprint,
                    'IE_array': ie_array,
                    'Supp_Rates': ie_dict.get('Supp_Rates', ''),
                    'Extended_Supp_Rates': ie_dict.get('Extended_Supp_Rates', ''),
                    'DS_Parameter': ie_dict.get('DS_Parameter', ''),
                    'HT_Capabilities': ie_dict.get('HT_Capabilities', ''),
                    'Extended_Capabilities': ie_dict.get('Extended_Capabilities', ''),
                    'VHT_Capabilities': ie_dict.get('VHT_Capabilities', ''),
                    'RM_enabled_Capabilities': ie_dict.get('RM_enabled_Capabilities', ''),
                    'Interworking': ie_dict.get('Interworking', ''),
                    'Supp_Operating_Classes': ie_dict.get('Supp_Operating_Classes', ''),
                    'Vendor_1': vendors[0],
                    'Vendor_2': vendors[1],
                    'Vendor_3': vendors[2],
                    'Vendor_4': vendors[3],
                    'Timestamp': timestamp,
                    'Power': power,
                    'Manufacturer': manufacturer,
                    'SEQ': seq,
                    'Device': device,
                    'Mode': mode,
                    'Channel': channel
                }
                data.append(entry)

df = pd.DataFrame(data)

if write_file:
    file = open('/home/kali/Detection_Testing/InformationElementsReport.txt', 'a')
# Data e hora atual
dataAtual=dt.datetime.now().replace(second=0, microsecond=0)
if write_file: file.write("#################################### [" + str(dataAtual) + "] ######################################\n\n")
# Informacoes Gerais
print("\n--------------------------------------- Informacoes Gerais --------------------------------------------")
if write_file: file.write("\n--------------------------------------- Informacoes Gerais --------------------------------------\n")
#Numero total de Probe Requests (com enderecos MAC aleatorios) capturados
total_probe_req = len(df)
print("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_req) + "\n")
if write_file: file.write("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_req) + "\n\n")
#Numero de enderecos MAC diferentes na base de dados
total_mac_addresses = df['MAC_Address'].nunique()
print("[Numero de enderecos MAC diferentes: " + str(total_mac_addresses) + "]")
if write_file: file.write("[Numero de enderecos MAC diferentes: " + str(total_mac_addresses) + "]\n")
#Numero de Footprints diferentes na base de dados
total_footprints = df['Footprint'].nunique()
print("[Numero de Footprints diferentes: " + str(total_footprints) + "]")
if write_file: file.write("[Numero de Footprints diferentes: " + str(total_footprints) + "]\n")
#Racio #Enderecos MAC/#Footprints
if total_footprints != 0:
    print("[#Enderecos MAC/#Footprints: " + str(round((total_mac_addresses / total_footprints),2)) + "]\n")
    if write_file: file.write("[#Enderecos MAC/#Footprints: " + str(round((total_mac_addresses / total_footprints),2)) + "]\n\n")
else:
    print("[#Enderecos MAC/#Footprints: 0]\n")
    if write_file: file.write("[#Enderecos MAC/#Footprints: 0]\n\n")
#Numero de enderecos MAC com apenas uma Footprint
grouped_mac_fp = df.groupby(['MAC_Address', 'Footprint']).size().reset_index(name='count')
mac_fp_counts = grouped_mac_fp.groupby('MAC_Address').size()
mac_adresses_one_footprint = len(mac_fp_counts[mac_fp_counts == 1])
print("[Enderecos MAC com apenas uma Footprint: " + str(mac_adresses_one_footprint) + "]")
if write_file: file.write("[Enderecos MAC com apenas uma Footprint: " + str(mac_adresses_one_footprint) + "]\n")
#Numero de enderecos MAC com multiplas Footprints
mac_adresses_multiple_footprints = len(mac_fp_counts[mac_fp_counts > 1])
print("[Enderecos MAC com multiplas Footprints: " + str(mac_adresses_multiple_footprints) + "]")
if write_file: file.write("[Enderecos MAC com multiplas Footprints: " + str(mac_adresses_multiple_footprints) + "]\n")
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
# Quais os enderecos MAC com mais do que uma footprint e as diferentes footprints geradas para cada um
mac_adresses = mac_fp_counts[mac_fp_counts > 1].index.tolist()
number_footprints = []
print("------------------------------------- Enderecos MAC diferentes ---------------------------------------")
if write_file: file.write("---------------------------------- Enderecos MAC diferentes -------------------------------------\n\n")
#Numero de enderecos MAC com diferentes footprints
print("[Enderecos MAC com multiplas Footprints: " + str(len(mac_adresses)) + "]\n")
if write_file: file.write("[Enderecos MAC com multiplas Footprints: " + str(len(mac_adresses)) + "]\n\n")
mac_to_footprints = defaultdict(set)
for _, row in grouped_mac_fp.iterrows():
    mac_to_footprints[row['MAC_Address']].add(row['Footprint'])
for mac_address in mac_adresses:
    #Numero de footprints diferentes para cada endereco MAC
    footprints = list(mac_to_footprints[mac_address])
    number_footprints.append(len(footprints))
    #Footprints diferentes de cada endereco MAC
    footprints_string = " ".join(footprints)
    print(cyan(str(mac_address)) + "| " + str(len(footprints)) + " footprints diferentes | " + str(footprints_string))
    if write_file: file.write(str(mac_address) + "| " + str(len(footprints)) + " footprints diferentes | " + str(footprints_string) + "\n")
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
# Quais os Information Elements utilizados em cada Footprint para cada endereco MAC
print("----------------------------------- Information Elements Utilizados ----------------------------------")
if write_file: file.write("--------------------------------- Information Elements Utilizados -------------------------------\n")
mac_to_fp_count = defaultdict(lambda: defaultdict(int))
for _, row in grouped_mac_fp.iterrows():
    mac_to_fp_count[row['MAC_Address']][row['Footprint']] = row['count']
for mac_address in mac_adresses:
    #Numero de footprints diferentes e a sua contagem para cada endereco MAC
    footprints_and_IEs = []
    for fp in mac_to_fp_count[mac_address]:
        count = mac_to_fp_count[mac_address][fp]
        ie_array = df[(df['MAC_Address'] == mac_address) & (df['Footprint'] == fp)]['IE_array'].iloc[0]
        footprints_and_IEs.append((fp, ie_array, count))
    footprints_and_IEs = sorted(footprints_and_IEs, key=lambda x: x[2], reverse=True)
    print(cyan(str("[" + mac_address + "]: ")))
    if write_file: file.write(str("[" + mac_address + "]: ") + "\n")
    for footprint_and_IE in footprints_and_IEs:
        print("\t" + str(footprint_and_IE[0]) + ": " + str(footprint_and_IE[1]) + "| Contagem: " + str(footprint_and_IE[2]))
        if write_file: file.write("\t" + str(footprint_and_IE[0]) + ": " + str(footprint_and_IE[1]) + "| Contagem: " + str(footprint_and_IE[2]) + "\n")
    print("")
    if write_file: file.write("\n")
       
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
DEFINITELY_NUMBER_MESSAGES = 20
REASONABLE_NUMBER_MESSAGES = 10
DEFINITELY_PERCENTAGE_MIN = 25
DEFINITELY_PERCENTAGE_MAX = 50
REASONABLE_PERCENTAGE_MIN = 10
REASONABLE_PERCENTAGE_MAX = 25
GREEN_THREHSOLD = 10 #Ate este valor o output sera com a cor verde (percentagem nao justifica remocao desse bit)
YELLOW_THRESHOLD = 40 #Ate este valor o output sera com a cor amarela (percentagem pode justificar a remocao desse bit)
RED_THRESHOLD = 50 #Ate este valor o output sera com a cor vermelha (percentagem justifica certamente a remocao desse bit)
# Quais os Information Elements e os bits/bytes que variaram para cada endereco MAC
info_elements = ["Footprint","IE array", "Supported Rates", "Extended Supported Rates", "DS Parameter Set", "HT Capabilities", "Extended Capabilities", "VHT Capabilities", "RM Enabled Capabilities", "Interworking", "Supported Operating Classes"]
definitely_variable_bits = []
reasonable_variable_bits = []
Dict = {}
for mac_address in mac_adresses:
    mac_df = df[df['MAC_Address'] == mac_address]
    fp_group = mac_df.groupby('Footprint').first()
    fp_group = fp_group.assign(ie_len=fp_group['IE_array'].str.len()).sort_values(['ie_len', 'IE_array']).drop('ie_len', axis=1)
    different_footprints = fp_group.to_records(index=True)
    Dict[mac_address] = {} #Dicionario que ira conter informacao sobre cada endereco MAC
    variable_info_elements = [] #Lista com Information Elements que variaram para cada endereco MAC
    dictionary_list = [] #Lista de dicionarios com bytes e bits diferentes de cada Information Element diferente para cada endereco MAC
    variable_OUIs = []
    content_variation_elements = [[],[],[],[],[],[],[],[],[],[],[]]
    #Numero total de mensagens para esse endereco MAC
    footprints_total_count = len(mac_df)
    #Apanhar variacoes de conteudo para cada Information Element de cada Footprint do endereco MAC (ate aos Vendor Specific)
    ie_fields = ['Supp_Rates', 'Extended_Supp_Rates', 'DS_Parameter', 'HT_Capabilities', 'Extended_Capabilities', 'VHT_Capabilities', 'RM_enabled_Capabilities', 'Interworking', 'Supp_Operating_Classes']
    for idx, row in fp_group.iterrows():
        for a, field in enumerate(ie_fields, 2):
            content = row[field]
            if content not in content_variation_elements[a] and content != '' and content != ' ':
                content_variation_elements[a].append(content)
    #Apanhar Information Elements que variaram (ate aos Vendor Specific)
    for r in range(len(content_variation_elements)):
        if len(content_variation_elements[r]) > 1:
            variable_info_elements.append(info_elements[r])
      
    i = 0
    # Iterar os conteudos diferentes de cada Information Element (ate aos Vendor Specific)
    for different_info_contents_list in content_variation_elements:
        info_element_index = content_variation_elements.index(different_info_contents_list)
        if len(different_info_contents_list) > 1:
            min_length = 0
            #Ver menor tamanho entre todos os conteudos desse Information Element, para saber ate onde se comparar
            for different_info_element_content in different_info_contents_list:
                if min_length == 0:
                    min_length = len(different_info_element_content)
                elif len(different_info_element_content) < min_length:
                    min_length = len(different_info_element_content)
            different_info_elem_content_truncated_list = []
            #Truncar todos os conteudos ao tamanho de bytes minimo entre todos os conteudos desse Information Element
            for different_info_element_content in different_info_contents_list:
                if len(different_info_element_content) > min_length:
                    truncated_bytes = different_info_element_content[:-(len(different_info_element_content)-min_length)]
                else:
                    truncated_bytes = different_info_element_content
                different_info_elem_content_truncated_list.append(truncated_bytes)
            if len(set(different_info_elem_content_truncated_list)) > 1:
                bits_number = "0" + str(int(min_length/2)*8) + "b"
                xor_list = [] #Lista de todos os XORs feitos entre todos os conteudos desse Information Element
                #Comparar os conteudos (diferentes) de cada Information Element e fazer o XOR entre cada um adjacentemente
                for different_info_element_content_x,different_info_element_content_y in zip(different_info_elem_content_truncated_list,different_info_elem_content_truncated_list[1:]):
                    #XOR entre todos os conteudos desses Information Elements
                    convert_string_x = int(different_info_element_content_x, base=16)
                    convert_string_y = int(different_info_element_content_y, base=16)
                    xor = convert_string_x ^ convert_string_y
                    binary_xor = format(xor, bits_number)
                    xor_list.append(binary_xor)
                final_xor = format(0, bits_number)
                final_xor_l = list(final_xor)
                for xor_element in xor_list:
                    for xor_bit in range(len(xor_element)):
                        if str(xor_element[xor_bit]) == "1":
                            final_xor_l[xor_bit] = '1'
                final_xor = "".join(final_xor_l)
                bit_position = 1
                variable_bytes = [] #Bytes diferentes no conteudo
                variable_bits = [] #Bits e bytes diferentes no conteudo
                variable_bits_count = [] #Contagem de '0's e '1's de cada bit de cada byte diferente no conteudo
                temp_definitely_variable_bits = []
                temp_reasonable_variable_bits = []
                #Obtencao dos bits/bytes diferentes de entre todas as Footprints
                for bit in range(len(final_xor)):
                   
                    if(int(final_xor[bit]) == 1):
                        if( bit_position%8 != 0 ):
                            position_bit = bit_position%8
                            position_byte = bit_position//8 + 1
                        else:
                            position_bit = 8
                            position_byte = bit_position//8
                       
                        if position_byte not in variable_bytes:
                            variable_bytes.append(position_byte)
                           
                        variable_bits.append(str(position_byte) + "|" + str(position_bit))
                        zeros_counter = 0
                        ones_counter = 0
                       
                        #Contagem de 0's e 1's desse bit
                        for idx, row_fp in fp_group.iterrows():
                            footprint = idx
                            count_df = grouped_mac_fp[(grouped_mac_fp['MAC_Address'] == mac_address) & (grouped_mac_fp['Footprint'] == footprint)]
                            footprint_count = count_df['count'].iloc[0] if not count_df.empty else 0
                            different_footprint = row_fp
                            if different_footprint[ie_fields[i-2]] != '' and different_footprint[ie_fields[i-2]] != ' ':
                                if len(different_footprint[ie_fields[i-2]]) > min_length:
                                    truncated_bytes_temp = different_footprint[ie_fields[i-2]][:-(len(different_footprint[ie_fields[i-2]])-min_length)]
                                else:
                                    truncated_bytes_temp = different_footprint[ie_fields[i-2]]
                                convert_string_temp = int(truncated_bytes_temp, base=16)
                                binary_temp = format(convert_string_temp, bits_number)
                                if binary_temp[bit_position-1] != None:
                                    if str(binary_temp[bit_position-1]) == "0":
                                        zeros_counter += footprint_count
                                    elif str(binary_temp[bit_position-1]) == "1":
                                        ones_counter += footprint_count
                        bit0_calc = str(zeros_counter) + "/" + str(footprints_total_count)
                        bit0_percentage = round((zeros_counter/footprints_total_count)*100)
                        bit1_calc = str(ones_counter) + "/" + str(footprints_total_count)
                        bit1_percentage = round((ones_counter/footprints_total_count)*100)
                        variable_bits_count.append(str(position_byte) + "|" + str(position_bit) + "|" + str(bit0_calc) + "|" + str(bit0_percentage) + "|" + str(bit1_calc) + "|" + str(bit1_percentage))
                        if ((int(bit0_percentage) >= DEFINITELY_PERCENTAGE_MIN and int(bit0_percentage) <= DEFINITELY_PERCENTAGE_MAX) or (int(bit1_percentage) >= DEFINITELY_PERCENTAGE_MIN and int(bit1_percentage) <= DEFINITELY_PERCENTAGE_MAX)) and (int(footprints_total_count) > DEFINITELY_NUMBER_MESSAGES):
                            if str(position_byte) + "|" + str(position_bit) not in temp_definitely_variable_bits:
                                temp_definitely_variable_bits.append(str(position_byte) + "|" + str(position_bit))
                        elif ((int(bit0_percentage) >= REASONABLE_PERCENTAGE_MIN and int(bit0_percentage) <= REASONABLE_PERCENTAGE_MAX) or (int(bit1_percentage) >= REASONABLE_PERCENTAGE_MIN and int(bit1_percentage) <= REASONABLE_PERCENTAGE_MAX)) and (int(footprints_total_count) > REASONABLE_NUMBER_MESSAGES):
                            if str(position_byte) + "|" + str(position_bit) not in temp_reasonable_variable_bits and str(position_byte) + "|" + str(position_bit) not in temp_definitely_variable_bits:
                                temp_reasonable_variable_bits.append(str(position_byte) + "|" + str(position_bit))
                    bit_position += 1
                #print(temp_definitely_variable_bits)
                # Acrescentar bits definitivamente variaveis desse Information Element
                elemnt_already_exists = 0
                for info_elemnt_variable_bits_list in definitely_variable_bits:
                    if info_elemnt_variable_bits_list[0] == info_elements[i+2]:
                        elemnt_already_exists = 1
                if elemnt_already_exists == 0:
                    temp_list = []
                    temp_list.append(info_elements[i+2])
                    temp_list.append(temp_definitely_variable_bits)
                    definitely_variable_bits.append(temp_list)
                else:
                    for info_elemnt_variable_bits_list in definitely_variable_bits:
                        if info_elemnt_variable_bits_list[0] == info_elements[i+2]:
                            for variable_byte_bit in temp_definitely_variable_bits:
                                if variable_byte_bit not in info_elemnt_variable_bits_list[1]:
                                    info_elemnt_variable_bits_list[1].append(variable_byte_bit)
                # Acrescentar bits possivelmente variaveis desse Information Elements
                elemnt_already_exists = 0
                for info_elemnt_variable_bits_list in reasonable_variable_bits:
                    if str(info_elemnt_variable_bits_list[0]) == info_elements[i+2]:
                        elemnt_already_exists = 1
                       
                if elemnt_already_exists == 0:
                    temp_list = []
                    temp_list.append(info_elements[i+2])
                    temp_list.append(temp_reasonable_variable_bits)
                    reasonable_variable_bits.append(temp_list)
                else:
                    for info_elemnt_variable_bits_list in reasonable_variable_bits:
                        if info_elemnt_variable_bits_list[0] == info_elements[i+2]:
                            for variable_byte_bit in temp_reasonable_variable_bits:
                                if variable_byte_bit not in info_elemnt_variable_bits_list[1]:
                                    info_elemnt_variable_bits_list[1].append(variable_byte_bit)
                #Construcao de um dicionario para cada byte de cada Information Element com bits diferentes e sua contagem
                Info_Element_Byte_Dict = {}
                for t in range(len(variable_bytes)):
                    bits_list = []
                    for b in range(len(variable_bits)):
                        byte_n = variable_bits[b].split('|')[0]
                        bit_n = variable_bits[b].split('|')[1]
                        if(str(variable_bytes[t]) == str(byte_n)):
                            for g in range(len(variable_bits_count)):
                                byte_n_n = variable_bits_count[g].split('|')[0]
                                bit_n_n = variable_bits_count[g].split('|')[1]
                                if (str(byte_n_n) == str(byte_n) and str(bit_n_n) == str(bit_n)):
                                    bits_list.append(variable_bits_count[g])
                    Info_Element_Byte_Dict["[" + str(variable_bytes[t]) + "º byte]"] = bits_list
                dictionary_list.append(Info_Element_Byte_Dict)
        i += 1
    # * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * VENDOR SPECIFIC * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
    different_OUIs = []
    #Apanhar Vendor Specific OUIs diferentes para o endereco MAC
    for idx, row in fp_group.iterrows():
        for a in ['Vendor_1', 'Vendor_2', 'Vendor_3', 'Vendor_4']:
            different_footprint_a = row[a]
            if different_footprint_a != '' and different_footprint_a != ' ' and len(different_footprint_a) > 6:
                OUI_vend = str(different_footprint_a[0:2] + ":" + different_footprint_a[2:4] + ":" + different_footprint_a[4:6]).upper()
                if OUI_vend not in different_OUIs:
                    different_OUIs.append(OUI_vend)
    different_OUIs_content = [[] for _ in range(len(different_OUIs))]
    #Apanhar variacoes de conteudo para cada Vendor Specific OUI de cada Footprint do endereco MAC
    for idx, row in fp_group.iterrows():
        for a in ['Vendor_1', 'Vendor_2', 'Vendor_3', 'Vendor_4']:
            different_footprint_a = row[a]
            if different_footprint_a != '' and different_footprint_a != ' ' and len(different_footprint_a) > 6:
                OUI_temp = str(different_footprint_a[0:2] + ":" + different_footprint_a[2:4] + ":" + different_footprint_a[4:6]).upper()
                if OUI_temp in different_OUIs:
                    if different_footprint_a not in different_OUIs_content[different_OUIs.index(OUI_temp)]:
                        different_OUIs_content[different_OUIs.index(OUI_temp)].append(different_footprint_a)
    # Iterar os conteudos diferentes de cada Vendor Specific OUI
    for different_vendor_list in different_OUIs_content:
        OUI_vendor = different_OUIs[different_OUIs_content.index(different_vendor_list)]
        if len(different_vendor_list) > 1:
            variable_info_elements.append(OUI_vendor)
            min_length = 0
            for different_vendor_content in different_vendor_list:
                if min_length == 0:
                    min_length = len(different_vendor_content)
                elif len(different_vendor_content) < min_length:
                    min_length = len(different_vendor_content)
            different_vendor_content_truncated_list = []
            for different_vendor_content in different_vendor_list:
                if len(different_vendor_content) > min_length:
                    truncated_bytes = different_vendor_content[:-(len(different_vendor_content)-min_length)]
                else:
                    truncated_bytes = different_vendor_content
                different_vendor_content_truncated_list.append(truncated_bytes)
            if len(set(different_vendor_content_truncated_list)) > 1:
                bits_number = "0" + str(int(min_length/2)*8) + "b"
                xor_list = []
                for different_vendor_content_x,different_vendor_content_y in zip(different_vendor_content_truncated_list,different_vendor_content_truncated_list[1:]):
                    convert_string_x = int(different_vendor_content_x, base=16)
                    convert_string_y = int(different_vendor_content_y, base=16)
                    xor = convert_string_x ^ convert_string_y
                    binary_xor = format(xor, bits_number)
                    xor_list.append(binary_xor)
                final_xor = format(0, bits_number)
                final_xor_l = list(final_xor)
                for xor_element in xor_list:
                    for xor_bit in range(len(xor_element)):
                        if str(xor_element[xor_bit]) == "1":
                            final_xor_l[xor_bit] = '1'
                final_xor = "".join(final_xor_l)
                bit_position = 1
                variable_bytes = []
                variable_bits = []
                variable_bits_count = []
                temp_definitely_variable_bits_vendor = []
                temp_reasonable_variable_bits_vendor = []
                for bit in range(len(final_xor)):
                    if(int(final_xor[bit]) == 1):
                        if( bit_position%8 != 0 ):
                            position_bit = bit_position%8
                            position_byte = bit_position//8 + 1
                        else:
                            position_bit = 8
                            position_byte = bit_position//8
                        if position_byte not in variable_bytes:
                            variable_bytes.append(position_byte)
                        variable_bits.append(str(position_byte) + "|" + str(position_bit))
                        zeros_counter = 0
                        ones_counter = 0
                        for idx, row_fp in fp_group.iterrows():
                            footprint = idx
                            count_df = grouped_mac_fp[(grouped_mac_fp['MAC_Address'] == mac_address) & (grouped_mac_fp['Footprint'] == footprint)]
                            footprint_count = count_df['count'].iloc[0] if not count_df.empty else 0
                            different_footprint = row_fp
                            for a in ['Vendor_1', 'Vendor_2', 'Vendor_3', 'Vendor_4']:
                                if different_footprint[a] != '' and different_footprint[a] != ' ' and len(different_footprint[a]) > 6:
                                    OUI_vend = str(different_footprint[a][0:2] + ":" + different_footprint[a][2:4] + ":" + different_footprint[a][4:6]).upper()
                                    if OUI_vend == OUI_vendor:
                                        if len(different_footprint[a]) > min_length:
                                            truncated_bytes_temp = different_footprint[a][:-(len(different_footprint[a])-min_length)]
                                        else:
                                            truncated_bytes_temp = different_footprint[a]
                                        convert_string_temp = int(truncated_bytes_temp, base=16)
                                        binary_temp = format(convert_string_temp, bits_number)
                                        if binary_temp[bit_position-1] != None:
                                            if str(binary_temp[bit_position-1]) == "0":
                                                zeros_counter += footprint_count
                                            elif str(binary_temp[bit_position-1]) == "1":
                                                ones_counter += footprint_count
                        bit0_calc = str(zeros_counter) + "/" + str(footprints_total_count)
                        bit0_percentage = round((zeros_counter/footprints_total_count)*100)
                        bit1_calc = str(ones_counter) + "/" + str(footprints_total_count)
                        bit1_percentage = round((ones_counter/footprints_total_count)*100)
                        variable_bits_count.append(str(position_byte) + "|" + str(position_bit) + "|" + str(bit0_calc) + "|" + str(bit0_percentage) + "|" + str(bit1_calc) + "|" + str(bit1_percentage))
                        if ((int(bit0_percentage) >= DEFINITELY_PERCENTAGE_MIN and int(bit0_percentage) <= DEFINITELY_PERCENTAGE_MAX) or (int(bit1_percentage) >= DEFINITELY_PERCENTAGE_MIN and int(bit1_percentage) <= DEFINITELY_PERCENTAGE_MAX)) and (int(footprints_total_count) > DEFINITELY_NUMBER_MESSAGES):
                            if str(position_byte) + "|" + str(position_bit) not in temp_definitely_variable_bits_vendor:
                                temp_definitely_variable_bits_vendor.append(str(position_byte) + "|" + str(position_bit))
                        elif ((int(bit0_percentage) >= REASONABLE_PERCENTAGE_MIN and int(bit0_percentage) <= REASONABLE_PERCENTAGE_MAX) or (int(bit1_percentage) >= REASONABLE_PERCENTAGE_MIN and int(bit1_percentage) <= REASONABLE_PERCENTAGE_MAX)) and (int(footprints_total_count) > REASONABLE_NUMBER_MESSAGES):
                            if str(position_byte) + "|" + str(position_bit) not in temp_reasonable_variable_bits_vendor and str(position_byte) + "|" + str(position_bit) not in temp_definitely_variable_bits_vendor:
                                temp_reasonable_variable_bits_vendor.append(str(position_byte) + "|" + str(position_bit))
                    bit_position += 1
                # Acrescentar bits definitivamente variaveis desse Vendor Specific OUI
                elemnt_already_exists = 0
                for info_elemnt_variable_bits_list in definitely_variable_bits:
                    if str(info_elemnt_variable_bits_list[0]) == str(OUI_vendor):
                        elemnt_already_exists = 1
                if elemnt_already_exists == 0:
                    temp_list = []
                    temp_list.append(OUI_vendor)
                    temp_list.append(temp_definitely_variable_bits_vendor)
                    definitely_variable_bits.append(temp_list)
                else:
                    for info_elemnt_variable_bits_list in definitely_variable_bits:
                        if info_elemnt_variable_bits_list[0] == OUI_vendor:
                            for variable_byte_bit in temp_definitely_variable_bits_vendor:
                                if variable_byte_bit not in info_elemnt_variable_bits_list[1]:
                                    info_elemnt_variable_bits_list[1].append(variable_byte_bit)
                # Acrescentar bits possivelmente variaveis desse Vendor Specific OUI
                elemnt_already_exists = 0
                for info_elemnt_variable_bits_list in reasonable_variable_bits:
                    if str(info_elemnt_variable_bits_list[0]) == str(OUI_vendor):
                        elemnt_already_exists = 1
                if elemnt_already_exists == 0:
                    temp_list = []
                    temp_list.append(OUI_vendor)
                    temp_list.append(temp_reasonable_variable_bits_vendor)
                    reasonable_variable_bits.append(temp_list)
                else:
                    for info_elemnt_variable_bits_list in reasonable_variable_bits:
                        if info_elemnt_variable_bits_list[0] == OUI_vendor:
                            for variable_byte_bit in temp_reasonable_variable_bits_vendor:
                                if variable_byte_bit not in info_elemnt_variable_bits_list[1]:
                                    info_elemnt_variable_bits_list[1].append(variable_byte_bit)
                #Construcao de um dicionario para cada byte de cada Information Element com bits diferentes e sua contagem
                Info_Element_Byte_Dict = {}
                for t in range(len(variable_bytes)):
                    bits_list = []
                    for b in range(len(variable_bits)):
                        byte_n = variable_bits[b].split('|')[0]
                        bit_n = variable_bits[b].split('|')[1]
                        if(str(variable_bytes[t]) == str(byte_n)):
                            for g in range(len(variable_bits_count)):
                                byte_n_n = variable_bits_count[g].split('|')[0]
                                bit_n_n = variable_bits_count[g].split('|')[1]
                                if (str(byte_n_n) == str(byte_n) and str(bit_n_n) == str(bit_n)):
                                    bits_list.append(variable_bits_count[g])
                    Info_Element_Byte_Dict["[" + str(variable_bytes[t]) + "º byte]"] = bits_list
                dictionary_list.append(Info_Element_Byte_Dict)
    #Insercao no dicionario de cada Information Element que variou e bits/bytes que variaram
    for e in range(len(variable_info_elements)):
        Dict[mac_address][variable_info_elements[e]] = dictionary_list[e]
# Construcao de um dicionario com os bits definitivamente variaveis
Definitely_InfoElem_Dict = {}
for definitely_info_element_byte_bit_list in definitely_variable_bits:
    Definitely_InfoElem_Dict[definitely_info_element_byte_bit_list[0]] = {}
    def_bytes = []
    for definitely_byte_bit in definitely_info_element_byte_bit_list[1]:
        byte = definitely_byte_bit.split('|')[0]
        if byte not in def_bytes:
            def_bytes.append(byte)
    for def_byte in def_bytes:
        definitely_byte_bits_list = []
        for definitely_byte_bit in definitely_info_element_byte_bit_list[1]:
            byte = definitely_byte_bit.split('|')[0]
            if byte == def_byte:
                definitely_byte_bits_list.append(definitely_byte_bit.split('|')[1])
        Definitely_InfoElem_Dict[definitely_info_element_byte_bit_list[0]][def_byte] = definitely_byte_bits_list
# Construcao de um dicionario com os bits provavelmente variaveis
Reasonable_InfoElem_Dict = {}
for reasonable_info_element_byte_bit_list in reasonable_variable_bits:
    Reasonable_InfoElem_Dict[reasonable_info_element_byte_bit_list[0]] = {}
    res_bytes = []
    for reasonable_byte_bit in reasonable_info_element_byte_bit_list[1]:
        byte = reasonable_byte_bit.split('|')[0]
        if byte not in res_bytes:
            res_bytes.append(byte)
    for res_byte in res_bytes:
        reasonable_byte_bits_list = []
        for reasonable_byte_bit in reasonable_info_element_byte_bit_list[1]:
            byte = reasonable_byte_bit.split('|')[0]
            if byte == res_byte:
                if Definitely_InfoElem_Dict.get(reasonable_info_element_byte_bit_list[0], {}).get(res_byte) is not None:
                    if reasonable_byte_bit.split('|')[1] not in Definitely_InfoElem_Dict[reasonable_info_element_byte_bit_list[0]][res_byte]:
                        reasonable_byte_bits_list.append(reasonable_byte_bit.split('|')[1])
                else:
                    reasonable_byte_bits_list.append(reasonable_byte_bit.split('|')[1])
        if len(reasonable_byte_bits_list):
            Reasonable_InfoElem_Dict[reasonable_info_element_byte_bit_list[0]][res_byte] = reasonable_byte_bits_list
       
print("----------------------------------- Information Elements Diferentes ----------------------------------\n")
if write_file: file.write("-------------------------------- Information Elements Diferentes --------------------------------\n\n")
for mac_address,info_element in Dict.items():
    if isinstance(info_element, str):
        print( cyan("[" + mac_address + "]: ") + red(str(info_element)) + "\n")
        if write_file: file.write("[" + mac_address + "]: " + str(info_element) + "\n")
    else:
        print( cyan("[" + mac_address + "]: ") + red(str(sorted(list(info_element.keys()), reverse=True))) )
        if write_file: file.write("[" + mac_address + "]: " + str(sorted(list(info_element.keys()))) + "\n")
        for key in sorted(info_element, reverse=True):
            if isinstance(info_element[key], str):
                print("\t" + red(key + ": " + str(info_element[key])))
                if write_file: file.write("\t" + key + ": " + str(info_element[key]) + "\n")
            else:
                print("\t" + red(key + ":") + magenta(" [Bytes diferentes: " + str(len(info_element[key])) + "] ") + "[Bits diferentes: " + str(sum(len(v) for v in info_element[key].values())) + "]")
                if write_file: file.write("\t" + key + ":" + " [Bytes diferentes: " + str(len(info_element[key])) + "] " + "[Bits diferentes: " + str(sum(len(v) for v in info_element[key].values())) + "]\n")
                if show_bytes_variation:
                    for byte_bit in sorted(info_element[key].keys(), key=lambda x: int(x[1:-7])):
                        print("\t " + magenta(byte_bit))
                        if write_file: file.write("\t " + byte_bit + "\n")
                        if show_bits_variation:
                            for bit_and_0s_1s in info_element[key][byte_bit]:
                                bit_n = bit_and_0s_1s.split('|')[1]
                                bit0_calc_n = bit_and_0s_1s.split('|')[2]
                                bit0_percentage_n = int(bit_and_0s_1s.split('|')[3])
                                bit1_calc_n = bit_and_0s_1s.split('|')[4]
                                bit1_percentage_n = int(bit_and_0s_1s.split('|')[5])
                                if (bit0_percentage_n >= YELLOW_THRESHOLD and bit0_percentage_n <= RED_THRESHOLD) or (bit1_percentage_n >= YELLOW_THRESHOLD and bit1_percentage_n <= RED_THRESHOLD):
                                    print("\t [" + str(bit_n) + "º bit]: " + red("0: " + str(bit0_percentage_n) + "% (" + str(bit0_calc_n) + ") | 1: " + str(bit1_percentage_n) + "% (" + str(bit1_calc_n) + ")"))
                                elif (bit0_percentage_n >= GREEN_THREHSOLD and bit0_percentage_n < YELLOW_THRESHOLD) or (bit1_percentage_n >= GREEN_THREHSOLD and bit1_percentage_n < YELLOW_THRESHOLD):
                                    print("\t [" + str(bit_n) + "º bit]: " + yellow("0: " + str(bit0_percentage_n) + "% (" + str(bit0_calc_n) + ") | 1: " + str(bit1_percentage_n) + "% (" + str(bit1_calc_n) + ")"))
                                elif (bit0_percentage_n > 0 and bit0_percentage_n < GREEN_THREHSOLD ) or (bit1_percentage_n > 0 and bit1_percentage_n < GREEN_THREHSOLD):
                                    print("\t [" + str(bit_n) + "º bit]: " + "0: " + str(bit0_percentage_n) + "% (" + str(bit0_calc_n) + ") | 1: " + str(bit1_percentage_n) + "% (" + str(bit1_calc_n) + ")")
                                else:
                                    print("\t [" + str(bit_n) + "º bit]: 0: " + str(bit0_percentage_n) + "% (" + str(bit0_calc_n) + ") | 1: " + str(bit1_percentage_n) + "% (" + str(bit1_calc_n) + ")")
                                if write_file: file.write("\t [" + str(bit_n) + "º bit]: 0: " + str(bit0_percentage_n) + "% (" + str(bit0_calc_n) + ") | 1: " + str(bit1_percentage_n) + "% (" + str(bit1_calc_n) + ")" + "\n")
               
            print("")
            if write_file: file.write("\n")
   
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
print("----------------------------------- Definitely Variable Bytes/Bits -----------------------------------\n")
if write_file: file.write("----------------------------------- Definitely Variable Bytes/Bits ------------------------------\n\n")
print("PARAMETERS:")
if write_file: file.write("PARAMETERS: \n")
print(" 1 - Minimum total number of Probe Requests: " + str(DEFINITELY_NUMBER_MESSAGES))
if write_file: file.write(" 1 - Minimum total number of Probe Requests: " + str(DEFINITELY_NUMBER_MESSAGES) + "\n")
print(" 2 - Variation Percentage: " + str(DEFINITELY_PERCENTAGE_MIN) + "%-" + str(DEFINITELY_PERCENTAGE_MAX) + "%")
if write_file: file.write(" 2 - Variation Percentage: " + str(DEFINITELY_PERCENTAGE_MIN) + "%-" + str(DEFINITELY_PERCENTAGE_MAX) + "% \n\n")
print("")
for info_element,bytes_bits in sorted(Definitely_InfoElem_Dict.items(), reverse=True):
    if len(bytes_bits):
        print(red("[" + str(info_element) + "]:"))
        if write_file: file.write("[" + str(info_element) + "]: \n")
        for byte in sorted(bytes_bits, key=int):
            print(red(" [" + str(byte) + "º byte]: "), end ="")
            if write_file: file.write(" [" + str(byte) + "º byte]: ")
           
            for count,bit in enumerate(sorted(bytes_bits[byte], key=int)):
                if count == len(bytes_bits[byte]) -1:
                    print(str(bit) + "º bit", end ="")
                    if write_file: file.write(str(bit) + "º bit")
                else:
                    print(str(bit) + "º bit, ", end ="")
                    if write_file: file.write(str(bit) + "º bit, ")
               
            print("")
            if write_file: file.write("\n")
        print("")
        if write_file: file.write("\n")
print("")
if write_file: file.write("\n")
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
print("----------------------------------- Possibly Variable Bytes/Bits -------------------------------------\n")
if write_file: file.write("----------------------------------- Possibly Variable Bytes/Bits --------------------------------\n\n")
print("PARAMETERS:")
if write_file: file.write("PARAMETERS: \n")
print(" 1 - Minimum total number of Probe Requests: " + str(REASONABLE_NUMBER_MESSAGES))
if write_file: file.write(" 1 - Minimum total number of Probe Requests: " + str(REASONABLE_NUMBER_MESSAGES) + "\n")
print(" 2 - Variation Percentage: " + str(REASONABLE_PERCENTAGE_MIN) + "%-" + str(REASONABLE_PERCENTAGE_MAX) + "%")
if write_file: file.write(" 2 - Variation Percentage: " + str(REASONABLE_PERCENTAGE_MIN) + "%-" + str(REASONABLE_PERCENTAGE_MAX) + "% \n\n")
print("")
for info_element,bytes_bits in sorted(Reasonable_InfoElem_Dict.items(), reverse=True):
    if len(bytes_bits):
        print(yellow("[" + str(info_element) + "]:"))
        if write_file: file.write("[" + str(info_element) + "]: \n")
        for byte in sorted(bytes_bits, key=int):
            print(yellow(" [" + str(byte) + "º byte]: "), end ="")
            if write_file: file.write(" [" + str(byte) + "º byte]: ")
           
            for count,bit in enumerate(sorted(bytes_bits[byte], key=int)):
                if count == len(bytes_bits[byte]) -1:
                    print(str(bit) + "º bit", end ="")
                else:
                    print(str(bit) + "º bit, ", end ="")
                if write_file: file.write(str(bit) + "º bit ")
            print("")
            if write_file: file.write("\n")
        print("")
        if write_file: file.write("\n")
print("")
if write_file: file.write("\n")
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
# Qual e o racio de presenca de cada Information Element para todos os Probe Requests (com enderecos MAC aleatorios) capturados
info_elements_IDs = ['1','50','3','45','127','191','70','107','59']
info_elements_presence_rate = [0] * len(info_elements_IDs)
print("--------------------------------- Information Elements Presence Rate ---------------------------------\n")
if write_file: file.write("--------------------------------- Information Elements Presence Rate ----------------------------\n\n")
#Numero total de Probe Requests com enderecos MAC aleatorios capturados
print("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_req) + "\n")
for idx, ie_id in enumerate(info_elements_IDs):
    info_elements_presence_rate[idx] = df['IE_array'].str.contains(ie_id).sum()
print("PRESENCE RATE: ")
if write_file: file.write("PRESENCE RATE: \n")
if total_probe_req != 0:
    for r in range(len(info_elements_IDs)):
        print("[" + str(info_elements[r+2]) + "]: " + str(info_elements_presence_rate[r]) + " | " + str(round(((info_elements_presence_rate[r]/total_probe_req)*100),2)) + " %")
        if write_file: file.write("[" + str(info_elements[r+2]) + "]: " + str(info_elements_presence_rate[r]) + " | " + str(round(((info_elements_presence_rate[r]/total_probe_req)*100),2)) + " %\n")
else:
    print("No messages captured.")
    if write_file: file.write("No messages captured.\n")
print("")
if write_file: file.write("\n")
           
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")
# Quais sao os Vendor Specific que mais costumam aparecer e os seus tipos nos Probe Requests (com enderecos MAC aleatorios) capturados
OUIs_count_Dict = {}
OUI_Types_count_Dict = {}
for mac_address in mac_adresses:
    mac_df = df[df['MAC_Address'] == mac_address]
    fp_group_count = grouped_mac_fp[grouped_mac_fp['MAC_Address'] == mac_address]
    fp_group = mac_df.groupby('Footprint').first()
    for idx, row in fp_group.iterrows():
        footprint = idx
        footprint_count = fp_group_count[fp_group_count['Footprint'] == footprint]['count'].iloc[0] if not fp_group_count[fp_group_count['Footprint'] == footprint].empty else 0
        for a in ['Vendor_1', 'Vendor_2', 'Vendor_3', 'Vendor_4']:
            vendor = row[a]
            if vendor != '' and len(vendor) > 6:
                OUI_c = vendor[0:2].upper() + ':' + vendor[2:4].upper() + ':' + vendor[4:6].upper()
                OUI_Type = str(int(vendor[6:8], base=16))
                OUIs_count_Dict[OUI_c] = OUIs_count_Dict.get(OUI_c, 0) + int(footprint_count)
                if OUI_Types_count_Dict.get(OUI_c) is None:
                    OUI_Types_count_Dict[OUI_c] = {}
                OUI_Types_count_Dict[OUI_c][OUI_Type] = OUI_Types_count_Dict[OUI_c].get(OUI_Type,0) + int(footprint_count)
print("--------------------------------------- Vendor Specific Information ----------------------------------\n")
if write_file: file.write("--------------------------------------- Vendor Specific Information -----------------------------\n\n")
print("Vendor Specific mais comuns: (Probe Requests com enderecos MAC aleatorios para apenas os enderecos MAC com mais do que uma Footprint) \n")
if write_file: file.write("Vendor Specific mais comuns: (Probe Requests com enderecos MAC aleatorios para apenas os enderecos MAC com mais do que uma Footprint) \n\n")
if OUIs_count_Dict:
    for oui,oui_total_count in sorted(OUIs_count_Dict.items(), key=lambda x:x[1], reverse=True):
        manuf_name = OUI_DICT.get(oui, "Unknown")
        print("[" + str(oui) + "]: Manufacturer: " + str(manuf_name) + " | Contagem: " + str(oui_total_count) + " | " + str(round((oui_total_count/total_probe_req*100),1)) + "%")
        if write_file: file.write("[" + str(oui) + "]: Manufacturer: " + str(manuf_name) + " | Contagem: " + str(oui_total_count) + " | " + str(round((oui_total_count/total_probe_req*100),1)) + "%\n")
        for oui_c ,oui_type_and_count in OUI_Types_count_Dict.items():
            if oui_c == oui:
                for key in oui_type_and_count:
                    print(" [OUI Type: " + str(key) + "]: " + str(oui_type_and_count[key]))
                    if write_file: file.write(" [OUI Type: " + str(key) + "]: " + str(oui_type_and_count[key]) + "\n")
else:
    print("No Vendor Specific Information Elements captured.")
    if write_file: file.write("No Vendor Specific Information Elements captured. \n")
print("\n------------------------------------------------------------------------------------------------------\n")
if write_file: file.write("\n-------------------------------------------------------------------------------------------------\n\n")
if write_file: file.write("#################################################################################################\n\n")
if write_file: file.close()