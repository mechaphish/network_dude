import sys
import struct
import time
import os
from common_utils.binary_tester import BinaryTester
from common_utils.simple_logging import log_error, log_info, log_success
from common_utils.pcap_parser import PcapParser


def open_pcap(filename):
    if filename is None:
        return None

    PCAP_MAGIC = 0xa1b2c3d4L
    LINK_TYPE = 1  # ethernet

    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    if filename is None:
        return None

    pcap_handle = open(filename, 'w')
    header = struct.pack('>IHHIIII', PCAP_MAGIC, PCAP_VERSION_MAJOR,
                         PCAP_VERSION_MINOR, 0, 0, 1500, LINK_TYPE)

    pcap_handle.write(header)
    return pcap_handle


def write_packet(pcap_handle, data):
    if pcap_handle is None:
        return

    timestamp = time.time()
    tv_sec = int(timestamp)
    tv_usec = int((float(timestamp) - int(timestamp)) * 1000000.0)

    packet = '\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00' + '\xff\xff' + data

    packet_len = len(packet)
    packet_header = struct.pack('>IIII', tv_sec, tv_usec, packet_len, packet_len)

    pcap_handle.write(packet_header)
    pcap_handle.write(packet)
    pcap_handle.flush()


bin_file = sys.argv[1]
xml_pov_dir = sys.argv[2]
output_pcap_file = sys.argv[3]
dummy_cs_id = 12345678L
all_tests = os.listdir(xml_pov_dir)
log_info("Trying to create PCAP for:" + str(len(all_tests)) + " tests.")
pcap_file_handle = open_pcap(output_pcap_file)
connection_id = 1L
for curr_file in all_tests:
    curr_file_path = os.path.join(xml_pov_dir, curr_file)
    pcap_output_file = curr_file + '.cb.pcap'
    bin_tester = BinaryTester(bin_file, curr_file_path, is_cfe=True, pcap_output_file=pcap_output_file,
                              is_pov=not curr_file.endswith('xml'), standalone=True)
    ret_code, _, _ = bin_tester.test_cb_binary()
    if ret_code == 0:
        log_success("Provided Test:" + curr_file_path + " is OK.")
    else:
        log_error("Provided Test:" + curr_file_path + " failed.")
    assert os.path.exists(pcap_output_file), "PCAP for Test:" + curr_file_path + " does not exist."

    pcap_parser = PcapParser(pcap_output_file)
    tcp_stream = pcap_parser.get_data_stream()
    # ignore first 2 packets, as they are are for negotiating seed
    all_data_pkts = tcp_stream.data_pkts[2:]
    msg_id = 1L
    for curr_data_pkt in all_data_pkts:
        side = 1 if curr_data_pkt.is_input else 0
        msg_hdr = struct.pack("<LLLHB", dummy_cs_id, connection_id, msg_id, len(curr_data_pkt.data), side)
        msg_id += 1
        write_packet(pcap_file_handle, msg_hdr + curr_data_pkt.data)
    connection_id += 1
pcap_file_handle.close()