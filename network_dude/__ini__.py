"""

"""
import os
import struct
import socket
import time
import thread
import pickle
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

import simple_logging


def log_error(msg):
    """
    Log error message
    :param msg: Message to be logged
    :return: None
    """
    print("[!] " + str(msg))


def log_info(msg):
    """
    Log info message
    :param msg: Message to be logged
    :return: None
    """
    print("[*] " + str(msg))


def log_success(msg):
    """
    Log success message
    :param msg: Message to be logged
    :return: None
    """
    print("[+] " + str(msg))


def log_failure(msg):
    """
    Log failure message
    :param msg: Message to be logged
    :return: None
    """
    print("[-] " + str(msg))

# END TODO


class Connection(object):

    CLIENT, SERVER = (0, 1)
    HEADER_LEN = 15
    LOG_EVERY_PKT_KEY = 'LOG_EVERY_PACKET'

    def __init__(self, port, datafolder):
        """

        :param port:
        :param datafolder:
        :return:
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock.bind(('', port))

        self.datafolder = datafolder
        self.curr_out_filename = None
        self.curr_out_file = None
        self.last_pkt_received_at = None
        self.log_every_packet = False
        if Connection.LOG_EVERY_PKT_KEY in os.environ:
            if int(os.environ[Connection.LOG_EVERY_PKT_KEY]):
                self.log_every_packet = True

        log_info("logging network traffic from port:" + str(port) + " to folder:" + str(self.datafolder))

    def start_listening(self):
        while True:
            data = self.sock.recvfrom(0xFFFF)[0]
            self.last_pkt_received_at = time.time()
            packet = self.parse(data)
            if packet is None:
                continue

            csid, connection_id, msg_id, side, message = packet

            if self.log_every_packet:
                log_info("csid: " + str(csid) + " connection: " + str(connection_id) + " message_id: " + str(msg_id) +
                         " side: " + str(side))

            self.write_packet(packet)

    def open_pcap(self, filename):
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

    def write_packet(self, packet):
        """

        :param packet:
        :return:
        """
        if self.curr_out_file is None or self.curr_out_filename is None:
            self.curr_out_filename = os.path.join(self.datafolder, str(time.time()) + '_network_log')
            self.curr_out_file = open(self.curr_out_filename, 'wb')
        pickle.dump(packet, self.curr_out_file)
        self.curr_out_file.flush()

    def parse(self, data):
        """

        :param data:
        :return:
        """
        if len(data) < Connection.HEADER_LEN:
            log_error("invalid message length: " + str(len(data)))
            return None

        header = data[:Connection.HEADER_LEN]
        message = data[Connection.HEADER_LEN:]
        csid, connection_id, msg_id, msg_len, side = struct.unpack('<LLLHB', header)
        if len(message) != msg_len:
            log_error("invalid message.  actual: " + str(len(data)) + " expected: " + str(msg_len))
            return None

        if side == Connection.CLIENT:
            side = 'client'
        else:
            side = 'server'

        return csid, connection_id, msg_id, side, message

    def log(self, data):
        if self.pcap_file is None:
            return

        pass

DEFAULT_DATA_FOLDER = "queue"
MIN_IDLE_TIME = 15
DEFAULT_IDLE_TIME = 20
DEFAULT_PORT_NUMBER = 1999
PORT_NUMBER_KEY = 'LISTEN_PORT'
IDLE_TIME_KEY = 'ROUND_IDLE_TIME'
DATA_FOLDER_KEY = 'QUEUE_FOLDER'


def do_setup():
    """

    :return:
    """
    # Setup idle time between rounds
    round_idle_time = DEFAULT_IDLE_TIME
    if IDLE_TIME_KEY in os.environ:
        round_idle_time = int(os.environ[IDLE_TIME_KEY])
    # Ensure that we have some minimum timeout.
    round_idle_time = max(MIN_IDLE_TIME, round_idle_time)
    # Setup Data folder
    data_folder = DEFAULT_DATA_FOLDER
    if DATA_FOLDER_KEY in os.environ:
        data_folder = os.environ[DATA_FOLDER_KEY]
    if os.path.exists(data_folder):
        log_info("Cleaning up Data Folder:" + str(data_folder))
        os.system("rm -rf " + data_folder)
    # Port number on which we need to listen
    listen_port = DEFAULT_PORT_NUMBER
    if PORT_NUMBER_KEY in os.environ:
        listen_port = int(os.environ[PORT_NUMBER_KEY])
    # Complete Setup
    log_info("Creating Data Folder:" + str(data_folder))
    os.makedirs(data_folder)
    log_success("Setup Complete with Data Folder:" + str(data_folder) + " and timeout:" + str(round_idle_time) +
                " seconds")

    return round_idle_time, data_folder, listen_port


def data_dumper_thread(connection_object, idle_time_threshold):
    """

    :param connection_object:
    :param idle_time_threshold:
    :return:
    """
    log_info("Starting Data Dumper Thread.")
    poll_time = idle_time_threshold / 3
    if poll_time == 0:
        poll_time += 1
    while True:
        curr_time = time.time()
        idle_time = curr_time - connection_object.last_pkt_received_at
        if idle_time >= idle_time_threshold and connection_object.curr_out_file is not None:
            target_file_name = connection_object.curr_out_filename
            connection_object.curr_out_file.close()
            connection_object.curr_out_file = None
            connection_object.curr_out_filename = None
            log_info("Dumping the file:" + str(target_file_name) + " into DB.")
            # TODO: Dump the data to DB
        else:
            time.sleep(poll_time)


def main():
    round_idle_time, data_folder, listen_port = do_setup()
    conn_obj = Connection(listen_port, data_folder)
    thread.start_new_thread(data_dumper_thread, (conn_obj, round_idle_time, ))
    conn_obj.start_listening()

if __name__ == "__main__":
    main()
