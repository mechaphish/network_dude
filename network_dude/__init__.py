"""
This module handles parsing data provided by DARPA UDP packets
into pickled objects and writes them to DB do after each round.
"""
import os
import pickle
import shutil
import socket
import struct
import thread
import threading
import collections
import time
import uuid
from Queue import Queue

from dotenv import load_dotenv
from common_utils.simple_logging import *
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
from farnsworth.models import *

MAX_CS_SIZE = 6*1024*1024  # 6 megs
CHUNKS_TIME = 60  # 1 minute


def str2bool(string):
    return string.lower() in ["true", "t", "1"]


class Connection(object):
    """
    Class that handles incomming packets.
    """

    CLIENT, SERVER = (0, 1)
    HEADER_LEN = 15

    def __init__(self, port, data_folder):
        """
            Create a connection object.
        :param port: Port number to listen
        :param data_folder: folder in which the incoming data needs to be saved.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock.bind(('0.0.0.0', port))

        self.data_folder = data_folder
        self.curr_out_filename = None
        self.curr_out_file = None
        self.log_every_packet = str2bool(os.environ.get('LOG_EVERY_PACKET', "False"))
        self.curr_file_lock = threading.Lock()
        self.data_queue = Queue()
        # holds amount of data for each cs
        self.cs_data = collections.defaultdict(int)

        log_info("logging network traffic from port:" + str(port) + " to folder:" + str(self.data_folder))

    def start_listening(self):
        # fast network thread, receive data, put into queue and move on.
        log_info("Starting to listen.")
        while True:
            # Receive data
            data = self.sock.recvfrom(0xFFFF)[0]
            self.data_queue.put(data)

    def write_packet(self, packet):
        """
            Write provided data as pickled object into file
        :param packet: packet to be written to file
        :return: None
        """
        try:
            # get CS and size
            pkt_cs = packet[0]
            # side
            pkt_side = packet[-2]
            # ignore the packet, if this packet is not to server or binary
            if pkt_side != 'server':
                return
            data_size = len(packet[-1])
            # Try to obtain lock.
            # but the lock should be non-blocking.
            # This way we will be fast and doesn't slow down the receiving thread.
            if self.curr_file_lock.acquire():
                # if we already captured enough data for this CS, ignore the packet.
                if self.cs_data[pkt_cs] < MAX_CS_SIZE:
                    if self.curr_out_file is None or self.curr_out_filename is None:
                        self.curr_out_filename = os.path.join(self.data_folder, str(time.time()) + '_' +
                                                              str(uuid.uuid4()) + '_network_traffic')
                        log_info("Starting dumping to new file:" + str(self.curr_out_filename))
                        self.curr_out_file = open(self.curr_out_filename, 'wb')
                    self.cs_data[pkt_cs] += data_size
                    pickle.dump(packet, self.curr_out_file)
                    self.curr_out_file.flush()
                self.curr_file_lock.release()
            else:
                log_error("Unable to obtain lock on current file, ignoring the packet.")
        except Exception as e:
            try:
                # Try to release the lock, to avoid deadlocks.
                self.curr_file_lock.release()
            except Exception as e1:
                # Ignore all exceptions.
                pass
            log_error("Unexpected error occurred while trying to write packet to file:" + str(e))

    def parse(self, data):
        """
            Parse the provided message into various fields.
        :param data: Data to be parsed.
        :return: csid, connection_id, msg_id, side, message
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


def pkt_processor_thread(connection_object):
    """
        Thread which parses each UDP pkt and writes the corresponding data into a file
    :param connection_object: Connection object, which is the producer of the data.
    :return: Never return
    """
    target_data_queue = connection_object.data_queue
    while True:
        try:
            curr_data = target_data_queue.get()
            packet = connection_object.parse(curr_data)
            if packet is None:
                continue
            if connection_object.log_every_packet:
                csid, connection_id, msg_id, side, message = packet
                log_info("csid: " + str(csid) + " connection: " + str(connection_id) + " message_id: " + str(msg_id) +
                         " side: " + str(side))
            connection_object.write_packet(packet)
        except Exception as e:
            log_error("Error occurred while trying to process pkt:" + str(e) + ", Ignoring and moving on.")


def data_dumper_thread(connection_object):
    """
    Thread which writes the collected data to DB.
    :param connection_object: Connection object, which needs to be monitored.
    :return:
    """
    log_info("Starting Data Dumper Thread.")
    cleanup_traffic_files = str2bool(os.environ.get('CLEANUP_RAW_TRAFFIC_FILES', "True"))
    while True:
        # sleep for chunks time.
        time.sleep(CHUNKS_TIME)
        try:
            target_file_name = None
            curr_round = Round.current_round()
            if connection_object.curr_out_file is not None:
                # blocking acquire
                connection_object.curr_file_lock.acquire()
                # close the current files
                target_file_name = connection_object.curr_out_filename
                # Do not close file here (as it might delay the pkt processor thread),
                # just get the file object and move on
                # we want the network thread to be super fast.
                target_fp = connection_object.curr_out_file
                connection_object.curr_out_file = None
                connection_object.curr_out_filename = None
                connection_object.cs_data = collections.defaultdict(int)
                # release file locks.
                connection_object.curr_file_lock.release()
                # close the file
                target_fp.close()
                if target_file_name is not None:
                    log_info("Chunk Time Expired in Round:" + str(curr_round.num) + ". Dumping the file:"
                             + str(target_file_name) + " into DB.")
                    fp = open(target_file_name, 'rb')
                    file_data = fp.read()
                    fp.close()
                    # check if we need to clean up..if yes, remove the file.
                    if cleanup_traffic_files:
                        os.system('rm ' + target_file_name)
                    RawRoundTraffic.create(round=curr_round, pickled_data=file_data)
        except Exception as e:
            try:
                # To avoid deadlocks.
                connection_object.curr_file_lock.release()
            except Exception as e1:
                pass
            log_error("Error occurred while trying to save the dump file to DB:" + str(e))


def main():
    # Setup idle time between rounds (ensure that we have some minimum timeout)
    # MIN_IDLE_TIME = 15
    # round_idle_time = max(MIN_IDLE_TIME, int(os.environ.get('ROUND_IDLE_TIME', 20)))
    # Setup Data folder: delete and recreate
    data_folder = os.environ.get('DATA_FOLDER', "queue")
    if os.path.exists(data_folder):
        shutil.rmtree(data_folder)
    os.makedirs(data_folder)
    # Port number on which we need to listen
    port = int(os.environ.get("IDS_SERVICE_PORT", 1999))

    # Create connection object.
    connection = Connection(port, data_folder)
    # Start the pkt processor thread
    thread.start_new_thread(pkt_processor_thread, (connection, ))
    # Start the data dumper thread.
    thread.start_new_thread(data_dumper_thread, (connection, ))
    # Continue listening.
    connection.start_listening()

if __name__ == "__main__":
    main()
