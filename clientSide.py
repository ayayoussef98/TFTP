import sys
import os
import enum
import struct
import socket


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.file_name = ""
        self.diskError = 0
        self.TFTPFlag = 0
        self.ErrorFlag = 0
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def parse(self):
        f = open(self.file_name, "rb")
        if f.mode == 'rb':
            content = f.read()
            f.close()
        array = []
        m = bytearray()

        for i in range(0, len(content), 511):
            count = 0
            while count < 512:
                m.append(content[i + count])
                count = count + 1
                if i + count >= len(content):
                    break
            array.append(m)
            m = bytearray()
        return array

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        unpacked = []

        if packet_bytes[0] == 0 and packet_bytes[1] == 3:  # data, respond with ack
            unpacked = struct.unpack('!HH' + str(packet_bytes[4:].__len__()) + 's', packet_bytes)
            file = open(self.file_name, "ab")
            try:
               file.write(unpacked[2])
            except MemoryError:
                self.diskError = 1

            file.close()

        elif packet_bytes[0] == 0 and packet_bytes[1] == 4:  # ack
            unpacked = struct.unpack('!HH', packet_bytes)

        elif packet_bytes[0] == 0 and packet_bytes[1] == 5:  #
            unpacked = struct.unpack('!HH' + str(packet_bytes[4:len(packet_bytes) - 1].__len__()) + 'sx', packet_bytes)
            print("Error Message: ")
            print(unpacked[2])
            exit()
        else:
            error = "Illegal TFTP operation."
            print(error)
            unpacked = struct.pack('!HH' + str(len(error)) + 'sx', 5, 4, str.encode(error))
            self.TFTPFlag=1
        return unpacked

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """

      #  print(f'YYY: {input_packet}')
        data = self.parse()
        packedData = []
        noofblock = input_packet[1]

        if input_packet[0] == 4:
            if noofblock == len(data):
                exit()
            packedData = struct.pack('!HH' + str(data[noofblock].__len__()) + 's', 3, noofblock+1 ,data[noofblock])
        elif input_packet[0] == 3:
            if self.diskError == 1:
                error = "Disk full or allocation exceeded."
                packedData = struct.pack('!HH' + str(len(error)) + 'sx', 5, 3, str.encode(error))
            else:
                packedData = struct.pack('!HH', 4, int(noofblock))


        return packedData

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        if os.path.isfile(file_path_on_server):
            print("File already exists")
            error="File already exists!"
            x.ErrorFlag = 1
            errorPacket=struct.pack('!HH' + str(len(error)) + 'sx',5,6,str.encode(error))
            print(errorPacket)
            self.packet_buffer.append(errorPacket)
        else:
           # print("File not exist")
               packed = struct.pack('!H' + str(file_path_on_server.__len__()) + 'sx' + str(("octet").__len__()) + 'sx', 1,
                        str.encode(file_path_on_server), str.encode("octet"))
               self.packet_buffer.append(packed)

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        if os.path.isfile(file_path_on_server):
            packed = struct.pack('!H' + str(file_path_on_server.__len__()) + 'sx' + str(("octet").__len__()) + 'sx', 2,
                                 str.encode(file_path_on_server), str.encode("octet"))
            self.packet_buffer.append(packed)
        else:
            print("File does not exist")
            error = "File does not exist!"
            errorPacket = struct.pack('!HH' + str(len(error)) + 'sx', 5, 6, str.encode(error))
            print(errorPacket)
            self.packet_buffer.append(errorPacket)

x = TftpProcessor()

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

def transferError():
    error = "Unknown transfer ID."
    errorPacket = struct.pack('!HH' + str(len(error)) + 'sx', 5, 5, str.encode(error))
    x.packet_buffer.append(errorPacket)

def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server_address = ("127.0.0.1", 69)

    # Note that sockets accept data as "bytes"
    # Sending a string will fail because the socket
    # can't assume an "encoding" that transforms this
    # string to the equivalent set of bytes.

    # client_socket.sendto("Hello".encode("ascii"), server_address)
    # on the other side, the server must call "decode" to convert
    # the received bytes to a human readable string.
    msg = x.get_next_output_packet()
    client_socket.sendto(msg, server_address)
    if x.ErrorFlag == 1:
        exit()
    a, b = client_socket.recvfrom(1024)
    c = b
    print("[CLIENT] Done!")
    # The buffer is the size of packet transit in our OS.
    while 1:

            if c == b:
                #print("[CLIENT] IN", server_packet)
                x.process_udp_packet(a, c)
                if x.TFTPFlag == 1:
                    exit()
                if x.has_pending_packets_to_be_sent():
                    z = x.get_next_output_packet()
                    print(z)
                    client_socket.sendto(z, c)
                if a[1] == 3:
                    if len(a[4:]) < 512:
                     exit()
            else:
              transferError()
              client_socket.sendto(x.get_next_output_packet(), c)

            a, c = client_socket.recvfrom(1024)
          #  c = ("127.0.0.1", 15)

    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        x.upload_file(file_name)

        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        x.request_file(file_name)
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "ayaa.txt")
    # Modify this as needed.
    x.file_name = file_name
    parse_user_input(ip_address, operation, file_name)
    setup_sockets("127.0.0.1")



if __name__ == "__main__":
    main()