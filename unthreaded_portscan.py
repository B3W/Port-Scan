# MIT License
#
# Copyright (c) 2019 Weston Berg
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
'''
UNTHREADED IMPLEMENTATION
Module providing functionality for scanning host for open TCP ports
'''
import socket

PORT_SCAN_MAX_WORKERS = 10      # How many workers can spawn for port scanning
PORT_SCAN_LOWER_RANGE = 1       # Where to start port scanning
PORT_SCAN_UPPER_RANGE = 100     # Where to end port scanning
ADDR_FAMILY = socket.AF_INET    # Addresses represented by tuple (host, port)
SOCK_TYPE = socket.SOCK_STREAM  # 'TCP' sockets


def unthreaded_scan(host, port):
    is_open = False

    # Attempt connection
    with socket.socket(ADDR_FAMILY, SOCK_TYPE) as sock:
        try:
            sock.connect((host, port))
            is_open = True  # If we make it here, connection successful
        except Exception:
            pass

    return is_open


def unthreaded_port_scan(host):
    '''
    Conducts a port scan of the provided host

    :param host: Host name or IP of host to conduct port scan.
                 IP shall be formatted 'xxx.xxx.xxx.xxx'.
    :returns: List of open ports on provided host
    '''
    open_ports = []

    # Check whether hostname or IP and whether it exists
    try:
        if any(c.isalpha() for c in host):
            socket.gethostbyname(host)
        else:
            # TODO check for correct IP formatting
            socket.gethostbyaddr(host)

    except (socket.gaierror, socket.herror):
        raise ValueError('%s host does not exist' % (host))

    # Start scanning the port on the host
    for port in range(PORT_SCAN_LOWER_RANGE, (PORT_SCAN_UPPER_RANGE + 1)):
        if unthreaded_scan(host, port):
            open_ports.append(port)

    return open_ports


# Unit Testing
if __name__ == '__main__':
    portlist = unthreaded_port_scan('localhost')

    for port in portlist:
        print(port)
