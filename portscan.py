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
Module providing functionality for scanning host for open TCP ports
'''
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import socket

PORT_SCAN_MAX_WORKERS = 1000    # How many workers can spawn for port scanning
ADDR_FAMILY = socket.AF_INET    # Addresses represented by tuple (host, port)
SOCK_TYPE = socket.SOCK_STREAM  # 'TCP' sockets


def __scan(queue, host, port):
    '''
    Helper function for scanning a port and placing result in queue
    '''
    # Attempt connection
    with socket.socket(ADDR_FAMILY, SOCK_TYPE) as sock:
        try:
            sock.connect((host, port))
            queue.append(port)  # If we make it here, connection successful
        except Exception:
            pass


def execute(host, lower_scan_range, upper_scan_range):
    '''
    Conducts a port scan of the provided host

    :param host: Host name or IP of host to conduct port scan.
                 IP shall be formatted 'xxx.xxx.xxx.xxx'.
    :param lower_scan_range: Port to begin scan at
    :param upper_scan_range: Port to end scan at
    :returns: List of open ports on provided host
    '''
    open_ports = deque()  # Deque holding discovered open ports

    # Check whether hostname or IP and whether it exists
    try:
        if any(c.isalpha() for c in host):
            socket.gethostbyname(host)
        else:
            # TODO check for correct IP formatting
            socket.gethostbyaddr(host)

    except (socket.gaierror, socket.herror):
        raise ValueError('%s host does not exist' % (host))

    with ThreadPoolExecutor(max_workers=PORT_SCAN_MAX_WORKERS) as executor:
        # Schedule scans with thread pool
        for port in range(lower_scan_range, (upper_scan_range + 1)):
            executor.submit(__scan, open_ports, host, port)

    return list(open_ports)
