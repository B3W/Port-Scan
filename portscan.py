'''
Module providing functionality for scanning host for open TCP ports
'''
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import socket


PORT_SCAN_MAX_WORKERS = 1000    # How many workers can spawn for port scanning
PORT_SCAN_LOWER_RANGE = 1       # Where to start port scanning
PORT_SCAN_UPPER_RANGE = 1024    # Where to end port scanning
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


def port_scan(host):
    '''
    Conducts a port scan of the provided host

    :param host: Host name or IP of host to conduct port scan.
                 IP shall be formatted 'xxx.xxx.xxx.xxx'.
    :returns: list of open ports on provided host
    '''
    open_ports = deque()

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
        for port in range(PORT_SCAN_LOWER_RANGE, (PORT_SCAN_UPPER_RANGE + 1)):
            executor.submit(__scan, open_ports, host, port)

    # Wait for executor to complete
    executor.shutdown(wait=True)

    return open_ports
