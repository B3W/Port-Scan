'''
Testing module
'''
import portscan
from timeit import default_timer as timer
# import unthreaded_portscan

if __name__ == '__main__':
    # Unthreaded Testing
    # portlist = unthreaded_portscan.unthreaded_port_scan('localhost')
    #
    # print('Open Ports Discovered From Unthreaded Scan:')
    # for port in portlist:
    #     print(port)

    # Threaded Testing
    start = timer()
    portlist = portscan.port_scan('localhost')
    end = timer()

    print('Open Ports Discovered From Scan:')
    for port in portlist:
        print(port)

    print('Elapsed Time: %.6f' % (end - start))
