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
    start_port = 400
    end_port = 1000

    start = timer()

    portlist = portscan.execute('localhost', start_port, end_port)

    end = timer()

    print('Open Ports Discovered From Scan:')
    for port in portlist:
        print(port)

    print('Elapsed Time: %.6f' % (end - start))
