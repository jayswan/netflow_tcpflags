import argparse
from itertools import compress

"""
NetFlow collectors typically include a decimal value that represents a bitwise-OR
of the flags that are set in a TCP header across the NetFlow session.
This script translates between those decimal values and their human-readable
equivalents, e.g.:
    19 = ACK SYN FIN

References:
    NetFlow v5:
        http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
    NetFlow v9:
        https://www.ietf.org/rfc/rfc3954.txt (see section 8)

 RFC 3540 defines an experimental ninth TCP flag, "NS", for ECN-nonce
 concealment protection.
 It appears to be rarely if ever used, so we default to excluding it.
 However, the IANA IPFIX entities list standard explicitly lists it, so I include
 an option for it. I don't include any option to decode reserved bits.
 Reference: http://www.iana.org/assignments/ipfix/ipfix.xhtml
"""
rfc_3540_flags = ['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
# short versions:
#rfc_3540_flags = ['N', 'C', 'E', 'U', 'A', 'P', 'R', 'S', 'F']
standard_flags = rfc_3540_flags[1:]

def flags_as_list(decimal_flags,tcpflags):
    """ return a list of the bits in the TCP flags field, given the field as decimal"""
    if len(tcpflags) == 8:
        formatter = '{:08b}'
    else:
        formatter = '{:09b}'
    return [int(n) for n in list(formatter.format(decimal_flags))]

def flags_dict(tcpflags=standard_flags):
    """ generate a dict of all possible numeric to human-readable flag mappings"""
    flags_dict = {}
    for n in xrange(2**len(tcpflags)+1):
        verbose_flags = [i for i in compress(tcpflags,flags_as_list(n,tcpflags))]
        flags_dict[n] = verbose_flags
    return flags_dict

def print_flags(tcpflags=standard_flags):
    """ print the dictionary """
    for k,v in flags_dict(tcpflags).items():
        print k, ' '.join(v)

def main():
    parser = argparse.ArgumentParser(description = "NetFlow TCP Flags")
    parser.add_argument('--rfc3540', action = 'store_true',\
                        help='include RFC3540 NS bit options')
    parser.add_argument('--list', '-l', action = 'store',\
                        help='list a single value')
    args = parser.parse_args()
    if args.list:
        if args.rfc3540:
            print ' '.join(flags_dict(tcpflags=rfc_3540_flags)[int(args.list)])
        else:
            print ' '.join(flags_dict()[int(args.list)])
    elif args.rfc3540:
        print_flags(tcpflags=rfc_3540_flags)
    else:
        print_flags()

if __name__ == '__main__':
    main()
