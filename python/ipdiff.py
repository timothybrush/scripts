#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Permission to copy and modify is granted under the bsd license

DESCRIPTION: Compares two list of IPs

AUTHOR: Timothy Brush

NOTES:
  -  Output is sorted numerically
  -  CIDR notation loads much faster when using netaddr IP sets.
"""

__title__ = "ipdiff.py"
__version__ = "1.0"
__author__ = "Timothy Brush"
__license__ = "BSD"

import logging
import argparse
import sys
import re
#import fileinput
#from pprint import pprint as pp

# Third party module
from netaddr import IPAddress, IPRange, IPSet

logging.basicConfig(level=logging.WARN, format='%(message)s')


def ipv4_addresses(lines):
    """ Checks if line contains IPv4 Addresses """
    # IPv4 - this doesn't handle %interface formats
    ip4_regex = (r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3,3}"
                 "(25[0-5]|(2[0-4]|1?[0-9])?[0-9])")
    ip4_cidr = "(3[0-2]|[12]?[0-9])"

    ip4_match = "^{}(/{})?$".format(ip4_regex, ip4_cidr)
    ip4_range = r"^{}\s*-\s*{}$".format(ip4_regex, ip4_regex)

    # Compile regexes increases speed
    match_ip4_cidr = re.compile(ip4_match)
    match_ip4_range = re.compile(ip4_range)

    ip_set = IPSet()
    remaining = []
    for line in lines:
        line = line.strip()

        try:
            if match_ip4_cidr.match(line):
                logging.info('IPv4 match: %s', line)
                ip_set.add(line)
            elif match_ip4_range.match(line):
                logging.info('IPv4 range: %s', line)
                start, finish = line.split("-")
                start = IPAddress(start.strip())
                finish = IPAddress(finish.strip())

                if start < finish:
                    ip_set.add(IPRange(start, finish))
                else:
                    logging.warning('IPv4 range: %s (beginning of range '
                                    'larger than end of range', line)
                    ip_set.add(IPRange(finish, start))
            else:
                remaining.append(line)
        except (RuntimeError, TypeError, NameError):
            logging.debug('Invalid IPv4 addresses: %s', line)
            remaining.append(line)

    return ip_set, remaining


def ipv6_addresses(lines):
    """ Checks if line contains IPv6 Addresses """
    # IPv6 - this doesn't handle %interface formats
    ip6_regex = ("(([0-9a-fA-F]{1,4}:){7,7}([0-9a-fA-F]{1,4})|"
                 "([0-9a-fA-F]{1,4}:){1,7}:|"
                 "([0-9a-fA-F]{1,4}:){1,6}(:[0-9a-fA-F]{1,4})|"
                 "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                 "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                 "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                 "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                 "([0-9a-fA-F]{1,4}:){1,1}(:[0-9a-fA-F]{1,4}){1,6}|"
                 ":(:[0-9a-fA-F]{1,4}){1,7})|([0-9a-fA-F]{1,4}:){1,4}:"
                 r"((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3,3}"
                 "(25[0-5]|(2[0-4]|1?[0-9])?[0-9])")
    ip6_cidr = "(12[0-8]|(1[01]|[0-9])?[0-9])"

    ip6_match = "^{}(/{})?$".format(ip6_regex, ip6_cidr)
    ip6_range = r"^{}\s*-\s*{}$".format(ip6_regex, ip6_regex)

    # Compile regexes increases speed
    match_ip6_cidr = re.compile(ip6_match)
    match_ip6_range = re.compile(ip6_range)

    ip_set = IPSet()
    remaining = []
    for line in lines:
        line = line.strip()

        try:
            if match_ip6_cidr.match(line):
                logging.info('IPv6 match: %s', line)
                ip_set.add(line)

            elif match_ip6_range.match(line):
                logging.info('IPv6 range: %s', line)
                start, finish = line.split("-")
                start = IPAddress(start.strip())
                finish = IPAddress(finish.strip())

                if start < finish:
                    ip_set.add(IPRange(start, finish))
                else:
                    logging.warning('IPv4 range: %s (beginning of range '
                                    'larger than end of range', line)
                    ip_set.add(IPRange(finish, start))
            else:
                logging.info('Unmatched: %s', line)
                remaining.append(line)
        except (RuntimeError, TypeError, NameError):
            logging.debug('Invalid IPv6 addresses: %s', line)
            remaining.append(line)

    return ip_set, remaining


def build_ipset(lines):
    """ Build IP Set from list. """
    ipv4_set, remaining = ipv4_addresses(lines)
    ipv6_set, remaining = ipv6_addresses(remaining)

    if remaining:
        logging.debug('\nUnmatched lines:\n  %s\n', '\n  '.join(remaining))

    return ipv4_set | ipv6_set


def print_ips(ipset):
    """ Outputs each IP to STDOUT """
    for cidr in ipset.iter_cidrs():
        print('{}'.format(cidr))


def parse_args():
    """Command line parsing for this utility."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Compares two IP lists identifying overlapping and unique "
                    "IP Networks.  Output uses CIDR notation.")

    parser.add_argument("-V", "--version", action="version",
                        version="%(prog)s {}".format(__version__))

    optional = parser.add_mutually_exclusive_group(required=False)
    optional.add_argument("-v", "--verbose", action="store_true",
                          help="enable verbose output.")
    optional.add_argument("-d", "--debug", action="store_true",
                          help="enable debugging output.\n\n")

    required = parser.add_mutually_exclusive_group(required=True)
    required.add_argument("-1", "--first", action="store_true",
                          help="output list of IPs unique to first file.")
    required.add_argument("-2", "--second", action="store_true",
                          help="output list of IPs unique to second file.")
    required.add_argument("-b", "--both", action="store_true",
                          help="output list of IPs common to both files.")
    required.add_argument("-m", "--merge", action="store_true",
                          help="output list of all IPs in both files.\n\n")

    parser.add_argument("file_1", metavar="file_1",
                        help="first file to compare.")
    parser.add_argument("file_2", metavar="file_2",
                        help="second file to compare.")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    return args


def main():
    """
    Compares two IP lists identifying overlapping and unique IP Addresses &
    IP Networks.  Output uses CIDR notation.
    """
    args = parse_args()

    # Build IP Set from first file
    logging.debug('Processing: %s', args.file_1)
    with open(args.file_1, 'rt') as file:
        lines = [l.strip() for l in file if not re.match('^(#|$)', l.strip())]
        ipset1 = build_ipset(lines)

    # Build IP Set from second file
    logging.debug('Processing: %s', args.file_2)
    with open(args.file_2, 'rt') as file:
        lines = [l.strip() for l in file if not re.match('^(#|$)', l.strip())]
        ipset2 = build_ipset(lines)

    if args.first:
        logging.debug('IPs unique to %s:', args.file_1)
        print_ips(ipset1 - ipset2)
    elif args.second:
        logging.debug('IPs unique to %s:', args.file_2)
        print_ips(ipset2 - ipset1)
    elif args.both:
        logging.debug('Common IP CIDRs to %s and %s:', args.file_1, args.file_2)
        print_ips(ipset1 & ipset2)
    elif args.merge:
        logging.debug('All IP CIDRs in %s and %s:', args.file_1, args.file_2)
        print_ips(ipset1 | ipset2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
