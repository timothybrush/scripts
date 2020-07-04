#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Permission to copy and modify is granted under the bsd license

DESCRIPTION: Convert a list of IPs between individual IPs, IP ranges, and
             CIDR Notation.

AUTHOR: Timothy Brush

NOTES:
  -  Output is sorted numerically
  -  CIDR notation loads much faster if using netaddr IP sets.
"""

__title__ = "ipconv.py"
__version__ = "1.0"
__author__ = "Timothy Brush"
__license__ = "BSD"

import logging
import argparse
import sys
import re
import fileinput

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
    remaining = []
    ipv4_set, remaining = ipv4_addresses(lines)
    ipv6_set, remaining = ipv6_addresses(remaining)

    if remaining:
        logging.debug('\nUnmatched lines:\n  %s\n', '\n  '.join(remaining))

    return ipv4_set | ipv6_set


def print_cidrs(ipset):
    """ Outputs IPs using CIDR notation to STDOUT """
    for cidr in ipset.iter_cidrs():
        print('{}'.format(cidr))


def print_ranges(ipset, supress):
    """ Outputs beginning and end of IP networks to STDOUT """
    for cidr in ipset.iter_cidrs():
        if supress and (cidr[0] == cidr[-1]):
            print('{}'.format(cidr[0]))
        else:
            print('{}\t{}'.format(cidr[0], cidr[-1]))


def print_ips(ipset):
    """ Outputs each IP to STDOUT """
    for cidr in ipset.iter_cidrs():
        try:
            # Protect from listing HUGE networks
            if len(cidr) < 250000:
                for ip_address in list(cidr):
                    print('{}'.format(ip_address))
            else:
                raise IndexError
        except IndexError:
            print('Too many ips - {}'.format(str(cidr)))


def parse_args():
    """ Command line parsing for this utility. """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Convert between a list of individual IPs, IP ranges, "
                    "and CIDR notation.")

    parser.add_argument("-V", "--version", action="version",
                        version="%(prog)s {}".format(__version__))

    optional = parser.add_mutually_exclusive_group(required=False)
    optional.add_argument("-v", "--verbose", action="store_true",
                          help="enable verbose output.")
    optional.add_argument("-d", "--debug", action="store_true",
                          help="enable debugging output.\n\n")

    required = parser.add_mutually_exclusive_group(required=True)
    required.add_argument("-c", "--cidr", action="store_true",
                          help="output list of IPs in CIDR notation.")
    required.add_argument("-i", "--individual", action="store_true",
                          help="output each IP on a separate line.")
    required.add_argument("-r", "--range", action="store_true",
                          help="output ranges of IPs.")

    parser.add_argument("-s", "--supress", action="store_true",
                        help="don't print second column if single IP.\n\n")
    parser.add_argument("files", metavar="files", nargs='*',
                        help="files to read - if empty, STDIN is used.")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    return args


def main():
    """
    Convert a list of IPs provided between individual IPs, IP ranges, and CIDR
    notation.  List can be input via STDIN or list of filenames. Verbose or
    Debug messages are output to STDERR.
    """
    args = parse_args()

    # If you would call fileinput.input() without files it would try to
    # process all arguments. We pass '-' as only file when argparse got no
    # files which will cause fileinput to read from stdin
    files = args.files if args.files else ('-',)

    lines = []
    for line in fileinput.input(files):
        # Ignore comments and empty lines
        if not re.match('^(#|$)', line.strip()):
            lines.append(line.strip())

    # Build our IP Sets from file contents
    ipset = build_ipset(lines)

    if args.cidr:
        print_cidrs(ipset)
    elif args.range:
        print_ranges(ipset, args.supress)
    else:
        print_ips(ipset)

    return 0


if __name__ == "__main__":
    sys.exit(main())
