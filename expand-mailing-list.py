#!/usr/bin/env python

import os
import sys
import string
import ldap
import logging
import getpass
from argparse import ArgumentParser

def search_for_ddlists(ldap_conn, dn):
    return ldap_conn.search_s(dn,
                              ldap.SCOPE_BASE,
                              filterstr='(objectclass=msExchDynamicDistributionList)',
                              attrlist=['msExchDynamicDLBaseDN',
                                        'msExchDynamicDLFilter'])

def search_ddlist(ldap_conn, list_attrs):
    dyn_base_dn = list_attrs['msExchDynamicDLBaseDN'][0]
    dyn_filter = list_attrs['msExchDynamicDLFilter'][0]
    return ldap_conn.search_s(dyn_base_dn,
                              ldap.SCOPE_SUBTREE,
                              filterstr=dyn_filter,
                              attrlist=[])

# Find DNs that are of objecttype msExchDynamicDistributionList,
# get their filters, and expand them to more DNs
def expand_dyn_list(ldap_conn, dn_list):
    expanded_dns = []
    for base_dn in dn_list:
        results = search_for_ddlists(ldap_conn, base_dn)
        if results == None or len(results) == 0:
            #print '{} is not a mailing list, append'.format(base_dn)
            expanded_dns.append(base_dn)
        else:
            #print '{} is a mailing list, results: {}'.format(base_dn, results)
            for _, attrs in results:
                results = search_ddlist(ldap_conn, attrs)
                if results != None and len(results) > 0:
                    # Recursive call to expand any other mailing lists
                    expanded_dns.extend(expand_dyn_list(ldap_conn, [dn for dn, _ in results]))
                else:
                    #print 'No people in DN {} matching filter {}'.format(dyn_base_dn, dyn_filter)
                    pass
    return expanded_dns

def run(args):
    ldap_opts = {
        ldap.OPT_PROTOCOL_VERSION: 3,
        ldap.OPT_REFERRALS: 1 # Yes, chase referrals
        }

    ldap_conn = ldap.initialize(args.ldap_uri, trace_level=args.trace_level)

    for opt, val in ldap_opts.items():
        ldap_conn.set_option(opt, val)

    ldap_conn.simple_bind_s(args.bind_dn, args.password)
    base_dn = args.mailing_list_dn
    #print 'Searching {}'.format(base_dn)

    try:
        results = ldap_conn.search_s(base_dn,
                                     ldap.SCOPE_BASE,
                                     filterstr='(objectclass=group)',
                                     attrlist=['member'])
    except Exception as exc:
        print 'Search exception: {}'.format(exc)
        sys.exit(1)

    dns = []

    if results != None and len(results) > 0:
        for _, attrs in results:
            members = attrs['member']
            #print 'Members: {}'.format(members)
            dns.extend(expand_dyn_list(ldap_conn, members))

        for dn in sorted(set(dns)):
            result = ldap_conn.search_s(dn,
                                        ldap.SCOPE_SUBTREE,
                                        attrlist=['cn'])

            if result != None:
                (_, attrs) = result[0]
                print attrs['cn'][0]
            else:
                print 'DN {} not found'.format(dn)
    else:
        print 'No results returned'


def parse_args():
    argp = ArgumentParser()

    # Output verbosity options.
    argp.add_argument('-q', '--quiet', help='No tracing (default)',
                      action='store_const', dest='trace_level',
                      const=0, default=0)
    argp.add_argument('-d', '--debug', help='Trace method calls with arguments',
                      action='store_const', dest='trace_level',
                      const=1, default=0)
    argp.add_argument('-v', '--verbose', help='Trace method calls with arguments and results',
                      action='store_const', dest='trace_level',
                      const=2, default=0)
    argp.add_argument('-9', '--very-verbose', help='Trace method maxmimum level',
                      action='store_const', dest='trace_level',
                      const=9, default=0)

    argp.add_argument('-D', '--bind-dn', dest='bind_dn',
                      help='LDAP bind DN (e.g. john@example.com)')

    argp.add_argument('-w', '--password', dest='password',
                      help='LDAP bind password')

    argp.add_argument('-H', '--ldap-uri', dest='ldap_uri',
                      help='LDAP URI to use (e.g. ldaps://ad.example.com)')

    argp.add_argument('-M', '--mailing-list-dn',
                      dest='mailing_list_dn',
                      help='DN of the mailing list (e.g. CN=Example List,CN=Users,DC=example,DC=com)')

    return argp.parse_args()



if __name__ == '__main__':

    args = parse_args()

    if args.bind_dn is None:
        args.bind_dn = raw_input("Bind DN: ")

    if args.password is None:
        args.password = getpass.getpass("LDAP password: ")

    if args.ldap_uri is None:
        args.ldap_uri = raw_input("LDAP URI: ")

    if args.mailing_list_dn is None:
        args.mailing_list_dn = raw_input("Mailing list DN: ")

    run(args)

# vim: ts=4 sts=4 sw=4 et si:
