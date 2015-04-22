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

def search_for_groups(ldap_conn, dn):
    return ldap_conn.search_s(dn,
                              ldap.SCOPE_BASE,
                              filterstr='(objectclass=group)',
                              attrlist=['member'])

def expand_group(ldap_conn, dn):
    #print 'Expanding group {}'.format(dn)
    dns = []
    results = search_for_groups(ldap_conn, dn)
    if results != None:
        for _, attrs in results:
            if attrs['member'] != None:
                for member in attrs['member']:
                    dns.extend(expand_dn(ldap_conn,member))
    return dns

def expand_ddlist(ldap_conn, dn):
    #print 'Expanding ddlist {}'.format(dn)
    dns = []
    results = search_for_ddlists(ldap_conn, dn)
    if results != None:
        for _, attrs in results:
            results = search_ddlist(ldap_conn, attrs)
            if results != None:
                for dn, _ in results:
                    dns.extend(expand_dn(ldap_conn, dn))
    return dns

def expand_dn(ldap_conn, dn):
    #print 'Expanding dn {}'.format(dn)
    dns = []
    results = ldap_conn.search_s(dn, ldap.SCOPE_BASE, attrlist=['objectclass'])
    if results != None:
        for _, attrs in results:
            cs = attrs['objectClass']
            if 'group' in cs:
                dns.extend(expand_group(ldap_conn, dn))
            elif 'msExchDynamicDistributionList' in cs:
                dns.extend(expand_ddlist(ldap_conn, dn))
            else:
                dns.append(dn)
    return dns

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

    dns = expand_dn(ldap_conn, base_dn)

    if dns != None and len(dns) > 0:
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
