#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for collecting group membership
statistics.
"""

from neo4j.v1 import GraphDatabase
from time import ctime
from datetime import datetime, timedelta, date
from colors import red, green, yellow
from lib import helpers

class UserMetrics(object):
    """A class containing functions for checking group membership data."""

    def __init__(self, driver):
        """Everything that should be initiated with a new object goes here."""
        # Collect the database info from the config file
        self.neo4j_driver = driver

    def get_total_users(self, domain, enabled=False):
        """Returns the total number of users in the given domain. All user accounts are returned
        unless the Enabled flag is set, in which case only accounts with the "Enabled" attribute
        are returned.
        """
        if enabled:
            query = """
            MATCH (totalUsers:User {domain:UPPER('%s')})
            WHERE (totalUsers.Enabled = True)
            RETURN COUNT(DISTINCT(totalUsers))
            """ % domain            
        else:
            query = """
            MATCH (totalUsers:User {domain:UPPER('%s')})
            RETURN COUNT(DISTINCT(totalUsers))
            """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        for record in results:
            return record[0]

    def get_total_computers(self, domain):
        """Returns the total number of computers in the given domain."""
        query = """
        MATCH (totalComputers:Computer {domain:UPPER('%s')})
        RETURN COUNT(DISTINCT(totalComputers))
        """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        for record in results:
            return record[0]

    def find_da_spn(self, domain):
        """Identify Domain Admins linked to SPNs."""
        query = """
        MATCH (u:User {domain:'%s'})-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@%s'})
        WHERE u.HasSPN = True
        RETURN u.name
        """ % (domain, domain)

        results = helpers.execute_query(self.neo4j_driver, query)

        has_spn = []
        for record in results:
            has_spn.append(record[0])

        return has_spn

    def find_unconstrained_delegation(self, domain):
        """Identifies computers with unconstrained delegation enabled on the given domain."""
        query = """
        MATCH (c:Computer {domain:'%s'})
        WHERE c.UnconstrainedDelegation = True
        RETURN c.name
        """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        computers = []
        for record in results:
            computers.append(record[0])

        return computers

    def find_old_pwdlastset(self, domain, months=6):
        """Find active users with PwdLastSet dates older than the specified number of months."""
        months_ago = datetime.today() - timedelta(months*365/12)

        query = """
        MATCH (u:User {domain:'%s'})
        RETURN u.name,u.PwdLastSet
        """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        old_passwords = {}
        for record in results:
            timestamp = record[1]
            if timestamp:
                pwdlastset = datetime.fromtimestamp(timestamp)
                if pwdlastset < months_ago:
                    old_passwords[record[0]] = ctime(timestamp)

        return old_passwords

    def find_special_users(self, domain):
        """Attempt to find user accounts containing common prefixes or suffixes that often
        denote accounts with administrator privileges.
        """
        # TODO: This seems like it could be more efficient
        query = """
        MATCH (u:User {domain:'%s'})
        WHERE u.name STARTS WITH '_' or u.name STARTS WITH '$'
        or u.name =~ '(?i).*ADMIN_.*' or u.name =~ '(?i).*ADMIN-.*'
        or u.name =~ '(?i).*_ADMIN.*' or u.name =~ '(?i).*-ADMIN.*'
        or u.name =~ '(?i).*ADM_.*' or u.name =~ '(?i).*ADM-.*'
        or u.name =~ '(?i).*_ADM.*' or u.name =~ '(?i).*-ADM.*'
        or u.name =~ '(?i).*_A.*' or u.name =~ '(?i).*-A.*'
        or u.name =~ '(?i).*A_.*' or u.name =~ '(?i).*A-.*'
        RETURN u.name
        """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        users = []
        for record in results:
            users.append(record[0])

        return users

    def find_foreign_group_membership(self, domain):
        """Identify users with foregin group memberships."""
        query = """
        MATCH (n:User) 
        WHERE n.name ENDS WITH ('@' + '%s') 
        WITH n 
        MATCH (n)-[r:MemberOf]->(m:Group) 
        WHERE NOT m.name ENDS WITH ('@' + '%s') 
        RETURN n.name,m.name
        """ % (domain, domain)

        results = helpers.execute_query(self.neo4j_driver, query)

        users = {}
        for record in results:
            users[record[0]] = record[1]

        return users
    