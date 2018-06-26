#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for collecting group membership
statistics.
"""

from neo4j.v1 import GraphDatabase
from colors import red, green, yellow
from lib import helpers

class GroupMetrics(object):
    """A class containing functions for checking group membership data."""

    def __init__(self, driver):
        """Everything that should be initiated with a new object goes here."""
        # Collect the database info from the config file
        self.neo4j_driver = driver

    def get_avg_group_membership(self, domain, recursive=False):
        """Calculate the average number of groups memberships for each user. If the recursive
        flag is set, this function will unroll group memberships to get the total number
        of groups.
        """
        if recursive:
            query = """
            MATCH (u:User {domain: UPPER('%s')})-[r:MemberOf*1..]->(g:Group)
            WITH u.name as userName,COUNT(r) as relCount
            RETURN AVG(relCount)
            """ % domain
        else:
            query = """
            MATCH (u:User {domain: UPPER('%s')})-[r:MemberOf*1]->(g:Group)
            WITH u.name as userName,COUNT(r) as relCount
            RETURN AVG(relCount)
            """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        for record in results:
            return record[0]

    def get_admin_groups(self, domain):
        """Get the Domain Admins, Enterprise Admins, and Administrator group members for the
        given domain.
        """
        da_query = """
        MATCH (n:Group) WHERE n.name =~ 'DOMAIN ADMINS@%s'
        WITH n MATCH (n)<-[r:MemberOf*1..]-(m)
        RETURN m.name,r
        """ % domain

        ea_query = """
        MATCH (n:Group) WHERE n.name =~ 'ENTERPRISE ADMINS@%s'
        WITH n MATCH (n)<-[r:MemberOf*1..]-(m)
        RETURN m.name,r
        """ % domain

        admin_query = """
        MATCH (n:Group) WHERE n.name =~ 'ADMINISTRATORS@%s'
        WITH n MATCH (n)<-[r:MemberOf*1..]-(m)
        RETURN m.name,r
        """ % domain

        da_results = helpers.execute_query(self.neo4j_driver, da_query)
        ea_results = helpers.execute_query(self.neo4j_driver, ea_query)
        admin_results = helpers.execute_query(self.neo4j_driver, admin_query)

        domain_admins = []
        for record in da_results:
            domain_admins.append(record[0])
        
        enterprise_admins = []
        for record in ea_results:
            enterprise_admins.append(record[0])

        admins = []
        for record in admin_results:
            admins.append(record[0])

        return domain_admins, enterprise_admins, admins

    def find_admin_groups(self, domain):
        """Attempt to find interesting groups with ADMIN in their names. The built-in Domain
        Admins, Enterprise Admins, and Administrator accounts are ignored.
        """
        query = """
        MATCH (g:Group {domain:'%s'})
        WHERE g.name =~ '(?i).*ADMIN.*'
        AND NOT ('DOMAIN ADMINS@%s' in g.name)
        AND NOT ('ENTERPRISE ADMINS@%s' in g.name)
        AND NOT ('ADMINISTRATORS@%s' in g.name)
        RETURN g.name
        """ % (domain, domain, domain, domain)

        results = helpers.execute_query(self.neo4j_driver, query)

        groups = []
        for record in results:
            groups.append(record[0])

        return groups

    def find_local_admin_groups(self, domain):
        """Identify groups that are not built-in Admin groups and have Local Administrator
        privileges.
        """
        query = """
        MATCH (g:Group {domain:'%s'})-[:AdminTo*1..]->(c:Computer)
        WHERE NOT ('DOMAIN ADMINS@%s' in g.name)
        AND NOT ('ENTERPRISE ADMINS@%s' in g.name)
        AND NOT ('ADMINISTRATORS@%s' in g.name)
        RETURN DISTINCT(g.name)
        """ % (domain, domain, domain, domain)

        results = helpers.execute_query(self.neo4j_driver, query)

        groups = []
        for record in results:
            groups.append(record[0])

        return groups

    def find_foreign_group_membership(self, domain):
        """Identify groups with foregin group memberships."""
        query = """
        MATCH (n:Group) 
        WHERE n.name ENDS WITH ('@' + '%s') 
        WITH n 
        MATCH (n)-[r:MemberOf*1..]->(m:Group) 
        WHERE NOT m.name ENDS WITH ('@' + '%s') 
        RETURN n.name,m.name
        """ % (domain, domain)

        results = helpers.execute_query(self.neo4j_driver, query)

        groups = {}
        for record in results:
            groups[record[0]] = record[1]

        return groups
    
    def find_remote_desktop_users(self, domain):
        """Identify members of the Remote Desktop Users."""
        query = """
        MATCH (n:Group) WHERE n.name = 'REMOTE DESKTOP USERS@%s'
        WITH n MATCH (n)<-[r:MemberOf*1..]-(m)
        RETURN m.name
        """ % domain

        results = helpers.execute_query(self.neo4j_driver, query)

        members = []
        for member in results:
            members.append(member[0])

        return members