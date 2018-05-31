#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for collecting domain data."""

from neo4j.v1 import GraphDatabase
from colors import red, green, yellow
from lib import helpers

class DomainData(object):
    """A class containing functions for getting domain statistics."""

    def __init__(self, driver):
        """Everything that should be initiated with a new object goes here."""
        # Collect the database info from the config file
        self.neo4j_driver = driver

    def get_all_domains(self):
        """Fetch and return distinct domains from the BloodHound data set."""
        query = """
        MATCH (g:Group)
        RETURN DISTINCT g.domain
        """

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        domains = []
        for record in results:
            domains.append(record[0])

        return domains

    def get_all_da_paths(self, domain):
        """Returns the number of paths to a Domain Admin that exist for the given domain."""
        query = """
        MATCH p = shortestPath((pathToDAUsers:User {domain:UPPER('%s')})-[r*1..]-> 
        (g:Group {name:UPPER('DOMAIN ADMINS@%s')}))
        RETURN COUNT(DISTINCT(pathToDAUsers))
        """ % (domain, domain)

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        for record in results:
            return record[0]

    def avg_path_length(self, domain):
        """Returns the average number of hops in a path to a Domain Admin in the given domain."""
        query = """
        MATCH p = shortestPath((n {domain:UPPER('%s')})-[r*1..]->(g:Group {name:'DOMAIN ADMINS@%s'}))
        RETURN toInt(AVG(LENGTH(p))) as avgPathLength
        """ % (domain, domain)

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        for record in results:
            return record[0]

    def get_systems_with_da(self, domain):
        """Returns a list of computers that are not Domain Controllers and have a DOmain Admin
        user logged-in.
        """
        query = """
        MATCH (c2:Computer)-[r3:MemberOf*1..]->(g2:Group {name:UPPER('DOMAIN CONTROLLERS@%s')})
        WITH COLLECT(c2.name) as domainControllers
        MATCH (c1:Computer)-[r1:HasSession]->(u1:User)-[r2:MemberOf*1..]->(g1:Group {name:UPPER('DOMAIN ADMINS@%s')})
        WHERE NOT (c1.name IN domainControllers)
        RETURN DISTINCT(c1.name)
        ORDER BY c1.name ASC
        """ % (domain, domain)

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        computers = []
        for record in results:
            computers.append(record[0])
        
        return computers

    def count_local_admins(self, domain):
        """Discover the number of local admins each computer in the domain has."""
        query = """
        MATCH p = (u1:User)-[r:MemberOf|AdminTo*1..]->(c:Computer)
        RETURN c.name as computerName,COUNT(DISTINCT(u1)) AS adminCount
        ORDER BY adminCount DESC
        """

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        admin_count = {}
        for record in results:
            admin_count[record[0]] = record[1]
        
        return admin_count

    def get_operating_systems(self, domain):
        """Get a list of the opreating systems reported for the given domain's computers."""
        query = """
        MATCH (c:Computer {domain:'%s'})
        WHERE NOT (c.OperatingSystem = "" or c.OperatingSystem is Null)
        RETURN DISTINCT(c.OperatingSystem) as OperartingSystems,COUNT(c.OperatingSystem) as Total
        """ % domain

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        operating_systems = {}
        for record in results:
            operating_systems[record[0]] = record[1]
        
        return operating_systems

    def get_all_gpos(self, domain):
        """Get all GPOs for the given domain."""
        query = """
        MATCH (g:GPO {domain:'%s'})
        WHERE NOT (g.name is Null or g.name = "")
        RETURN g.name
        """ % domain

        with self.neo4j_driver.session() as session:
            results = session.run(query)

        gpos = []
        for record in results:
            gpos.append(record[0])
        
        return gpos