#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions that are shared across different custom libraries.
"""

import sys
import configparser
from neo4j.v1 import GraphDatabase
from colors import red, yellow, green


def config_section_map(section):
    """Function to read a config file section and return a dictionary object that can be
    referenced for configuration settings.
    """
    try:
        config_parser = configparser.ConfigParser()
        config_parser.read("database.config")
    except configparser.Error as error:
        print(red("[X] Could not open the database.config file -- make sure it exists and is readable."))
        print(red("L.. Details: {}".format(error)))
        exit()

    try:
        section_dict = {}
        # Parse the config file's sections into options
        options = config_parser.options(section)
        # Loop through each option
        for option in options:
            # Get the section and option and add it to the dictionary
            section_dict[option] = config_parser.get(section, option)
            if section_dict[option] == -1:
                print("[X] Skipping: {}".format(option))

        # Return the dictionary of settings and values
        return section_dict
    except configparser.Error as error:
        print(red("[X] There was an error with: {}".format(section)))
        print(red("L.. Details: {}".format(error)))


def setup_database_conn():
    """Function to setup the database connection to the Neo4j project containing the BloodHound
    data.
    """
    try:
        database_uri = config_section_map("Database")["uri"]
        database_user = config_section_map("Database")["username"]
        database_pass = config_section_map("Database")["password"]
        print(yellow("[!] Attempting to connect to your Neo4j project using {}:{} @ {}."
                .format(database_user, database_pass, database_uri)))
        neo4j_driver = GraphDatabase.driver(database_uri, auth=(database_user, database_pass))
        print(green("[+] Success!"))
        return neo4j_driver
    except Exception:
        neo4j_driver = None
        print(red("[X] Could not create a database connection using the details provided in \
your database.config! Please check the URI, username, and password. Also, make sure your Neo4j \
project is running. Note that the bolt port can change sometimes."))
        exit()


def prepare_domains_list(domain_metrics_obj, domain=None):
    """Function to prepare the list of domains to be enumerated. If a domain is provided, it will
    check if BloodHound has data for that domain. If no domain is provided, it will create a list
    of all domains in BloodHound for which data is available. A list of known domains missing data
    is produced as well.
    """
    if domain:
        all_domains = [domain]

        domain_check = domain_metrics_obj.get_all_domains()
        if not domain in domain_check:
            print(red("[X] No data is available for the specified domain!"))
            exit()
    else:
        all_domains = domain_metrics_obj.get_all_domains()
        all_domains_inc = domain_metrics_obj.get_all_domains(True)

        for domain in all_domains_inc:
            missing_data = []
            if not domain in all_domains:
                missing_data.append(domain)

        if missing_data:
            print(yellow("[!] The following domains were found in the dataset, but we don't have any \
    data for them! Run BloodHound on these domains:"))
            for domain in missing_data:
                print(yellow("\t* %s" % domain))

    return all_domains


def execute_query(driver, query):
    """Execute the provided query using the current Neo4j database connection."""
    with driver.session() as session:
        results = session.run(query)

    return results
