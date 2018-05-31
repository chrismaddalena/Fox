#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Developer:   Chris "cmaddy" Maddalena
Version:     0.1
Description: Fox is a companion tool for BloodHound. Its intended purpose is to help both
             penetration testers and defenders analyze BloodHound data and better understand
             the target Active Directory environment. The goal is utilizing this data and
             understanding to make decisions, simulate those decisions in BloodHound, and
             then re-run Fox's calculations. The ultimate goal is finding changes that
             are feasible and affect a positive change on security posture and resiliency.
"""

from neo4j.v1 import GraphDatabase
import os
import click
from colors import red, green, yellow
from lib import users, groups, domains, helpers


def setup_database_conn():
    """Function to setup the database connection to the Neo4j project containing the BloodHound
    data.
    """
    try:
        database_uri = helpers.config_section_map("Database")["uri"]
        database_user = helpers.config_section_map("Database")["username"]
        database_pass = helpers.config_section_map("Database")["password"]
        print(yellow("[*] Attempting to connect to your Neo4j project using {}:{} @ {}."
                .format(database_user, database_pass, database_uri)))
        neo4j_driver = GraphDatabase.driver(database_uri, auth=(database_user, database_pass))

        return neo4j_driver
    except Exception:
        neo4j_driver = None
        print(red("[!] Could not create a database connection using the details provided in \
your database.config! Please check the URI, username, and password. lso, make sure your Neo4j \
project is running."))
        exit()


# Setup a class for CLICK
class AliasedGroup(click.Group):
    """Allows commands to be called by their first unique character."""

    def get_command(self, ctx, cmd_name):
        """
        Allows commands to be called by their first unique character
            :param ctx: Context information from click
            :param cmd_name: Calling command name
            :return:
        """
        command = click.Group.get_command(self, ctx, cmd_name)
        if command is not None:
            return command
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail("Too many matches: %s" % ", ".join(sorted(matches)))

# That's right, we support -h and --help! Not using -h for an argument like 'host'! ;D
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)

# Note: The following function descriptors will look weird and some will contain '\n' in spots.
# This is necessary for CLICK. These are displayed with the help info and need to be written
# just like we want them to be displayed in the user's terminal. Whitespace really matters.
def fox():
    """
    Welcome to Fox! Before using Fox, start your Neo4j project containing your
    BloodHound data. Please review the README for details for the modules and queries.\n
    Let's crunch some BloodHound data!\n
    Run 'fox.py <MODULE> --help' for more information on a specific module.
    """
    # Everything starts here
    pass

@fox.command(name='group', short_help="Calculate stats for groups and group membership.")
# Required arguments
# None
# Optional arguments
@click.option('-d', '--domain', help="The Active Directory domain to use for Cypher \
queries.", required=False)
# Pass the above arguments on to your group function
@click.pass_context

def group(self, domain):
    """
    Generate statistics for Active Directory groups, such as average group membership.
    """
    print(green("[+] Group Module Selected: Crunching group membership data..."))
    neo4j_driver = setup_database_conn()
    domain_metrics = domains.DomainData(neo4j_driver)
    group_metrics = groups.GroupMetrics(neo4j_driver)
    users_metrics = users.UserMetrics(neo4j_driver)

    if domain:
        all_domains = [domain]
    else:
        all_domains = domain_metrics.get_all_domains()
    
    for domain in all_domains:
        # We may get a 'None' domain if the label is missing in BloodHound
        if domain:
            print(green("[*] Domain: %s" % domain))

            avg_membership_nonrecur = group_metrics.get_avg_group_membership(domain)
            avg_membership_recur = group_metrics.get_avg_group_membership(domain, True)
            admin_groups = group_metrics.find_admin_groups(domain)
            local_admin = group_metrics.find_local_admin_groups(domain)
            foreign_groups = group_metrics.find_foreign_group_membership(domain)

            print(green("L.. Average group membership:\t\t\t%s" % avg_membership_nonrecur))
            print(green("L.. Average recursive group membership:\t\t%s" % avg_membership_recur))
            print(green("L.. Nested groups increased membership by:\t%s"
                         % float(avg_membership_recur-avg_membership_nonrecur)))
            print(green("L.. Admin groups:"))
            for group in admin_groups:
                print(yellow("\t%s" % group))
            print(green("L.. Non-Admin groups with Local Admin:"))
            for group in local_admin:
                print(yellow("\t%s" % group))
            print(green("L.. Groups with foregin group membership:"))
            for group,foreign_group in foreign_groups.items():
                print(yellow("\t%s -> %s" % (group, foreign_group)))

@fox.command(name='user', short_help="Calculate stats for user and machine accounts.")
# Required arguments
# None
# Optional arguments
@click.option('-d', '--domain', help="The Active Directory domain to use for Cypher \
queries.", required=False)
@click.option('--pass-age', help="Password age (in months) to look for with PwdLastset. Default \
to 6 months.", required=False, type=int, default=6)
# Pass the above arguments on to your user function
@click.pass_context

def user(self, domain, pass_age):
    """
    Generate information and statistics for Active Directory user objects.
    """
    print(green("[+] User Module Selected: Crunching group membership data..."))
    neo4j_driver = setup_database_conn()
    domain_metrics = domains.DomainData(neo4j_driver)
    group_metrics = groups.GroupMetrics(neo4j_driver)
    users_metrics = users.UserMetrics(neo4j_driver)
    super_total_users = 0
    super_total_enabled_users = 0
    super_total_computers = 0

    if domain:
        all_domains = [domain]
    else:
        all_domains = domain_metrics.get_all_domains()
    
    for domain in all_domains:
        # We may get a 'None' domain if the label is missing in BloodHound
        if domain:
            print(green("\n[+] Domain: %s" % domain))
            # Calculations for totals of user objects
            total_users = users_metrics.get_total_users(domain)
            total_enabled_users = users_metrics.get_total_users(domain, True)
            total_computers = users_metrics.get_total_computers(domain)
            super_total_users = super_total_users + total_users
            super_total_enabled_users = super_total_enabled_users + total_enabled_users
            super_total_computers = super_total_computers + total_computers
            # Path to DA calculations
            total_paths = domain_metrics.get_all_da_paths(domain)
            avg_path = domain_metrics.avg_path_length(domain)
            percentage_users_path_to_da = 100.0 * (total_paths/total_users)
            percentage_comps_path_to_da = 100.0 * (total_paths/total_computers)
            # Other statistics and data
            old_passwords = users_metrics.find_old_pwdlastset(domain, pass_age)
            special_users = users_metrics.find_special_users(domain)
            da_spn = users_metrics.find_da_spn(domain)
            foreign_groups = users_metrics.find_foreign_group_membership(domain)

            print(green("L.. Total users:\t\t\t\t%s" % total_users))
            print(green("L.. Total enabled users:\t\t\t%s (%s disabled)"
                         % (total_enabled_users, total_users-total_enabled_users)))
            print(green("L.. Total computers:\t\t\t\t%s" % total_computers))
            print(green("L.. Total paths:\t\t\t\t%s" % total_paths))
            print(green("L.. Average path length:\t\t\t%s" % avg_path))
            print(green("L.. Users with path to a Domain Admin:\t\t%s%%"
                         % percentage_users_path_to_da))
            print(green("L.. Machines with path to Domain Admin:\t\t%s%%"
                         % percentage_comps_path_to_da))
            print(green("L.. Users with passwords older than %s months:\t%s"
                         % (pass_age, len(old_passwords))))
            print(green("L.. Domain Admins tied to SPNs:"))
            for account in da_spn:
                print(yellow("\t%s" % account))
            print(green("L.. Potentially privileged accounts:"))
            for account in special_users:
                print(yellow("\t%s" % account))
            print(green("L.. Users with foregin group membership:"))
            for account,group in foreign_groups.items():
                print(yellow("\t%s -> %s" % (account, group)))

    print(green("\n[*] Total users across domains:\t\t\t%s" % super_total_users))
    print(green("[*] Total enabled users across domains:\t\t%s" % super_total_enabled_users))
    print(green("[*] Total computers across domains:\t\t%s" % super_total_computers))

@fox.command(name='domain', short_help="Present domains in the dataset and their trusts.")
# Required arguments
# None
# Optional arguments
@click.option('-d', '--domain', help="The Active Directory domain to use for Cypher \
queries.", required=False)
# Pass the above arguments on to your domain function
@click.pass_context

def domain(self, domain):
    """
    Generate information and statistics for domains in the dataset.
    """
    print(green("[+] Domain Module Selected: Crunching domain-related data..."))
    neo4j_driver = setup_database_conn()
    domain_metrics = domains.DomainData(neo4j_driver)
    group_metrics = groups.GroupMetrics(neo4j_driver)
    users_metrics = users.UserMetrics(neo4j_driver)

    if domain:
        all_domains = [domain]
    else:
        all_domains = domain_metrics.get_all_domains()
    
    for domain in all_domains:
        # We may get a 'None' domain if the label is missing in BloodHound
        if domain:
            print(green("\n[+] Domain: %s" % domain))

            operating_systems = domain_metrics.get_operating_systems(domain)
            gpo_list = domain_metrics.get_all_gpos(domain)
            da_sessions = domain_metrics.get_systems_with_da(domain)

            print(green("L.. Number of GPOs:\t%s" % len(gpo_list)))
            print(green("L.. Systems that are not Domain Controllers with Domain Admin sessions:"))
            if da_sessions:
                for session in da_sessions:
                    print(yellow("\t%s" % session))
            else:
                print(yellow("\tNone! :D"))
            print(green("L.. Operating Systems seen in domain:"))
            for op_sys,count in operating_systems.items():
                print(yellow("\t%s\t%s" % (count,op_sys)))

if __name__ == "__main__":
    fox()
