#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Developer:   Chris "cmaddy" Maddalena
Version:     0.2
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
@click.command(context_settings=CONTEXT_SETTINGS)

# Declare our CLI options
@click.option('-d', '--domain', help="The Active Directory domain to use for Cypher \
queries.", required=False)
@click.option('--pass-age', help="Password age (in months) to look for with PwdLastset. Default \
to 6 months.", required=False, type=int, default=6)

def fox(domain, pass_age):
    """
    Welcome to Fox! Before using Fox, start your Neo4j project containing your
    BloodHound data. Please review the README for details for the modules and queries.\n
    Let's crunch some BloodHound data!
    """
    click.clear()
    print(green("""
  █████▒▒█████  ▒██   ██▒
▓██   ▒▒██▒  ██▒▒▒ █ █ ▒░
▒████ ░▒██░  ██▒░░  █   ░
░▓█▒  ░▒██   ██░ ░ █ █ ▒ 
░▒█░   ░ ████▓▒░▒██▒ ▒██▒
 ▒ ░   ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░
 ░       ░ ▒ ▒░ ░░   ░▒ ░
 ░ ░   ░ ░ ░ ▒   ░    ░  
           ░ ░   ░    ░  
\t\t  v.0.2
    """))

    # Setup the DB connection and metrics objects
    neo4j_driver = helpers.setup_database_conn()
    domain_metrics = domains.DomainData(neo4j_driver)
    group_metrics = groups.GroupMetrics(neo4j_driver)
    users_metrics = users.UserMetrics(neo4j_driver)
    all_domains = helpers.prepare_domains_list(domain_metrics, domain)
    # A few variables we need for tracking some numbers across domains
    super_total_users = 0
    super_total_enabled_users = 0
    super_total_computers = 0
    
    for domain in all_domains:
        # We may get a 'None' domain if the label is missing in BloodHound
        if domain:
            # Neo4j will expect domain names to match what it has in the database, so must be all uppercase
            domain = domain.upper()
            print(green("\n[+] Domain: %s" % domain))

            # Collect session info
            print(green("[+] Collecting session data..."))
            da_sessions = domain_metrics.get_systems_with_da(domain)
            
            # Calculations for group membership
            print(green("[+] Collecting group membership information..."))
            avg_membership_nonrecur = group_metrics.get_avg_group_membership(domain)
            avg_membership_recur = group_metrics.get_avg_group_membership(domain, True)
            dadmins, eadmins, admins = group_metrics.get_admin_groups(domain)
            admin_groups = group_metrics.find_admin_groups(domain)
            local_admin = group_metrics.find_local_admin_groups(domain)
            rdp_users = group_metrics.find_remote_desktop_users(domain)
            foreign_groups = group_metrics.find_foreign_group_membership(domain)
            
            # Collect user object info
            print(green("[+] Collecting user and computer object information..."))
            total_users = users_metrics.get_total_users(domain)
            total_enabled_users = users_metrics.get_total_users(domain, True)
            total_computers = users_metrics.get_total_computers(domain)
            unc_deleg_computers = users_metrics.find_unconstrained_delegation(domain)
            
            # Calculations for user objects
            super_total_users += total_users
            super_total_enabled_users += total_enabled_users
            super_total_computers = super_total_computers + total_computers
            
            # Path to DA calculations
            print(green("[+] Calculating paths to Domain Admin and averages -- this can take \
some time..."))
            total_paths = domain_metrics.get_all_da_paths(domain)
            avg_path = domain_metrics.avg_path_length(domain)
            try:
                percentage_users_path_to_da = 100.0 * (total_paths/total_users)
            except:
                percentage_users_path_to_da = 0
            try:
                percentage_comps_path_to_da = 100.0 * (total_paths/total_computers)
            except:
                percentage_comps_path_to_da = 0

            # Other statistics and data
            print(green("[+] Querying some additional interesting data... nearly done..."))
            gpo_list = domain_metrics.get_all_gpos(domain)
            operating_systems = domain_metrics.get_operating_systems(domain)
            old_passwords = users_metrics.find_old_pwdlastset(domain, pass_age)
            special_users = users_metrics.find_special_users(domain)
            da_spn = users_metrics.find_da_spn(domain)
            foreign_groups = users_metrics.find_foreign_group_membership(domain)
            blocker_ous = domain_metrics.find_blocked_inheritance(domain)

            # Review the data to see if we can detect any missing labels/data and try to name
            # CollectionMethod types that are missing from the database
            warning_count = 0
            print(yellow("\n[!] WARNINGS for %s:" % domain))
            if len(gpo_list) == 0:
                warning_count += 1
                print(yellow("[*] There are zero GPOs for this domain!"))
                print(yellow("L.. Missing CollectionMethod: GPO"))
            if total_enabled_users == 0:
                warning_count += 1
                print(yellow("[*] There are no user objects with the Enabled attribute!"))
                print(yellow("L.. Missing CollectionMethod: ObjectProps"))
            if not operating_systems:
                warning_count += 1
                print(yellow("[*] There are no computer objects with the operating system attribute!"))
                print(yellow("L.. Missing CollectionMethod: ObjectProps"))
            if not avg_membership_nonrecur:
                warning_count += 1
                print(red("[X] Cannot pull group membership data!"))
                print(red("L.. Data for this domain is too incomplete and will be skipped."))
                continue
            if warning_count == 0:
                print(green("\tNone! BloodHound data looks good!\n"))

            # Report domain-related data
            if len(gpo_list) > 0:
                print(green("Number of GPOs:\t%s" % len(gpo_list)))
            if blocker_ous:
                print(green("OUs blockiung inheritance:"))
                for ou in blocker_ous:
                    print(yellow("\t%s" % ou))
            if operating_systems:
                print(green("Operating Systems seen in domain:"))
                for key, value in operating_systems.items():
                    print(yellow("\t%s\t%s" % (value, key)))
            print(green("Domain Admins tied to SPNs:"))
            if len(da_spn):
                for account in da_spn:
                    print(yellow("\t%s" % account))
            else:
                print(green("\tNone! :D"))

            # Report session data
            print(green("Systems that are not Domain Controllers with Domain Admin sessions:"))
            if da_sessions:
                for session in da_sessions:
                    print(yellow("\t%s" % session))
            else:
                print(green("\tNone! :D"))

            # Report group-related data
            print(green("Average group membership:\t\t\t%s" % avg_membership_nonrecur))
            print(green("Average recursive group membership:\t\t%s" % avg_membership_recur))
            print(green("Nested groups increased membership by:\t\t%s"
                         % float(avg_membership_recur-avg_membership_nonrecur)))
            print(green("Domain Admins:"))
            for user in dadmins:
                print(yellow("\t%s" % user))
            print(green("Enterprise Admins:"))
            for user in eadmins:
                print(yellow("\t%s" % user))
            print(green("Administrators:"))
            for user in admins:
                print(yellow("\t%s" % user))
            print(green("Other ADMIN groups:"))
            for group in admin_groups:
                print(yellow("\t%s" % group))
            print(green("Non-Admin groups with Local Admin:"))
            if local_admin:
                for group in local_admin:
                    print(yellow("\t%s" % group))
            else:
                print(green("\tNone! :D"))
            print(green("REMOTE DESKTOP USERS members:"))
            for member in rdp_users:
                if "DOMAIN USERS" in member:
                    print(red("\t--> %s" % member))
                else:
                    print(yellow("\t%s" % member))
            if foreign_groups:
                print(green("Groups with foregin group membership:"))
                for group,foreign_group in foreign_groups.items():
                    print(yellow("\t%s -> %s" % (group, foreign_group)))

            # Report user statistics
            print(green("Total users:\t\t\t\t\t%s" % total_users))
            print(green("Total enabled users:\t\t\t\t%s (%s disabled)"
                         % (total_enabled_users, total_users-total_enabled_users)))
            print(green("Users with passwords older than %s months:\t%s"
                         % (pass_age, len(old_passwords))))
            print(green("Total computers:\t\t\t\t%s" % total_computers))
            print(green("Potentially privileged accounts:"))
            for account in special_users:
                print(yellow("\t%s" % account))
            print(green("Users with foregin group membership:"))
            if foreign_groups:
                for account,group in foreign_groups.items():
                    print(yellow("\t%s -> %s" % (account, group)))
            else:
                print(green("\tNone!"))

            # Report on computer objects
            print(green("Computers with Unconstrained Delegation:"))
            if unc_deleg_computers:
                for computer in unc_deleg_computers:
                    print(yellow("\t%s" % computer))
            else:
                print(green("\tNone! :D"))

            # Report on paths
            print(green("Total paths:\t\t\t\t\t%s" % total_paths))
            print(green("Average path length:\t\t\t\t%s" % avg_path))
            print(green("Users with path to a Domain Admin:\t\t%s %%"
                         % percentage_users_path_to_da))
            print(green("Machines with path to Domain Admin:\t\t%s %%"
                         % percentage_comps_path_to_da))

    # Report totals across domains
    print(green("\n[+] Totals for all domains in dataset:"))
    print(green("Total users across domains:\t\t\t%s" % super_total_users))
    print(green("Total enabled users across domains:\t\t%s" % super_total_enabled_users))
    print(green("Total computers across domains:\t\t\t%s" % super_total_computers))


if __name__ == "__main__":
    fox()
