"""ec2-security-groups-dumper

Dumps the EC2 firewall rules as a json or csv output. Redirect the output to a
file to dump it to this file.
Useful to keep track of the firewall changes in git.
Can also be used as a backup in case you lose some rules on EC2.

Usage:
    ec2-security-groups-dumper (--json | --csv) [options]
    ec2-security-groups-dumper (-h | --help)

Options:
  -h --help                 Show this screen.
  --region=<region>         Set an AWS region
  --profile=<profile>       Set an AWS/Boto CLI profile
  --vpc=<vpc>               Set a VPC ID to filter by

Examples:
    ec2-security-groups-dumper --csv > path/to/ec2-security-groups.csv
    ec2-security-groups-dumper --json > path/to/your-firewall-backup.json

"""
import boto
import boto.ec2
import json
import csv
from docopt import docopt
import StringIO
from types import NoneType, StringType


class FirewallRule(object):

    def __init__(self,
                 id,
                 name,
                 description,
                 rules_ip_protocol=None,
                 rules_from_port=None,
                 rules_to_port=None,
                 rules_grants_group_id=None,
                 rules_grants_name=None,
                 rules_grants_cidr_ip=None):
        """
        Args:
            - id (unicode)
            - name (unicode)
            - description (unicode)
            - rules_ip_protocol (unicode)
            - rules_from_port (unicode)
            - rules_to_port (unicode)
            - rules_grants_group_id (unicode)
            - rules_grants_name (unicode)
            - rules_grants_cidr_ip (unicode)
        """
        assert isinstance(id, unicode), "Invalid id: {}".format(id)
        assert isinstance(name, unicode)
        assert isinstance(description, unicode)
        assert rules_ip_protocol in (u'tcp', u'udp', u'icmp', "-1", None)
        assert isinstance(rules_from_port, (unicode, NoneType))
        assert isinstance(rules_to_port, (unicode, NoneType))
        assert isinstance(rules_grants_group_id, (unicode, NoneType))
        assert isinstance(rules_grants_name, (unicode, NoneType))
        assert isinstance(rules_grants_cidr_ip, (unicode, NoneType))

        self.id = id
        self.name = name
        self.description = description
        self.rules_ip_protocol = rules_ip_protocol
        self.rules_from_port = rules_from_port
        self.rules_to_port = rules_to_port
        self.rules_grants_group_id = rules_grants_group_id
        self.rules_grants_name = rules_grants_name
        self.rules_grants_cidr_ip = rules_grants_cidr_ip

    def as_dict(self):
        """
        Returns:
            dict
        """
        dict_fw = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'rules_ip_protocol': self.rules_ip_protocol,
            'rules_from_port': self.rules_from_port,
            'rules_to_port': self.rules_to_port,
            'rules_grants_group_id': self.rules_grants_group_id,
            'rules_grants_name': self.rules_grants_name,
            'rules_grants_cidr_ip': self.rules_grants_cidr_ip
        }

        return dict_fw


class Firewall(object):

    def __init__(self, region=None, profile=None, vpc=None):
        """Create a Firewall Object

        Keyword arguments:
        region -- the AWS region to be queried
        profile --  the AWS profile to use
        vpc -- the AWS VPC to filter by
        """
        self.region = region
        self.profile = profile
        self.filters = {}
        if vpc is not None:
            self.filters['vpc_id'] = [vpc]
        self.dict_rules = self._get_rules_from_aws()

        assert type(region) is StringType or NoneType, \
            "The region must be a string."
        assert type(profile) is StringType or NoneType, \
            "The profile must be a string."
        assert type(vpc) is StringType or NoneType, "The vpc must be a string."

    @property
    def json(self):
        """
        Output the security rules as a json string.

        Return:
            str
        """
        return json.dumps(self.dict_rules,
                          sort_keys=True,
                          indent=2,
                          separators=(',', ': '))

    @property
    def rules(self):
        """
        Returns a sorted list of firewall rules.

        Returns:
            list
        """
        list_of_rules = []

        for main_row in self.dict_rules:
            if 'rules' in main_row:
                for rule_row in main_row['rules']:
                    if 'grants' in rule_row:
                        for grant_row in rule_row['grants']:
                            if 'group_id' in grant_row:
                                # Set a var to not go over 80 chars
                                group_id = grant_row['group_id']

                                # Some VPC grants don't specify a name
                                if 'name' in grant_row:
                                    row_name = grant_row['name']
                                else:
                                    row_name = None

                                # Some VPC grants specify -1 instead for the
                                # ip_protocol instead of not declaring it
                                if rule_row['ip_protocol'] == u'-1':
                                    row_ip_protocol = None
                                else:
                                    row_ip_protocol = rule_row['ip_protocol']

                                fr = FirewallRule(
                                    main_row['id'],
                                    main_row['name'],
                                    main_row['description'],
                                    rules_ip_protocol=row_ip_protocol,
                                    rules_from_port=rule_row['from_port'],
                                    rules_to_port=rule_row['to_port'],
                                    rules_grants_group_id=group_id,
                                    rules_grants_name=row_name)
                                list_of_rules.append(fr)
                            elif 'cidr_ip' in grant_row:
                                fr = FirewallRule(
                                    main_row['id'],
                                    main_row['name'],
                                    main_row['description'],
                                    rules_ip_protocol=rule_row['ip_protocol'],
                                    rules_from_port=rule_row['from_port'],
                                    rules_to_port=rule_row['to_port'],
                                    rules_grants_cidr_ip=grant_row['cidr_ip'])
                                list_of_rules.append(fr)
                            else:
                                raise ValueError("Unsupported grant:",
                                                 grant_row)
                    else:
                        fr = FirewallRule(
                            main_row['id'],
                            main_row['name'],
                            main_row['description'],
                            rules_ip_protocol=rule_row['ip_protocol'],
                            rules_from_port=rule_row['from_port'],
                            rules_to_port=rule_row['to_port'])
                        list_of_rules.append(fr)
            else:
                fr = FirewallRule(main_row['id'],
                                  main_row['name'],
                                  main_row['description'])
                list_of_rules.append(fr)

        # Sort the data in order to get a consistent output
        sorted_list = sorted(list_of_rules,
                             key=lambda fr: (fr.id,
                                             fr.name,
                                             fr.description,
                                             fr.rules_ip_protocol,
                                             fr.rules_from_port,
                                             fr.rules_to_port,
                                             fr.rules_grants_group_id,
                                             fr.rules_grants_name,
                                             fr.rules_grants_cidr_ip))

        return sorted_list

    @property
    def csv(self):
        """
        Returns the security rules as a CSV.

        CSV format:
        - id
        - name
        - description
        - rules_ip_protocol
        - rules_from_port
        - rules_to_port
        - rules_grants_group_id
        - rules_grants_name
        - rules_grants_cidr_ip

        Returns:
            str
        """
        # Generate a csv file in memory with all the data in
        output = StringIO.StringIO()
        fieldnames = ['id',
                      'name',
                      'description',
                      'rules_ip_protocol',
                      'rules_from_port',
                      'rules_to_port',
                      'rules_grants_group_id',
                      'rules_grants_name',
                      'rules_grants_cidr_ip']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for fr in self.rules:
            writer.writerow(fr.as_dict())

        # Get the CSV in a string
        csv_content = output.getvalue()

        # Removing some useless newline at the end
        stripped_csv_content = csv_content.strip()

        return stripped_csv_content

    def _get_rules_from_aws(self):
        """
        Load the EC2 security rules off AWS into a list of dict.

        Returns:
            list
        """
        list_of_rules = list()

        if self.region:
            conn = boto.ec2.connect_to_region(region_name=self.region,
                                              profile_name=self.profile)
        else:
            conn = boto.connect_ec2(profile_name=self.profile)
        security_groups = conn.get_all_security_groups(filters=self.filters)
        for group in security_groups:
            group_dict = dict()
            group_dict['id'] = group.id
            group_dict['name'] = group.name
            if group.description:
                group_dict['description'] = group.description

            if group.rules:
                group_dict['rules'] = list()

            for rule in group.rules:
                rule_dict = dict()
                rule_dict['ip_protocol'] = rule.ip_protocol
                rule_dict['from_port'] = rule.from_port
                rule_dict['to_port'] = rule.to_port

                if rule.grants:
                    rule_dict['grants'] = list()

                for grant in rule.grants:
                    grant_dict = dict()
                    if grant.name:
                        grant_dict['name'] = grant.name
                    if grant.group_id:
                        grant_dict['group_id'] = grant.group_id
                    if grant.cidr_ip:
                        grant_dict['cidr_ip'] = grant.cidr_ip

                    rule_dict['grants'].append(grant_dict)

                group_dict['rules'].append(rule_dict)

            list_of_rules.append(group_dict)

        return list_of_rules


def main():
    arguments = docopt(__doc__)

    if '--region' in arguments:
        region = arguments['--region']
    else:
        region = None

    if '--profile' in arguments:
        profile = arguments['--profile']
    else:
        profile = None

    if '--vpc' in arguments:
        vpc = arguments['--vpc']
    else:
        vpc = None

    firewall = Firewall(region=region, profile=profile, vpc=vpc)

    if arguments['--json']:
        print firewall.json
    elif arguments['--csv']:
        print firewall.csv


if __name__ == '__main__':
    main()
