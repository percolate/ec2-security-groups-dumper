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
import boto3
import json
import csv
from docopt import docopt
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class FirewallRule(object):

    def __init__(self,
                 id,
                 name,
                 description,
                 rules_direction=None,
                 rules_ip_protocol=None,
                 rules_from_port=None,
                 rules_to_port=None,
                 rules_grants_group_id=None,
                 rules_grants_name=None,
                 rules_grants_cidr_ip=None,
                 rules_description=None):
        """
        Args:
            - id (str)
            - name (str)
            - description (str)
            - rules_direction (str)
            - rules_ip_protocol (str)
            - rules_from_port (int)
            - rules_to_port (int)
            - rules_grants_group_id (str)
            - rules_grants_name (str)
            - rules_grants_cidr_ip (str)
            - rules_description (str)
        """
        assert isinstance(id, str), "Invalid id: {}".format(id)
        assert isinstance(name, str)
        assert isinstance(description, str)
        assert rules_direction in ('INGRESS', 'EGRESS', None)
        assert rules_ip_protocol in (
            u'tcp', u'udp', u'icmp', u'icmpv6', "-1", None)
        assert isinstance(rules_from_port, (int, type(None)))
        assert isinstance(rules_to_port, (int, type(None)))
        assert isinstance(rules_grants_group_id, (str, type(None)))
        assert isinstance(rules_grants_name, (str, type(None)))
        assert isinstance(rules_grants_cidr_ip, (str, type(None)))
        assert isinstance(rules_description, (str, type(None)))

        self.id = id
        self.name = name
        self.description = description
        self.rules_direction = rules_direction
        self.rules_ip_protocol = rules_ip_protocol
        self.rules_from_port = rules_from_port
        self.rules_to_port = rules_to_port
        self.rules_grants_group_id = rules_grants_group_id
        self.rules_grants_name = rules_grants_name
        self.rules_grants_cidr_ip = rules_grants_cidr_ip
        self.rules_description = rules_description

    def as_dict(self):
        """
        Returns:
            dict
        """
        dict_fw = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'rules_direction': self.rules_direction,
            'rules_ip_protocol': self.rules_ip_protocol,
            'rules_from_port': self.rules_from_port,
            'rules_to_port': self.rules_to_port,
            'rules_grants_group_id': self.rules_grants_group_id,
            'rules_grants_name': self.rules_grants_name,
            'rules_grants_cidr_ip': self.rules_grants_cidr_ip,
            'rules_description': self.rules_description
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
        self.filters = list()
        if vpc is not None:
            vpc_filter = {
                'Name': 'vpc-id',
                'Values': [vpc]
            }
            self.filters.append(vpc_filter)
        self.dict_rules = self._get_rules_from_aws()

        assert isinstance(region, (str, type(None))), \
            "The region must be a string."
        assert isinstance(profile, (str, type(None))), \
            "The profile must be a string."
        assert isinstance(vpc, (str, type(None))), \
            "The vpc must be a string."

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

                                fr = FirewallRule(
                                    main_row['id'],
                                    main_row['name'],
                                    main_row['description'],
                                    rules_direction=rule_row['direction'],
                                    rules_ip_protocol=rule_row['ip_protocol'],
                                    rules_from_port=rule_row['from_port'],
                                    rules_to_port=rule_row['to_port'],
                                    rules_grants_group_id=group_id,
                                    rules_grants_name=row_name,
                                    rules_description=grant_row['description'])

                                list_of_rules.append(fr)
                            elif 'cidr_ip' in grant_row:
                                fr = FirewallRule(
                                    main_row['id'],
                                    main_row['name'],
                                    main_row['description'],
                                    rules_direction=rule_row['direction'],
                                    rules_ip_protocol=rule_row['ip_protocol'],
                                    rules_from_port=rule_row['from_port'],
                                    rules_to_port=rule_row['to_port'],
                                    rules_grants_cidr_ip=grant_row['cidr_ip'],
                                    rules_description=grant_row['description'])
                                list_of_rules.append(fr)
                            else:
                                raise ValueError("Unsupported grant:",
                                                 grant_row)
                    else:
                        fr = FirewallRule(
                            main_row['id'],
                            main_row['name'],
                            main_row['description'],
                            rules_direction=rule_row['direction'],
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
                                             fr.rules_direction,
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
        - rules_direction
        - rules_ip_protocol
        - rules_from_port
        - rules_to_port
        - rules_grants_group_id
        - rules_grants_name
        - rules_grants_cidr_ip
        - rules_description

        Returns:
            str
        """
        # Generate a csv file in memory with all the data in
        output = StringIO.StringIO()
        fieldnames = ['id',
                      'name',
                      'description',
                      'rules_direction',
                      'rules_ip_protocol',
                      'rules_from_port',
                      'rules_to_port',
                      'rules_grants_group_id',
                      'rules_grants_name',
                      'rules_grants_cidr_ip',
                      'rules_description']
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

        if self.profile:
            boto3.setup_default_session(profile_name=self.profile)

        if self.region:
            ec2 = boto3.client('ec2', region_name=self.region)
        else:
            ec2 = boto3.client('ec2')

        security_groups = ec2.describe_security_groups(Filters=self.filters)

        for group in security_groups['SecurityGroups']:
            group_dict = dict()
            group_dict['id'] = group['GroupId']
            group_dict['name'] = group['GroupName']
            group_dict['description'] = group.get('Description', None)

            if (group.get('IpPermissions', None) or
                    group.get('IpPermissionsEgress', None)):
                group_dict['rules'] = list()

            for rule in group.get('IpPermissions', None):
                rule_dict = self._build_rule(rule)
                rule_dict['direction'] = "INGRESS"

                group_dict['rules'].append(rule_dict)

            for rule in group.get('IpPermissionsEgress', None):
                rule_dict = self._build_rule(rule)
                rule_dict['direction'] = "EGRESS"

                group_dict['rules'].append(rule_dict)

            list_of_rules.append(group_dict)

        return list_of_rules

    def _build_rule(self, rule):
        rule_dict = dict()

        rule_dict['ip_protocol'] = rule['IpProtocol']
        rule_dict['from_port'] = rule.get('FromPort', -2)
        rule_dict['to_port'] = rule.get('ToPort', -2)

        rule_dict['grants'] = list()

        for grant in (rule.get('IpRanges')
                      + rule.get('Ipv6Ranges')
                      + rule.get('UserIdGroupPairs')):
            grant_dict = dict()
            grant_dict['name'] = grant.get('Description', None)
            grant_dict['description'] = grant.get('Description', None)
            if grant.get('GroupId', None):
                grant_dict['group_id'] = grant.get('GroupId', None)

            if 'CidrIp' in grant.keys():
                grant_dict['cidr_ip'] = grant.get('CidrIp')
            elif 'CidrIpv6' in grant.keys():
                grant_dict['cidr_ip'] = grant.get('CidrIpv6')

            rule_dict['grants'].append(grant_dict)

        return rule_dict


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
        print(firewall.json)
    elif arguments['--csv']:
        print(firewall.csv)


if __name__ == '__main__':
    main()
