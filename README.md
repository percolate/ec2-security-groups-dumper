# ec2-security-groups-dumper

[![Circle CI](https://circleci.com/gh/percolate/ec2-security-groups-dumper.svg?style=shield)](https://circleci.com/gh/percolate/ec2-security-groups-dumper)

Dump your EC2 Security Groups as a CSV or JSON file.

Makes it possible to maintain your firewall rules in git.

## Quick Start

```bash
$ ec2-security-groups-dumper --help
ec2-security-groups-dumper

Dumps the EC2 firewall rules as a json or csv output. Redirect the output to a
file to dump it to this file.
Useful to keep track of the firewall changes in git.
Can also be used as a backup in case you lose some rules on EC2.

Usage:
    ec2-security-groups-dumper --json [--region=<region>] [--profile=<profile>] [--vpc=<vpc>]
    ec2-security-groups-dumper --csv [--region=<region>] [--profile=<profile>] [--vpc=<vpc>]
    ec2-security-groups-dumper (-h | --help)

Options:
  -h --help     Show this screen.

Examples:
    ec2-security-groups-dumper --csv > path/to/ec2-security-groups.csv
    ec2-security-groups-dumper --json > path/to/your-firewall-backup.json
```

## Install

```bash
pip install ec2-security-groups-dumper
```

## See Also

- [IAMer](https://github.com/percolate/iamer) to dump your IAM rules as INI and
  JSON text files.
