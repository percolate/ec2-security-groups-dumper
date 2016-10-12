from setuptools import setup


setup(
    name='ec2-security-groups-dumper',
    version='1.4',
    description='AWS EC2 Security Groups dump tool',
    url='https://github.com/percolate/ec2-security-groups-dumper',
    author='Laurent Raufaste',
    author_email='analogue@glop.org',
    license='GPLv3',
    keywords='aws ec2 firewall boto',
    packages=['ec2_security_groups_dumper'],
    install_requires=[
        'boto',
        'docopt'
    ],
    entry_points={
        'console_scripts': [
            'ec2-security-groups-dumper=ec2_security_groups_dumper.main:main'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Topic :: System :: Systems Administration"
    ]
)
