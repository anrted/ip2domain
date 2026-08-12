from setuptools import setup, find_packages

setup(
    name="ip2domain",
    version="1.4.0",
    description="Scalable Reverse IP to Domain parser supporting single IPs, CIDR subnets, and ranges.",
    author="Antigravity",
    packages=find_packages(exclude=("tests", "tests.*")),
    install_requires=[
        "aiohttp>=3.8.0",
        "tabulate>=0.9.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
        "jinja2>=3.1.0",
        "cryptography>=42.0.0",
        "dnspython>=2.6.0",
    ],
    entry_points={
        "console_scripts": [
            "ip2domain = ip2domain.cli:main",
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    package_data={"ip2domain.web": ["templates/*.html", "static/*.js", "static/*.css"]},
)
