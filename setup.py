from setuptools import setup, find_packages

setup(
    name="proxmox-redfish",
    version="0.1.0",
    description="Redfish API daemon for Proxmox VMs",
    author="Brandon B. Jozsa",
    author_email="bjozsa@redhat.com",
    url="https://github.com/v1k0d3n/proxmox-redfish",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests",
        "requests_toolbelt",
        "proxmoxer",
    ],
    entry_points={
        "console_scripts": [
            "proxmox-redfish=proxmox_redfish.proxmox_redfish:main"
        ]
    },
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache 2.0 License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
) 