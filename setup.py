from setuptools import find_packages, setup

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md") as f:
    long_description = f.read()

setup(
    name="pcap_blur",
    version="1.0.0",
    description="Pcap Blur is a command line tool that anonymizes network traffic.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rafaelsilva81/pcap-blur",
    author="Rafael Galdino da Silva",
    author_email="rafaelgaldinosilva81@gmail.com",
    license="MIT",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pcap-blur=pcap_blur:main",
            "pcap_blur=pcap_blur:main",
            "pcapblur=pcap_blur:main",
        ],
    },
    install_requires=requirements,
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)
