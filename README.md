# Pcap_Blur

`pcap_blur` is a command line tool for anonymizing network traffic captured in `.pcap` or `.pcapng` files in a simple yet secure way. The main purpose of this tool is to allow anyone to anonymize their own network traffic for research, testing, or educational purposes. The main focus of `pcap_blur` is on anonymization of Internet traffic under the TCP/IP stack.

## Installation

### Windows

1. Download and install [Python 3.10 or later](https://www.python.org/downloads/windows/) and [pip](https://pypi.org/project/pip/)

2. Download and install the latest version of [Npcap](https://nmap.org/npcap/)

> It is advised to turn **off** the `Winpcap compatibility mode` option during installation

3. Install `pcap_blur` using `pip`:

```bash
pip install pcap_blur
```

### Linux

1. Install [Python 3.10 or later](https://www.python.org/downloads/) and [pip](https://pypi.org/project/pip/)

2. Install [libpcap](https://www.tcpdump.org/)

For Debian based distributions:

```bash
sudo apt install libpcap-dev
```

For Fedora/Red Hat based distributions:

```bash
sudo yum install libpcap-devel
```

3. Install `pcap_blur` using `pip`:

```bash
pip install pcap_blur
```

## Usage

The main usage of `pcap_blur` is to anonymize a .pcap file. To do this, you can use the following command:

```bash
pcap_blur path/to/file.pcap
```

By default, the output file will be named `file_anonymized.pcap` and together with the log file will be saved in a folder named `output`. You can change the output folder and filename by using the `--outDir` and `--outName` options, respectively.

```bash
pcap_blur path/to/file.pcap --outDir /new_output_folder --outName new_name.pcap
```

You can also use the `--batch` option to anonymize multiple
capture files in a folder.

```bash
pcap_blur --batch /path/to/folder
```

Using this option, an `output` folder will be created in the specified folder and the anonymized files will be saved in it. All the logs will be saved individually under the `output/logs` folder. You can change the output folder by using the `--outDir` option.

```bash
pcap_blur --batch /path/to/folder --outDir /new_output_folder
```

You can use the `--validate` option to validate the anonymization of a .pcap file. This option will compare the original and anonymized files and search if any of the original information is found in the anonymized packets.

```bash
pcap_blur --validate path/to/original_file.pcap path/to/anonymized_file.pcap
```

Below is a table with all the command line options available for `pcap_blur`:

| Option                                                   | Description                                                                                       | Default                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `path`                                                   | Path to the capture file to be anonymized.                                                        | None                                                           |
| `--batch`                                                | Specify a folder for batch anonymization.                                                         | None                                                           |
| `--outDir ${directory}`                                  | Set the output directory for the anonymized capture file(s).                                      | `output` or `${original_folder}/output` if used with `--batch` |
| `--outName ${filename}`                                  | Set the filename of the anonymized capture file. Can only be used with single file anonymization. | `${original_filename}.anon.pcap`                               |
| `--version`                                              | Show the version of the tool.                                                                     | None                                                           |
| `--validate ${original_filename} ${anonymized_filename}` | Validate the anonymization of a capture file.                                                     | None                                                           |

## Anonymization Policy

`pcap_blur` uses an anonymization policy defined by the original author (me) for a final project at the Federal University of Ceará (UFC), which is based on the following principles:

- Focus on anonymizing Internet traffic under the TCP/IP stack.
- Anonymization that provides a good balance between privacy and usability.
- Anonymization that is simple and easy to understand.

Below is a table of the fields that are anonymized and the anonymization method used:

| Field            | Anonymization Method                  |
| ---------------- | ------------------------------------- |
| MAC Adresses     | Double permutation                    |
| IP Adresses      | Prefix-preserving pseudorandomization |
| Port Numbers     | Permutation                           |
| Timestamps       | Precision degradation                 |
| Application Data | Black marker                          |

You can find more information about the anonymization policy and other edge-case scenarios on the final paper (link to be added).

## Building from source

If you wish to use `pcap_blur` from source instead of using the pre-built binary or if you want to modify the source code before running it, you can follow these steps:

1. Install [Python 3.10 or later](https://www.python.org/downloads/)

2. Clone the repository:

```bash
git clone https://github.com/rafaelsilva81/pcap_blur.git
```

3. (Optionally) Initialize a virtual environment with [venv](https://docs.python.org/3/library/venv.html):

4. Install the dependencies:

```bash
pip install -r requirements.txt
```

5. Run the tool by executing the `main.py` script:

```bash
python main.py --version
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please file an issue or submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## Acknowledgments

- [Scapy](https://scapy.net/) - A powerful and flexible packet manipulation library for Python.
- [YaCryptoPan](https://github.com/yacryptopan/yacryptopan) - A Python library for CrpyoPAn, a cryptographic anonymization algorithm.
- [Netresec Publicly available PCAP files](https://netresec.com/?page=public-pcap-files) - A collection of publically available PCAP files for testing and research purposes.
