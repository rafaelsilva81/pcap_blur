import argparse
import glob
import os
import signal
import sys

from anonymizer import PcapAnonymizer
from utils import (
    change_log_file,
    check_tcpinfo,
    initial_logging_config,
    validate_anonymization,
)


def signal_handler(sig, frame):
    print("\nInterrupt received. Exiting...")
    sys.exit(0)


def main():
    # Setup signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    initial_logging_config()

    parser = argparse.ArgumentParser(
        description="PcapBlur is a tool for anonymizing network traffic captured in .pcap files."
    )

    # Create mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "path", nargs="?", help="Path to the .pcap file to be anonymized."
    )

    group.add_argument("--batch", help="Specify a folder for batch anonymization.")

    group.add_argument(
        "--version", "-v", help="Show the version of the tool.", action="store_true"
    )

    group.add_argument(
        "--validate",
        nargs=2,
        metavar=("first", "second"),
        help="Validate anonymization by comparing two .pcap files.",
    )

    group.add_argument(
        "--check-tcp",
        nargs=2,
        metavar=("first", "second"),
        help="Check TCP information by comparing two .pcap files.",
    )

    parser.add_argument(
        "--outDir",
        "-o",
        help="Set the output directory for the anonymized .pcap file(s).",
        default="output",
    )
    parser.add_argument(
        "--outName",
        "-n",
        help="Set the filename of the anonymized .pcap file. (OPTIONAL, works with path only)",
    )

    args = parser.parse_args()

    if args.version:
        print("pcap_blur version 1.0.0")
        return

    if args.check_tcp:
        print("Checking TCP information. This can take a while...")
        # Handling TCP information check for two pcap files
        first_file, second_file = args.check_tcp
        if not os.path.exists(first_file):
            print(f"Error: Original file {first_file} does not exist.")
            return

        if not os.path.exists(second_file):
            print(f"Error: Anonymized file {second_file} does not exist.")
            return

        check_tcpinfo(first_file, second_file)
        return

    if args.validate:
        # Handling validation of two pcap files
        first_file, second_file = args.validate
        if not os.path.exists(first_file):
            print(f"Error: Original file {first_file} does not exist.")
            return

        if not os.path.exists(second_file):
            print(f"Error: Anonymized file {second_file} does not exist.")
            return

        validate_anonymization(first_file, second_file)
        return

    if args.batch:
        # Handling batch anonymization for a folder
        if args.outName:
            parser.error("--outName cannot be used with --batch")

        print(f"Batch anonymization for folder: {args.batch}")

        out_folder = os.path.join(args.batch, args.outDir)
        out_folder_logs = os.path.join(out_folder, "logs")

        if not os.path.exists(out_folder):
            os.makedirs(out_folder)

        if not os.path.exists(out_folder_logs):
            os.makedirs(out_folder_logs)

        # Search for all .pcap or .pcapng files in the folder

        pcap_files = glob.glob(os.path.join(args.batch, "*.pcap")) + glob.glob(
            os.path.join(args.batch, "*.pcapng")
        )

        for pcap_file in pcap_files:
            out_name = os.path.basename(pcap_file).replace(".pcap", ".anon.pcap")
            change_log_file(out_folder_logs, out_name)
            pcap_anonymizer = PcapAnonymizer(pcap_file, out_folder, out_name)
            pcap_anonymizer.anonymize_file()

    else:
        # Handling single file anonymization
        if args.outName is None:
            args.outName = os.path.basename(args.path).replace(
                ".pcap", "_anonymized.pcap"
            )

        if not os.path.exists(args.outDir):
            os.makedirs(args.outDir)

        if not os.path.exists(args.path):
            print(f"Error: The file {args.path} does not exist.")
            return

        file_name = os.path.basename(args.path)

        change_log_file(args.outDir, file_name)
        pcap_anonymizer = PcapAnonymizer(args.path, args.outDir, args.outName)
        pcap_anonymizer.anonymize_file()


if __name__ == "__main__":
    main()
