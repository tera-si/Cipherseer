import json
import requests
import sys
import tabulate


# UNIX terminal colour codes
class ColourCodes:
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    green = "\033[0;32m"
    cyan = "\033[0;36m"
    reset = "\033[0m"


# Structs to hold results
class Host:
    table_headers = ["Cipher", "Rating"]

    def __init__(self, hostname: str) -> None:
        self.hostname = hostname
        self.ciphers = {
            "SSLv2": [],
            "SSLv3": [],
            "TLSv1": [],
            "TLSv1.1": [],
            "TLSv1.2": [],
            "TLSv1.3": [],
        }
        self.weaks: list[str] = []

    def pretty_report(self) -> None:
        """Prints the results as a neatly formatted table to STDOUT"""
        for protocol, ciphers in self.ciphers.items():
            print(f"{protocol} (server order):")
            print(tabulate.tabulate(ciphers, headers=self.table_headers, tablefmt="psql") , end="\n\n\n")

    def plain_report_weak(self) -> None:
        """Prints all the weak ciphers in unformatted text for easy copying"""
        for cipher in self.weaks:
            print(cipher)
        print("\n")


class Hosts:
    def __init__(self) -> None:
        self.hosts: list[Host] = []

    def retrieve_host(self, hostname: str) -> Host:
        """Searches through the hosts array and returns the host object that
        matches the provided hostname. If none found, creates a new host object
        with that hostname and returns it."""
        for host in self.hosts:
            if host.hostname == hostname:
                return host

        host = Host(hostname)
        self.hosts.append(host)
        return host


def main():
    url_base = "https://ciphersuite.info/api/cs/"

    # Check and parse args
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} [Testssl.sh_JSON_output_file]", file=sys.stderr)
        sys.exit(1)
    filename = sys.argv[1]

    hosts = Hosts()

    with open(filename, "r") as f:
        raw_json = json.load(f)

        for entry in raw_json:
            if entry["id"].startswith("cipher-"):
                # Grep the relevant fields from the Testssl.sh JSON file
                s = entry["finding"].split(" ")
                protocol = s[0].strip()
                cipher = s[-1].strip()
                # Fetch/Create host object
                host = hosts.retrieve_host(entry["ip"])

                # Make API request and grep relevant fields
                url = url_base + cipher
                rsp = requests.get(url)

                if rsp.status_code == 404:
                    print(f"{cipher} not found in CipherSuite's API", file=sys.stderr)
                    host.ciphers[protocol].append([cipher, "Unknown"])
                    continue

                rsp = rsp.json()
                rsp_rating: str = rsp[cipher]["security"].strip()


                # Colour encode API response
                if rsp_rating == "insecure":
                    host.weaks.append(cipher)
                    coloured_rating = f"{ColourCodes.red}{rsp_rating.capitalize()}{ColourCodes.reset}"
                elif rsp_rating == "weak":
                    host.weaks.append(cipher)
                    coloured_rating = f"{ColourCodes.yellow}{rsp_rating.capitalize()}{ColourCodes.reset}"
                elif rsp_rating == "secure":
                    coloured_rating = f"{ColourCodes.green}{rsp_rating.capitalize()}{ColourCodes.reset}"
                elif rsp_rating == "recommended":
                    coloured_rating = f"{ColourCodes.cyan}{rsp_rating.capitalize()}{ColourCodes.reset}"
                else:
                    coloured_rating = rsp_rating
                # Write result to host object
                host.ciphers[protocol].append([cipher, coloured_rating])

    # Display results
    for host in hosts.hosts:
        print(f"Report for: {host.hostname}")
        host.pretty_report()
        print("Weak ciphers used by this host (for easy copying):")
        host.plain_report_weak()


if __name__ == "__main__":
    main()
