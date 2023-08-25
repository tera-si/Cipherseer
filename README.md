# Cipherseer
Parses testssl.sh JSON output and queries ciphersuite.info for security rating of ciphers.

# Requirments

- Python 3.6+
- [Requests](https://pypi.org/project/requests/)
- [Tabulate](https://pypi.org/project/tabulate/)

# Usage

1. First run [testssl.sh](https://testssl.sh/) against the target server(s). **Ensure you save the output to JSON.**
```
$ testssl.sh --json https://example.com
```
2. Once testssl.sh finishes, run the script with the JSON output.
```
$ python3 main.py example.json
```

# Quirks

- The script expects the testssl.sh scan to be performed with default checks, ordering, and formatting. So if change any of these, e.g. using `--mapping`, then the script will not work correctly.
