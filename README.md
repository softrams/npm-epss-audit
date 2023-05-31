# NPM EPSS Audit

Currently NPM Audit reports severity of vulnerabilities based on the CVSS score. NPM bulk audit response do not include CVEs in the report as of May 2023. This interim tool uses the NPM Quick Audit end point to retrieve associated CVEs and reports corresponding EPSS scores to help prioritize vulnerabilities.

> **Note**
> Now includes support to check if a CVE is included in the CISA Known Exploited Vulnerability (KEV) catalog.

## About EPSS

EPSS stands for Exploit Prediction Scoring System. It is a machine learning-based model that predicts the likelihood of a software vulnerability being exploited in the wild. The EPSS score is a number between 0 and 1, with a higher score indicating a higher likelihood of exploitation. The EPSS score is calculated using a variety of factors, including the severity of the vulnerability, the availability of exploit code, and the number of known attacks.

See EPSS at [https://www.first.org/epss](https://www.first.org/epss).

## About CISA Known Exploited Vulnerability (KEV) catalog

> For the benefit of the cybersecurity community and network defenders—and to help every organization better manage vulnerabilities and keep pace with threat activity—CISA maintains the authoritative source of vulnerabilities that have been exploited in the wild: the Known Exploited Vulnerability (KEV) catalog.

See CISA KEV Catalog at [https://www.cisa.gov/known-exploited-vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities).

> **Note**
> The CISA KEV catalog is very limited when it comes to individual NPM packages. This is included for future updates to the tool.

## Usage

### Usage via global install option

> Note: NPM Audit requires that all project dependencies are already installed and package-lock.json file exists. Make sure to install dependencies in the project before running the tool.

```bash
npm install -g npm-epss-audit@latest

## Run the tool in the project directory
npm-epss-audit
```

### Usage via npx

```bash
## Run the tool in the project directory
npx npm-epss-audit@latest
```

### Options

```bash
Usage: npm-epss-audit [-v|--verbose] [-r|--refresh] [-t|--threshold]]

Options:
      --version    Show version number                                 [boolean]
  -v, --verbose    Verbose output
  -r, --refresh    Refresh EPSS scores
  -t, --threshold  EPSS score threshold to fail the audit  [number] [default: 0.0]
      --help       Show help                                           [boolean]

```

### Exit Codes

For use in CI pipelines and automation tools, the tool will exit with the following exit codes:

- 0: Ran successfully and no vulnerabilities found
- 1: Failed to run due to errors or other configuration issues
- 2: Ran successfully and vulnerabilities found that exceeded the EPSS Score threshold (default: 0.0, means all vulnerabilities are reported)

### Example output

```bash
# Run with default options
npm-epss-audit

Auditing <project> v0.1.0

┌─────────┬────────────────────────┬────────────┬──────────────────┬──────┬────────────────┬───────────┬──────────┐
│ (index) │         Module         │  Severity  │      CVE ID      │ CVSS │ EPSS Score (%) │ CISA KEV? │ Due Date │
├─────────┼────────────────────────┼────────────┼──────────────────┼──────┼────────────────┼───────────┼──────────┤
│    0    │        'json5'         │   'high'   │ 'CVE-2022-46175' │ 7.1  │     0.225      │   'No'    │    ''    │
│    1    │     'loader-utils'     │ 'critical' │ 'CVE-2022-37601' │ 9.8  │     0.163      │   'No'    │    ''    │
└─────────┴────────────────────────┴────────────┴──────────────────┴──────┴────────────────┴───────────┴──────────┘

# Fail audit only for vulnerabilities with EPSS score greater than 0.0015 (0.15%)
npm-epss-audit --threshold 0.0015

Auditing <project> v0.1.0

┌─────────┬────────────────────────┬────────────┬──────────────────┬──────┬────────────────┬───────────┬──────────┐
│ (index) │         Module         │  Severity  │      CVE ID      │ CVSS │ EPSS Score (%) │ CISA KEV? │ Due Date │
├─────────┼────────────────────────┼────────────┼──────────────────┼──────┼────────────────┼───────────┼──────────┤
│    0    │        'json5'         │   'high'   │ 'CVE-2022-46175' │ 7.1  │     0.225      │   'No'    │    ''    │
│    1    │     'loader-utils'     │ 'critical' │ 'CVE-2022-37601' │ 9.8  │     0.163      │   'No'    │    ''    │
└─────────┴────────────────────────┴────────────┴──────────────────┴──────┴────────────────┴───────────┴──────────┘


At least one CVE with EPSS Score threshold 0.0015 exceeded.

```

### Configuration Options

On first run, the tool will create a folder named .epss in the ${HOME} or "/tmp" folder. This folder will contain the raw EPSS Data file and uncompressed CSV file.
If you would like to choose a different folder, you may set the `EPSS_DATA_FOLDER` environment variable to the desired folder.

## How to contribute

This tool addresses a gap to take advantage of EPSS Scores for NPM packages, as a starting point to prioritize vulnerabilities.
This is probably just be an interim tool until NPM Audit includes CVEs and EPSS scores in the bulk audit response and audit report and
streamline this process for developers.

If you would like to contribute to this project, feel free to fork and create PR if you can.
Otherwise, create an issue with your thoughts and ideas.

## References

- [EPSS](https://www.first.org/epss/data_stats)
- [NPM Audit](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [NPM Quick Audit](https://docs.npmjs.com/cli/v9/commands/npm-audit#quick-audit-endpoint)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
