# NPM EPSS Audit

Currently NPM Audit reports severity of vulnerabilities based on the CVSS score. NPM bulk audit response do not include CVEs in the report as of May 2023. This interim tool uses the NPM Quick Audit end point to retrieve associated CVEs and reports corresponding EPSS scores to help prioritize vulnerabilities.

> Note: This is probably just be an interim tool until NPM Audit includes CVEs and EPSS scores in the bulk audit response and audit report.

## About EPSS

EPSS stands for Exploit Prediction Scoring System. It is a machine learning-based model that predicts the likelihood of a software vulnerability being exploited in the wild. The EPSS score is a number between 0 and 1, with a higher score indicating a higher likelihood of exploitation. The EPSS score is calculated using a variety of factors, including the severity of the vulnerability, the availability of exploit code, and the number of known attacks.

See EPSS at [https://www.first.org/epss](https://www.first.org/epss).

## Usage

### Usage via global install option

> Note: NPM Audit requires that all project dependencies are already installed and package-lock.json file exists. Make sure to install dependencies in the project before running the tool.

```bash
npm install -g npm-epss-audit

## Run the tool in the project directory
npm-epss-audit
```

### Usage via npx

```bash
## Run the tool in the project directory
npx npm-epss-audit
```

### Options

```bash
Usage: npm-audit-epss [-v|--verbose] [-r|--refresh]

Options:
      --version  Show version number                                   [boolean]
  -v, --verbose  Verbose output
  -r, --refresh  Refresh EPSS scores
      --help     Show help                                             [boolean]

```

### Example output

```bash
npm-epss-audit

Auditing <project> v0.1.0

CVE-2022-xxxxx 	 CVSS:7.1 	 EPSS:0.225%

```

### Configuration Options

On first run, the tool will create a folder named .epss in the ${HOME} or "/tmp" folder. This folder will contain the raw EPSS Data file and uncompressed CSV file.
If you would like to choose a different folder, you may set the `EPSS_DATA_FOLDER` environment variable to the desired folder.

## References

- [EPSS](https://www.first.org/epss/data_stats)
- [NPM Audit](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [NPM Quick Audit](https://docs.npmjs.com/cli/v9/commands/npm-audit#quick-audit-endpoint)
