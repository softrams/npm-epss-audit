#!/usr/bin/env node

const fs = require("fs");
const zlib = require("node:zlib");
const { pipeline } = require("node:stream/promises");
const { Readable } = require("stream");
const { finished } = require("stream/promises");
const yargs = require("yargs");

const EPSS_DATA_FOLDER =
  process.env.EPSS_DATA_FOLDER || process.env.HOME || "/tmp";

const epssScores = {};
const kevData = {};

async function downloadFile(url, path) {
  const outfile = fs.createWriteStream(path);
  const response = await fetch(url);
  await finished(Readable.fromWeb(response.body).pipe(outfile));
}

async function syncKEV(refresh = false) {
  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss`)) {
    console.log(`\nCreating ${EPSS_DATA_FOLDER}/.epss folder`);
    fs.mkdirSync(`${EPSS_DATA_FOLDER}/.epss`);
  }

  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss/kev.json`) || refresh) {
    console.log(`\nDownloading CISA Known Exploited Vulnerabilities catalog`);
    await downloadFile(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      `${EPSS_DATA_FOLDER}/.epss/kev.json`
    );
  }
}

async function syncEpss(refresh = false) {
  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss`)) {
    console.log(`\nCreating ${EPSS_DATA_FOLDER}/.epss folder`);
    fs.mkdirSync(`${EPSS_DATA_FOLDER}/.epss`);
  }

  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`) || refresh) {
    console.log(`\nDownloading EPSS scores`);
    await downloadFile(
      "https://epss.cyentia.com/epss_scores-current.csv.gz",
      `${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`
    );
  }

  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss/epss.csv`) || refresh) {
    // Download GZ file and unzip it
    console.log("\nUnzipping EPSS scores data file");
    const input = fs.createReadStream(`${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`);
    const output = fs.createWriteStream(`${EPSS_DATA_FOLDER}/.epss/epss.csv`);
    const unzip = zlib.createGunzip();
    await pipeline(input, unzip, output);
  }
}

async function loadKEVCatalog(refresh = false) {
  const kevContents = fs.readFileSync(
    `${EPSS_DATA_FOLDER}/.epss/kev.json`,
    "utf8"
  );
  const kev = JSON.parse(kevContents);
  for (const item of kev.vulnerabilities) {
    kevData[item.cveID] = {
      ...item,
    };
  }
}

async function loadScores(refresh = false) {
  const csv = fs.readFileSync(`${EPSS_DATA_FOLDER}/.epss/epss.csv`, "utf8");
  const lines = csv.split("\n");
  let idx = 1;
  for (const line of lines) {
    // skip headers
    if (refresh && idx == 1) {
      console.log(`\nEPSS Scores refreshed at ${new Date().toLocaleString()} `);
      console.log(`${line}\n`);
    }

    if (idx > 2) {
      const [cve, epss, percentile] = line.split(",");
      epssScores[cve] = {
        epss,
        percentile,
      };
    }
    idx++;
  }
  // console.log(`Loaded  ${idx} EPSS scores`);
}

async function audit(verbose = false, threshold = 0.0, failOnPastDue = false) {
  if (!fs.existsSync(process.cwd() + "/package.json")) {
    console.log(
      `\nError: package.json not found in ${process.cwd()}. Run 'npm-epss-audit' in the project root directory where package.json is located.`
    );
    process.exit(1);
  }

  // Read package.json from the script current working directory,
  // not from the directory where the script is located.
  const packageJson = JSON.parse(
    fs.readFileSync(process.cwd() + "/package.json")
  );

  // Check if package-lock.json is present.
  if (!fs.existsSync(process.cwd() + "/package-lock.json")) {
    console.log(
      `\nError: package-lock.json not found in ${process.cwd()}.
       \nMake sure to install all dependencies and run 'npm-epss-audit' in the project root directory where package-lock.json is located.`
    );
    process.exit(1);
  }

  // Read package-lock.json from the script current working directory,
  // not from the directory where the script is located.
  const packageLockJson = JSON.parse(
    fs.readFileSync(process.cwd() + "/package-lock.json")
  );

  console.log(`\nAuditing ${packageJson.name} v${packageJson.version} \n `);

  // Prepare payload
  const payload = {
    name: packageJson.name,
    version: packageJson.version,
    requires: {
      ...(packageJson.devDependencies || {}),
      ...(packageJson.peerDependencies || {}),
      ...(packageJson.optionalDependencies || {}),
      ...(packageJson.dependencies || {}),
    },
    dependencies: packageLockJson.dependencies,
    node_version: process.version,
    npm_version: process.env.npm_version,
  };

  // Send payload to the server
  const response = await fetch(
    "https://registry.npmjs.org/-/npm/v1/security/audits/quick",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  // Parse response
  const json = await response.json();
  if (json && json.error) {
    console.log(`Error: ${JSON.stringify(json, null, 2)}`);
    process.exit(1);
  }

  let aboveThreshold = false;
  let unknownCVE = false;
  let pastDueDate = false;

  const UNKNOWN = "n/a"
  const today = new Date();

  // Print results
  // Metadata -> Vulnerabilities

  if (verbose && json.metadata && json.metadata.vulnerabilities) {
    console.log(
      `Vulnerabilities: ${JSON.stringify(
        json.metadata.vulnerabilities,
        null,
        2
      )}`
    );
    console.log(`\n`);
  }

  let tabularData = [];

  // Loop through key, value pairs of the advisories object
  let count = 1;
  if (json.advisories && Object.keys(json.advisories).length > 0) {
    for (const [key, value] of Object.entries(json.advisories)) {
      if (verbose) {
        console.log(`Advisory ${count}: ${value.title}`);
        console.log(`Severity: ${value.severity}`);
        console.log(`Package: ${value.module_name}`);
        console.log(`  Version: ${value.findings[0].version}`);
        console.log(
          `  Paths: ${JSON.stringify(value.findings[0].paths[0], null, 2)}`
        );
        console.log(`Vulnerable Versions: ${value.vulnerable_versions}`);
        console.log(
          `Patched Version: ${value.patched_versions || "No patch available"}`
        );
        console.log(`More info: ${value.url}`);
        console.log(`\n`);

        if (value.cves && value.cves.length > 0) {
          console.log(`CVSS Score: ${value.cvss.score}`);
          console.log(`CVE: ${value.cves[0]}`);
          if (value.cves[0] in epssScores) {
            console.log(
              `EPSS Score: ${+Number(
                epssScores[value.cves[0]].epss * 100.0
              ).toFixed(3)}%`
            );
          } else {
            unknownCVE = true;
            console.log('EPSS Score: Not Found!');
          }

          // Check if CVW is in Known Exploratory Vulnerabilities
          const kve = kevData[value.cves[0]];
          if (kve) {
            console.log(`CISA Known Exploited Vulnerability: Yes`);
            console.log(`  Date Added: ${kve.dateAdded}`);
            console.log(`  Due Date: ${kve.dueDate}`);

            // Check if due date is in the past
            const dueDate = new Date(kve.dueDate);
            if (today > dueDate) {
              pastDueDate = true;
            }
          } else {
            console.log(`CISA Known Exploited Vulnerability: No`);
          }

          // Check if EPSS score is above threshold
          if (
            value.cves[0] in epssScores &&
            +Number(epssScores[value.cves[0]].epss).toFixed(5) >
            +Number(threshold).toFixed(5)
          ) {
            aboveThreshold = true;
          }
        }

        console.log(`\n`);
      } else {
        if (value.cves && value.cves.length > 0) {
          const kve = kevData[value.cves[0]];
          epssScore = value.cves[0] in epssScores ? +Number(epssScores[value.cves[0]].epss * 100.0).toFixed(3): UNKNOWN;

          if (epssScore == UNKNOWN) {
            unknownCVE = true;
          }

          tabularData.push({
            Module: value.module_name,
            Severity: value.severity,
            "CVE ID": value.cves[0],
            CVSS: value.cvss.score,
            "EPSS Score (%)": epssScore,
            "CISA KEV?": kve ? "Yes" : "No",
            "Due Date": kve ? kve.dueDate : "N/A",
            "More Info": value.url
          });

          // Check if EPSS score is above threshold
          if (
            epssScore != UNKNOWN &&
            +Number(epssScores[value.cves[0]].epss).toFixed(5) >
            +Number(threshold).toFixed(5)
          ) {
            aboveThreshold = true;
          }

          // Check if due date is in the past
          if (kve) {
            const dueDate = new Date(kve.dueDate);
            if (today > dueDate) {
              pastDueDate = true;
            }
          }
        }
      }
      count++;
    }

    // Sort and print in desc order of EPSS Score %
    if (!verbose) {
      tabularData
        .sort((a, b) =>
            a["EPSS Score (%)"] == UNKNOWN || a["EPSS Score (%)"] > b["EPSS Score (%)"]
            ? 1
            : b["EPSS Score (%)"] == UNKNOWN || b["EPSS Score (%)"] > a["EPSS Score (%)"]
            ? -1
            : 0
        )
        .reverse();
      console.table(tabularData);
    }

    console.log(`\n`);

    if (unknownCVE) {
      // not exiting early, this likely indicates a CVE that hasn't been fully disclosed yet
      console.log("Could not find EPSS Score for at least one CVE\n");
    }
    if (pastDueDate) {
      console.log(
        `At least one CVE is past its due date as per CISA Known Exploited Vulnerabilities Catalog.\n`
      );

      if (failOnPastDue) {
        process.exit(2);
      }
    }

    if (aboveThreshold) {
      if (Number(threshold) > 0.0) {
        console.log(
          `At least one CVE with EPSS Score threshold ${+Number(
            threshold
          ).toFixed(5)} exceeded.\n`
        );
      }
      process.exit(2);
    }

    process.exit(0);
  } else {
    console.log(`No vulnerabilities found`);
    process.exit(0);
  }
}

(async () => {
  try {
    const options = yargs
      .scriptName("npm-epss-audit")
      .usage(
        "Usage: $0 [-v|--verbose] [-r|--refresh] [-f|--fail-on-past-duedate] [-t|--threshold]"
      )
      .option("v", {
        alias: "verbose",
        describe: "Verbose output",
      })
      .option("r", { alias: "refresh", describe: "Refresh EPSS scores" })
      .option("f", {
        alias: "fail-on-past-duedate",
        describe: "Fail on past CISA KVE due date",
      })
      .option("t", {
        alias: "threshold",
        describe: "EPSS score threshold to fail the audit",
        type: "number",
        default: 0.0,
      })
      .help(true).argv;

    await syncEpss(options.refresh);
    await syncKEV(options.refresh);

    await loadScores(options.refresh);
    await loadKEVCatalog(options.refresh);

    await audit(
      options.verbose,
      options.threshold,
      options["fail-on-past-duedate"]
    );
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
})();
