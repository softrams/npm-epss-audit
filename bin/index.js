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

async function downloadFile(url, path) {
  const outfile = fs.createWriteStream(path);
  const response = await fetch(url);
  await finished(Readable.fromWeb(response.body).pipe(outfile));
}

async function syncEpss(refresh = false) {
  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss`)) {
    fs.mkdirSync(`${EPSS_DATA_FOLDER}/.epss`);
  }

  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`) || refresh) {
    await downloadFile(
      "https://epss.cyentia.com/epss_scores-current.csv.gz",
      `${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`
    );
  }

  if (!fs.existsSync(`${EPSS_DATA_FOLDER}/.epss/epss.csv`) || refresh) {
    // Download GZ file and unzip it
    const input = fs.createReadStream(`${EPSS_DATA_FOLDER}/.epss/epss.csv.gz`);
    const output = fs.createWriteStream(`${EPSS_DATA_FOLDER}/.epss/epss.csv`);
    const unzip = zlib.createGunzip();
    await pipeline(input, unzip, output);
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

async function audit(verbose = false) {
  // Read package.json from the script current working directory,
  // not from the directory where the script is located.
  const packageJson = JSON.parse(
    fs.readFileSync(process.cwd() + "/package.json")
  );

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
    return;
  }

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
          console.log(
            `EPSS Score: ${Number(
              epssScores[value.cves[0]].epss * 100.0
            ).toFixed(3)}%`
          );
        }
        console.log(`\n`);
      } else {
        if (value.cves && value.cves.length > 0) {
          console.log(
            `${value.cves[0]} \t CVSS:${value.cvss.score} \t EPSS:${Number(
              epssScores[value.cves[0]].epss * 100.0
            ).toFixed(3)}%`
          );
        }
      }
      count++;
    }
    console.log(`\n`);
  } else {
    console.log(`No vulnerabilities found`);
  }
}

(async () => {
  try {
    const options = yargs
      .scriptName("npm-epss-audit")
      .usage("Usage: $0 [-v|--verbose] [-r|--refresh]")
      .option("v", {
        alias: "verbose",
        describe: "Verbose output",
      })
      .option("r", { alias: "refresh", describe: "Refresh EPSS scores" })
      .help(true).argv;

    await syncEpss(options.refresh);
    await loadScores(options.refresh);
    await audit(options.verbose);
  } catch (err) {
    console.error(err);
  }
})();
