#!/usr/bin/env node

const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const path = require("path");
const API_KEY = null; // replace with VT API key 

const filePath = process.argv[2]; // param

if (!filePath) {
  console.error("Error: File not found.");
  process.exit(1);
}

const fullPath = path.resolve(filePath);

let lock;

try {
  lock = JSON.parse(fs.readFileSync(fullPath, "utf-8"));
} catch (err) {
  console.error(`Error: Could not parse "${fullPath}" — Script only accept JSON files.`);
  process.exit(1);
}

if (!lock.lockfileVersion || !lock.packages) {
  console.error(`Error: "${fullPath}" does not appear to be a valid package-lock.json`);
  process.exit(1);
}

function getFileBuffer(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      const data = [];

      res.on("data", (chunk) => data.push(chunk));
      res.on("end", () => {
        resolve(Buffer.concat(data));
      });

      res.on("error", reject);
    });
  });
}

async function sha256FromURL(url) {
  const fileBuffer = await getFileBuffer(url);

  const hash = crypto
    .createHash("sha256")
    .update(fileBuffer)
    .digest("hex");

  return hash;
}

// VirusTotal request using https
function checkHash(hash) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "www.virustotal.com",
      path: `/api/v3/files/${hash}`,
      method: "GET",
      headers: {
        "x-apikey": API_KEY, // replace with API key
      },
    };

    // heck you axios...
    const req = https.request(options, (res) => {
      let data = "";

      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on("error", reject);
    req.end();
  });
}

// reads package lockfile and returns JSON array of package name and their corresponding hash
async function constructJSON() {
  console.log("Building package information from lockfile, this may take a moment...")
  const packages = lock.packages || {};

  if (Object.keys(packages).length === 0) {
    console.log("Error: Failure to read values from package lockfile.");
    process.exit(1);
  }

  // the rest of this function was optomized by AI to leverage most of the computing power AWAY from the single-threaded CPU
  const results = await Promise.allSettled(
    // maps over the packages and returns an array of objects with package name, url, and sha256 hash -> this is done asynchronously to avoid a network yield in the await process
    // aka: works around JavaScript's single-threaded nature by allowing multiple network requests to be made in parallel
    Object.entries(packages).map(async ([pkgPath, pkgInfo]) => {
      if (!pkgInfo.integrity) return null;

      const pkgName = pkgPath.split("node_modules/").slice(-1)[0];
      const pkgLink = pkgInfo.resolved || null;
      const sha256 = pkgLink ? await sha256FromURL(pkgLink) : null;

      return {
        package: pkgName,
        url: pkgLink,
        sha256: sha256
      };
    })
  );
  return results
    .filter(r => r.status === "fulfilled" && r.value !== null) // removes the 'inital' null values and any rejected promises
    .map(r => r.value);
}

function isMalicious(pkgName, stats) {
  // returns if hash may contain malicious or suspected packages
  if (!stats?.data?.attributes?.last_analysis_stats) {
    console.warn(`[SKIP] No data returned for ${pkgName} — possible rate limit`);
    return null;
  }

  const malicious = stats.data.attributes.last_analysis_stats.malicious;
  const suspicious = stats.data.attributes.last_analysis_stats.suspicious;
  const undetected = stats.data.attributes.last_analysis_stats.undetected;
  const harmless = stats.data.attributes.last_analysis_stats.harmless;
  const timeout = stats.data.attributes.last_analysis_stats.timeout;
  const failure = stats.data.attributes.last_analysis_stats.failure;
  const total = malicious + suspicious + undetected + harmless + timeout + failure;
  const scanned = total - failure - timeout; // engines that gave a real answer
  const confidence = scanned > 0 ? Math.round((scanned / total) * 100) : 0;

  if (confidence < 25 || scanned === 0) {
    console.log(`Error: Failure to process hash with a confidence level of: ${confidence}% OR no engines have scanned the file(s).`);
    return;
  }

  const threatScore = Math.round(((malicious * 1.0 + suspicious * 0.5) / scanned) * 100);

  if (threatScore >= 30) {
    return {
      package: pkgName,
      hash: stats.data.id,
      verdict: "MALICIOUS",
      severity: "HIGH",
      reason: `${malicious} malicious, ${suspicious} suspicious out of ${scanned} engines (score: ${threatScore})`
    };
  }

  if (threatScore >= 10) {
    return {
      package: pkgName,
      hash: stats.data.id,
      verdict: "MALICIOUS",
      severity: "MEDIUM",
      reason: `${malicious} malicious, ${suspicious} suspicious out of ${scanned} engines (score: ${threatScore})`
    };
  } 

  if (suspicious > 0) {
    return {
      package: pkgName,
      hash: stats.data.id,
      verdict: "SUSPICIOUS",
      severity: "LOW",
      reason: `${suspicious} suspicious out of ${scanned} engines (score: ${threatScore})`
    };
  }

  if (harmless >= 0 && malicious <= 0 && suspicious <= 0) {
    return {
      package: pkgName,
      hash: stats.data.id,
      verdict: "CLEAN",
      severity: "NONE",
      reason: `${harmless} harmless out of ${scanned} engines (score: ${threatScore})`
    };
  } else {
    return {
      package: pkgName,
      hash: stats.data.id,
      verdict: "UNDETECTED",
      severity: "NONE",
      reason: `No engines flagged this file out of ${scanned} scanned`
    };
  }
}

async function scan() {
  const packageInfo = (await constructJSON()).filter(p => p?.sha256 !== null);

  if (!packageInfo) {
    console.error("Failed to construct package information.");
    return;
  }

  const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  for (let i = 0; i < packageInfo.length; i++) {
    const results = await checkHash(packageInfo[i].sha256);
    console.log(isMalicious(packageInfo[i].package, results));
    await delay(500); // 0.5 second delay to respect VirusTotal's rate limits
  }
}

scan();
