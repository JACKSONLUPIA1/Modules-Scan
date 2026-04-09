# Modules-Scan
This script was made out of respect to the Axios breach and is fairly simple. It takes every single package that is imported from a node_modules folder, hashes them, and computes their hash using VirusTotal's API. It then returns if that package is compromised, malicious, suspicious, etc...

1. Download the server.js file and place it in a working directory.
2. Obtain your VirusTotal API key and place it on the "API_KEY" variable  
3. Import your 'package-lock.json' file into a working directory. 
4. Run the script using 'node server.js ./package-lock.json'

NOTE: VirusTotal only allows 500 scans a day using their API so if the script randomly stops returning the values for each hash, that might be the reason. 
