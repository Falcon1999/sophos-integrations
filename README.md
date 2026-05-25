# Sophos Integration

Standalone Sophos SG → XGS migration app extracted from the Zeek Summarizer project.

## What it does

- stores separate SG and XGS connection settings
- tests SG connectivity
- tests XGS connectivity
- previews which SG rules can be migrated automatically
- migrates supported SG rules into XGS
- reloads XGS rules so you can immediately confirm visibility

## Files

- `server.js` — standalone backend and API
- `index.html` — standalone web UI
- `migration.config.json` — live local config
- `migration.config.example.json` — blank example config

## Run

```bash
cd /home/falcon/Desktop/sophos-integration
npm start
```

Then open:

- <http://127.0.0.1:3009/>

## Optional environment variables

- `PORT=3010 npm start` — run on another port
- `HOST=0.0.0.0 npm start` — listen on all interfaces

## Notes

- `migration.config.json` contains live credentials/settings for this local machine.
- `migration.config.example.json` is the safe template copy.
- No external npm dependencies are required.
- For a safe smoke test without touching the firewalls, use:

```bash
node --check server.js
PORT=3019 node server.js
curl http://127.0.0.1:3019/health
```
