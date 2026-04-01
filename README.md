# axios-scan

scan your system for indicators of compromise from the [axios npm supply chain attack](https://github.com/axios/axios/issues/10604) (march 2026).
checks lockfiles, node_modules, filesystem artifacts, and C2 connectivity.

published in tandem with [my blog post](https://blog.jiface.com/axios-supply-chain-attack)

## usage
```bash
npx axios-scan /path/to/project
```

or clone and run directly:
```bash
node index.js /path/to/project
```

## what it checks
- **lockfiles**: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb for `plain-crypto-js`, `axios@1.14.1`, `axios@0.30.4`
- **node_modules**: presence of `plain-crypto-js`, postinstall hook, setup.js dropper, package.md self-destruct artifact
- **filesystem**: platform-specific RAT payloads (`/Library/Caches/com.apple.act.mond`, `/tmp/ld.py`, `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.ps1`, `%TEMP%\6202033.vbs`)
- **network**: C2 server reachability (142.11.206.73:8000) and active connections

## exit codes
- `0`: clean
- `1`: compromised

## license
MIT
