#!/usr/bin/env node

import { readFileSync, existsSync } from "fs"
import { join, basename } from "path"
import { execSync } from "child_process"
import { platform, tmpdir } from "os"
import { createConnection } from "net"

const R = "\x1b[0;31m", G = "\x1b[0;32m", Y = "\x1b[1;33m", C = "\x1b[0;36m", B = "\x1b[1m", N = "\x1b[0m"
let hits = 0, checked = 0

const hit = m => { console.log(`  ${R}[!]${N} ${m}`); hits++ }
const ok = m => console.log(`  ${G}[+]${N} ${m}`)
const info = m => console.log(`  ${C}[*]${N} ${m}`)

const dir = process.argv[2] || "."

console.log(`\n${B}axios supply chain attack scanner${N}`)
console.log(`checks for axios@1.14.1, axios@0.30.4, plain-crypto-js IOCs\n`)

// lockfiles
console.log(`${Y}scanning lockfiles...${N}`)
for (const name of ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]) {
  const p = join(dir, name)
  if (!existsSync(p)) continues
  checked++
  let c
  try { c = readFileSync(p, "utf8") } catch { continue }
  info(`found ${name}`)
  c.includes("plain-crypto-js") ? hit(`${name} contains plain-crypto-js`) : ok(`${name} clean: no plain-crypto-js`)
  c.includes('"axios": "1.14.1"') || c.includes("axios@1.14.1") ? hit(`${name} contains axios@1.14.1`) : ok(`${name} clean: no axios@1.14.1`)
  c.includes('"axios": "0.30.4"') || c.includes("axios@0.30.4") ? hit(`${name} contains axios@0.30.4`) : ok(`${name} clean: no axios@0.30.4`)
}

// node_modules
console.log(`\n${Y}scanning node_modules...${N}`)
const nm = join(dir, "node_modules")
const pc = join(nm, "plain-crypto-js")

if (existsSync(pc)) {
  checked++
  hit("node_modules/plain-crypto-js exists")
  if (existsSync(join(pc, "setup.js"))) hit("setup.js dropper still present")
  try { if (readFileSync(join(pc, "package.json"), "utf8").includes('"postinstall"')) hit("postinstall hook in plain-crypto-js") } catch {}
  if (existsSync(join(pc, "package.md"))) hit("package.md found (self-destruct artifact)")
} else {
  checked++
  ok("no plain-crypto-js in node_modules")
}

const ap = join(nm, "axios", "package.json")
if (existsSync(ap)) {
  checked++
  try {
    const v = JSON.parse(readFileSync(ap, "utf8")).version
    v === "1.14.1" || v === "0.30.4" ? hit(`axios@${v} installed (compromised)`) : ok(`axios@${v} installed (not affected)`)
  } catch {}
}

// filesystem
console.log(`\n${Y}scanning filesystem...${N}`)
const os = platform()

if (os === "darwin") {
  checked++
  existsSync("/Library/Caches/com.apple.act.mond") ? hit("/Library/Caches/com.apple.act.mond exists (macOS RAT)") : ok("no macOS payload found")
}
if (os === "linux") {
  checked++
  existsSync("/tmp/ld.py") ? hit("/tmp/ld.py exists (linux RAT script)") : ok("no linux payload found")
}
if (os === "win32") {
  const pd = process.env.PROGRAMDATA
  if (pd) { checked++; existsSync(join(pd, "wt.exe")) ? hit(`${pd}/wt.exe exists (renamed powershell)`) : ok("no renamed powershell found") }
  const td = process.env.TEMP || tmpdir()
  if (existsSync(join(td, "6202033.ps1"))) { checked++; hit(`${td}/6202033.ps1 exists (windows RAT)`) }
  if (existsSync(join(td, "6202033.vbs"))) { checked++; hit(`${td}/6202033.vbs exists (VBScript launcher)`) }
}

// network
console.log(`\n${Y}checking C2 connectivity...${N}`)
checked++

await new Promise(resolve => {
  const sock = createConnection({ host: "142.11.206.73", port: 8000, timeout: 2000 })
  sock.on("connect", () => { hit("C2 server 142.11.206.73:8000 is reachable"); sock.destroy(); resolve() })
  sock.on("error", () => { ok("cannot reach C2 server (142.11.206.73:8000)"); resolve() })
  sock.on("timeout", () => { ok("cannot reach C2 server (142.11.206.73:8000)"); sock.destroy(); resolve() })
})

try {
  const ss = execSync("ss -tn 2>/dev/null", { encoding: "utf8" })
  ss.includes("142.11.206.73") ? hit("active connection to 142.11.206.73") : ok("no active connections to C2 IP")
} catch {}

// summary
console.log(`\n${B}scan complete${N}`)
console.log(`  checked: ${checked} items`)
hits > 0
  // x indicators
  ? console.log(`  ${R}${B}found ${hits} indicator(s) of compromise${N}\n`)
  : console.log(`  ${G}${B}no indicators of compromise found${N}\n`)

process.exit(hits > 0 ? 1 : 0)
