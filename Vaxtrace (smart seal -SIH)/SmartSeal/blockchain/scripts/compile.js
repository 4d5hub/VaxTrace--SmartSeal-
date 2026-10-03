const solc = require("solc");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const cdir = path.join(root, "contracts");
const sources = {};
(function walk(dir, prefix) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (fs.statSync(p).isDirectory()) walk(p, prefix + f + "/");
    else if (f.endsWith(".sol")) sources[prefix + f] = { content: fs.readFileSync(p, "utf8") };
  }
})(cdir, "");

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true,
    evmVersion: "london",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
  },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
let failed = false;
for (const e of out.errors || []) {
  console.log((e.severity === "error" ? "ERROR " : "warning ") + e.formattedMessage.trim());
  if (e.severity === "error") failed = true;
}
if (failed) process.exit(1);

fs.mkdirSync(path.join(root, "artifacts"), { recursive: true });
for (const [file, contracts] of Object.entries(out.contracts)) {
  for (const [name, c] of Object.entries(contracts)) {
    fs.writeFileSync(
      path.join(root, "artifacts", name + ".json"),
      JSON.stringify({ contractName: name, source: file, abi: c.abi, bytecode: "0x" + c.evm.bytecode.object,
                       deployedBytecodeSize: c.evm.deployedBytecode.object.length / 2 }, null, 1));
    console.log(`compiled ${name} (${c.evm.deployedBytecode.object.length / 2} bytes deployed)`);
  }
}
