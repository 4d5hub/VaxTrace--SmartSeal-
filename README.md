 VaxTrace (SmartSeal) (FULLY FUNCTIONAL BACKEND PROJECT) 

VaxTrace is our project for Smart India Hackathon 2026 (problem statement 26211, Hardware, Blockchain and Cybersecurity). It is a small seal that travels with a vaccine shipment, plus the software that lets everyone who handled the shipment check afterwards that nobody quietly changed the record.

Device simulation on Wokwi: https://wokwi.com/projects/476501663960510465

 Why we built it

When a vaccine batch moves from manufacturer to transporter to warehouse to pharmacy, the temperature log is usually kept by whoever is carrying it. If the cooling fails on the road, that same person could edit the log. We wanted a record that all the parties can check and none of them can rewrite without getting caught.

India already has digital stock and temperature monitoring, eVIN for example. We are not saying it is broken and we are not trying to replace it. This is an extra layer for one narrow problem, which is disputes between organisations that hand over the same shipment. The scenario in our demo is hypothetical, we are not claiming it happens often.

## How it works

The seal records temperature from two probes, plus shock, light and whether the lid was opened. Every record carries the hash of the record before it, so changing or deleting an old one breaks the chain.

After a few records they are grouped into a batch. The batch gets a Merkle root, which is one short fingerprint for the whole group, and a secure element signs that root. Only the root, the signature and a few small facts go onto a shared ledger run by four parties: manufacturer, transporter, pharmacy and regulator. The raw readings stay off the chain.

At every handover the sender and the receiver both have to sign, and the contract refuses the transfer otherwise. At the destination a separate verifier service rebuilds everything from the raw records, compares it with what the ledger holds, and gives a verdict of ACCEPT, QUARANTINE or REJECT with the reasons.

The part that matters is the ledger. Say someone edits the readings and even recomputes the whole hash chain so it looks consistent. The Merkle root they end up with no longer matches the one the ledger already holds, and that is what gets caught.

 What is in the repo

gateway: the FastAPI service. It receives records, checks the hash chain, batches them, signs, handles custody and talks to the chain.

verifier: a separate service that runs 25 checks and produces the verdict. It never reads the gateway's database.

blockchain: four Solidity contracts and a P-256 signature library, the compile and deploy scripts, and a 4-validator Hyperledger Besu network in Docker.

integration: an in-process full stack, 16 attack scenarios, end-to-end tests and a script that plants sample data.

dashboard: one HTML file with a simulation mode and a real backend mode.

 Where things stand

The backend is fully functional. The gateway, the verifier and the contracts run end to end, and 87 automated tests cover them: 43 for the gateway, 19 for the contracts and 25 for integration and attack scenarios.

Some things are not real yet. The secure element is a software mock, and a physical ATECC608 chip is planned but not wired up. The automated tests run the contracts on an in-process EVM. The 4-node Besu network is set up and has start scripts, but it is not part of the automated tests and the Besu image is not pinned to a version. The sensors are simulated, either in Wokwi or by the seeding script. The accounts used for the four parties are for demos only. Their keys are derived from public text, so anyone can work them out, and they should never be used on a real network.

 Running it

You need Python 3.11 or newer. The Besu network also needs Docker Desktop with the WSL2 backend. Node.js is only needed if you want to recompile the contracts.

To run everything with the Besu network on Windows, run this from the project folder:

    demo.bat

It checks Docker, installs the requirements, generates the Besu keys and genesis, starts the four validators, deploys the contracts, starts the gateway on port 8000 and the verifier on port 8100, plants a shipment and opens the dashboard. In the dashboard switch to Real backend. The API key is demo-only-change-me.

If you don't have Docker, or it is giving you trouble, run this instead:

    demo_nodocker.bat

It uses the same contracts, gateway, custody and verifier, but on an in-process EVM instead of Besu. The API key there is stack-key. There is no validator network in this mode, so the Blockchain tab will say 0 of 4 validators are reachable. That is correct, nothing is wrong.

To run the tests:

    pip install -r requirements-dev.txt
    run_all_tests.bat

## The dashboard

Open dashboard/index.html by double-clicking it. A bar at the top switches between two modes.

Simulation mode needs nothing running. The hashes, signatures and Merkle roots are real and computed in your browser. The sensors, the secure element and the four validators are stand-ins. It has a short guide at the top, 16 attack and policy scenarios, a self-test, a guided demo and a vaccine cold chain case study.

Real backend mode reads the running gateway, chain and verifier. It has eight tabs: Hardware, Records, Cryptographic evidence, Custody, Blockchain, Attacks, Destination verifier and India case study.

A few things to know. Reading data does not need the API key, but every write does, and that includes records, custody, verification and the attack suite. With a wrong key the tabs still show data, and the buttons that write fail with a 401. The attack suite takes about a minute, because each scenario runs on its own fresh in-memory chain. If you put the HTML file online, visitors only get Simulation mode, since Real backend mode talks to a gateway on your own machine.

## Trying the main demo

Start demo.bat first. Then plant a shipment that has a real 10 minute temperature excursion:

    python integration\live_demo.py seed --shipment SHP-HOT --seal SEAL-HOT --hot 5,6

In the dashboard go to Destination verifier and press Run verification. You should get QUARANTINE with EXCURSION_SHORT. A short excursion means go and inspect the goods, not throw them away.

Now play the dishonest transporter. This command rewrites the hot readings and recomputes the whole hash chain:

    python integration\live_demo.py attack edit --shipment SHP-HOT

Run verification again. This time it is REJECT with MERKLE_MISMATCH. The hash chain looks fine, but the ledger still holds the root from before the edit.

For custody, open the Custody tab and try Only the sender signs, which gives NEED_BOTH_SIGNATURES, and Reuse an old nonce, which gives NONCE_REUSED.

## Wokwi and the ESP32

The Wokwi project simulates the device side only: the ESP32, two temperature probes, a motion sensor, a light sensor, a lid switch, an OLED, LEDs, a buzzer and an SD card. It builds its own hash chain and Merkle roots and marks the secure element as simulated. It does not send anything to the gateway yet, and its hash format is different from the gateway's, so the two don't work together as they stand.

If you want to connect real firmware, the gateway recomputes every hash and rejects any mismatch, so records have to be built exactly like this:

    {"lid":false,"light":false,"prevHash":"0","sealId":"SEAL-A1","seq":1,"shipmentId":"SHP-001","shock":0.20,"temperature1":5.20,"temperature2":5.30,"timestamp":"2026-01-01T00:05:00Z"}

The SHA-256 of that line is a79bd1e10c2b76264645634aa4daa4431a99dfc0177e206db2a2cac3b87e22dd. Keys are sorted, there is no whitespace, measured values have exactly two decimals, the timestamp is UTC, and the first prevHash is 0. POST it to /api/record with an X-API-Key header. Example requests and responses are in integration/sample_payloads.

Wokwi's WiFi reaches the internet but not your PC, so you would need a tunnel such as ngrok or Cloudflare Tunnel. Change SMARTSEAL_API_KEY first, because a public Wokwi project would expose the key.

## What it does not protect against

We would rather tell you up front than have you find out later.

A signature proves which device produced a reading, not that the reading is true. Two probes catch one fooled probe, but if both are fooled the same way the verdict is ACCEPT. Heating or cooling a probe, or pulling the key out of the chip with lab equipment, is outside what the software can see.

Two signatures show that two parties agree, not that they are honest. If three of the four validators collude they can rewrite the ledger. A malicious gateway cannot forge signatures and tampered evidence is still caught, but it can delay or hold back records.

Secure boot and signed firmware updates are not built. The registry admin can assign roles and revoke participants, and a real deployment would need shared governance for that. A single SQLite file is also not decentralised. The export and import endpoints let several parties each keep an audit copy, and the verifier can check a copy.

The policy values (2 to 8 degrees C, 15 minutes, 2.5 g, a 3 degree gap between probes, a 20 minute offline gap) are only illustrative. They are not medical or regulatory limits. They can be changed per shipment and their hash is stored on the chain.

## Settings

SMARTSEAL_API_KEY is the key required in the X-API-Key header for writes. The default is demo-only-change-me, so change it before exposing the gateway to anyone.

SMARTSEAL_BATCH_SIZE is how many records go into a batch. The default is 4.

SMARTSEAL_CHAIN set to off runs the gateway without a chain, and records just queue up.

SMARTSEAL_RPC_URL picks the JSON-RPC endpoint. By default it comes from deployment.json.

BESU_IMAGE is the Besu Docker image, hyperledger/besu:latest by default. Pin a version you have checked.

## If something goes wrong

If it says Docker is not running, start Docker Desktop and give it a minute, or use demo_nodocker.bat.

If the network never produces blocks, at least three of the four containers have to be up. Try blockchain\reset_network.bat and then blockchain\start_network.bat.

If the dashboard says DISCONNECTED, the gateway isn't running or the URL or port is wrong. If writes return 401, the API key in the dashboard doesn't match the gateway's.

If a port is already in use, find the process with netstat -ano and stop it. The ports are 8000 for the gateway, 8100 for the verifier and 8545 to 8548 for the Besu nodes.

The gateway also serves its own API docs at http://127.0.0.1:8000/docs.

## Team

Cerebro Tech, Smart India Hackathon 2026.
