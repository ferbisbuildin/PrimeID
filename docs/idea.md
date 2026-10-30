PrimeID: Prove the Fact, Keep the Document
29 October 2026
Overview
PrimeID turns Passport Prime into a vault for signed credentials from any issuer, so a person can prove one fact, like “I’m over 18”, without handing over the document behind it. A verifier asks a question, Prime shows who is asking and exactly what will be shared, the user approves on the device, and Prime returns a signed answer bound to that one request.
Tagline: Prove the fact, keep the document.
Three things set it apart:
•	Issuer-agnostic. It holds credentials from governments, banks, employers, universities and exchanges, in any country.
•	Minimal disclosure. Only the requested claim leaves the device. Name, address and document number stay on Prime.
•	Hardware approval. The decision happens on Prime’s trusted screen, not on a phone or browser that may be compromised.
The global problem
People hand over whole documents to prove one small fact, and those documents no longer prove much.
•	Oversharing. To prove “I’m over 18” or “I live in this country”, people share a full ID with name, address, date of birth and document number.
•	AI forgeries. AI can produce a convincing ID image or PDF in seconds, so a photo or scan proves nothing on its own.
•	Policy pressure. Governments want age and identity checks, but done privately. On 26 June 2026 the G7 data protection authorities adopted a joint statement on privacy-preserving age assurance, saying it should not enable identification, tracking or profiling, and should collect only what is necessary (OPC Canada, summary).
•	Crypto KYC leaks. Exchanges, DeFi platforms and launchpads ask for passport uploads to central servers, which become targets and eventually leak.
The product
PrimeID is a KeyOS app with three jobs: store credentials safely, answer questions with the least data possible, and keep a record only the user can see.
1.	Receive. Prime scans a credential QR from an issuer, checks the issuer’s signature offline, and confirms the credential is bound to this device’s key. Valid credentials go into the app’s private storage.
2.	Answer. A verifier sends a signed request such as “prove over 18”. Prime shows the requester (verified or unknown), the exact claim asked for, and what will be shared. The user approves or denies on the device.
3.	Respond. Prime reveals only the requested claim, signs the answer with the key the credential is bound to, ties it to the request’s one-time nonce, and shows it as a QR.
4.	Remember. Every request is saved in a local privacy receipt log: who asked, what for, when, and what was shared.
PrimeID never needs the internet, a cloud account or a phone to work.
Why Prime, and how it fits with x401
The difference from phone wallets is air-gapped hardware, not “digital ID”. Apple, Google and the EU are all building phone ID wallets, and PrimeID does not compete on that.
•	Separate device. Prime doesn’t browse the web or run ordinary apps. Every connection (USB-C, NFC, camera, QuantumLink Bluetooth) is started by the user and visible.
•	Trusted screen. The approval is shown on Prime’s own display, not inside the phone or browser that is asking. Foundation describes this as moving the final decision onto hardware the user can see, hold and control (Foundation Enterprise).
•	Protected keys. Keys sit in Prime’s sandboxed app storage with a hardware secure element on the device (developer docs).
Positioning against x401 Approvals. Foundation’s showcase already has x401 Approvals: when a verifier asks an AI agent to prove personhood or authority, Prime shows the intent, claims and warnings for the user to approve or deny. PrimeID is complementary, not a copy:
•	x401 is the approval moment.
•	PrimeID is the vault behind it: where credentials live, how issuers are checked, and how little gets shared.
One line for the pitch: x401 asks the question, PrimeID holds the answer and shares only what’s needed. Supporting x401 requests is on the roadmap.
Security design
Eight protections close the gaps a simple “signed answer” design would leave open. The hackathon version covers holder binding, selective disclosure, replay protection, verified requesters and privacy receipts. The rest follow.
Protection	What it stops	How it works
Holder binding	A screenshot of a credential QR being loaded into a fake app	Prime shows its public key to the issuer first. The issuer signs that key into the credential, and the verifier checks the answer was signed by it.
Selective disclosure	Sharing name and country when only age was asked	The issuer signs a list of salted hashes, one per claim (the idea behind SD-JWT). Prime reveals only the requested claim and its salt.
Unlinkable presentations (roadmap)	Different sites linking the same user	Prime holds a batch of one-time credentials, each bound to a fresh key derived from the seed, and uses a different one per verifier.
Replay protection	Reusing an old answer, or relaying another site’s request	Each request carries a fresh nonce, the verifier’s identity and an expiry. Prime signs over all three.
Verified requesters	A phishing site pretending to be a bank	Verifiers sign their requests. Prime shows a green “verified” badge or a red “unknown requester” warning.
Seed-based recovery	Losing every credential with a lost device	PrimeID keys derive from the seed, as Foundation’s OpenPGP Keys app does for PGP keys, so a seed restore keeps holder-bound credentials working.
Expiry and revocation	Using a credential the issuer has cancelled	Credentials are short-lived. Prime picks up a signed revocation list whenever a new credential is scanned.
Privacy receipts	Not knowing who has seen your data	A local log of every request: requester, claim, time, and what was shared. Only the user can see it.
One honest limit: until batch credentials arrive, the issuer signature and the bound key are the same each time a credential is shown, so verifiers working together could link a user. Batch credentials or BBS+ signatures fix this.
Architecture
Three parties exchange four QR codes, and Prime never connects to the internet.
 
PrimeID architecture: 3 parties, 4 QR exchanges
The issuer binds the credential to Prime’s key (steps 1 and 2). The verifier’s signed request goes to Prime, which reveals one claim only after the user approves on its screen (steps 3 and 4).
Credential format (simplified). The issuer signs hashes, so Prime can later reveal one claim without exposing the rest:
{
  "issuer": "<issuer public key>",
  "holder": "<Prime's PrimeID public key>",
  "expires": "<date>",
  "claims": ["<hash(salt + over_18 + true)>", "<hash(salt + country + ...)>", "<hash(salt + name + ...)>"],
  "signature": "<issuer secp256k1 signature>"
}
Answer format. Prime sends the credential, the one revealed claim with its salt, the verifier’s nonce, and a signature from the holder key over all of it. The verifier checks the issuer signature, recomputes the claim’s hash, confirms the holder key signed the nonce, and checks the expiry.
Demo: one honest flow, four attacks that fail
The demo shows a real flow end to end, then four attacks failing live. Say clearly that the issuer is a demo issuer.
The flow
1.	Prime shows its PrimeID public key as a QR.
2.	The issuer page on the laptop scans it and issues a credential with claims such as over_18, country and name, signed with secp256k1 and bound to Prime’s key. It shows the credential as a QR.
3.	Prime scans the credential, verifies the issuer’s signature offline, and stores it.
4.	The verifier page shows a signed request: “prove over 18”, with a fresh nonce and expiry.
5.	Prime shows a green “verified requester” badge, the claim asked for, and “shared: over_18 only”. The user approves.
6.	Prime signs the answer with its bound key and shows it as a QR.
7.	The verifier checks the issuer signature, the holder binding, the disclosed claim and the nonce, then shows “Verified: over 18”.
8.	Prime’s privacy receipt log shows the new entry.
The four attacks
Attack	What happens	Check that stops it
Forged credential (the “AI fake ID”)	Credential made without the issuer’s key	Issuer signature fails
Copied credential in another app	Screenshot of a real credential QR	Holder binding fails
Replayed old answer	Yesterday’s valid answer sent again	Nonce check fails
Fake requester posing as a bank	Unsigned request with a bank’s name	Prime shows “unknown requester” in red
Real issuers: Passport on Passport, and a college pilot
The mock issuer proves the design works. These two additions prove it works with real issuers.
Passport on Passport (if NFC allows it)
Nearly every country’s e-passport follows the same ICAO standard, and its chip data is signed by the issuing government. If Prime can read the chip, PrimeID gets a real, global issuer without involving a phone.
1.	The user enters or scans the passport number, date of birth and expiry, which unlock the chip.
2.	Prime reads the chip over NFC and checks the government’s signature offline against that country’s signing certificate.
3.	PrimeID stores the verified data and answers questions like “over 18” or “citizen of a listed country” without showing the passport.
This is unconfirmed. Foundation lists NFC as hardware developers can use (developer page), and Prime already works with Keycards, which are NFC smart cards (Foundation). Whether third-party apps get the low-level card access a passport chip needs is the first question to ask Foundation’s team. Two more caveats: country signing certificates must be loaded onto Prime, and detecting a cloned chip needs extra checks.
College pilot: verified student credentials
A partner college issues “enrolled student” credentials to its students. Events then verify student status for student pricing without collecting ID card photos. Universities exist everywhere, so this stays global, and it shows PrimeID in real use rather than as a mockup.
Global use cases
Use case	Question asked	What the verifier learns
Age checks (online services, venues, events)	Is this person over 18?	Yes or no
Crypto compliance	Verified adult, not in a restricted region?	Yes or no, from a trusted issuer
Student pricing	Currently enrolled student?	Yes or no, from the college
P2P trading and marketplaces	Has this trader passed a check?	Yes or no, without documents
Remote work and rentals	Right to work, or income above a level?	Yes or no, without payslips or ID scans
AI agent requests (via x401)	Does a real, verified person stand behind this agent?	The minimum claim the request needs
Roadmap
1.	Hackathon version. Mock issuer and verifier pages, holder binding, selective disclosure, nonce-bound answers, verified requesters, privacy receipts, and the four-attack demo.
2.	Next. E-passport reading if NFC allows it, the college student credential pilot, and support for x401 requests.
3.	Later. Standard formats: W3C Verifiable Credentials, SD-JWT, OpenID4VP and the ISO mobile driver’s licence (these were described from memory, so check each spec). Then one-time batch or BBS+ credentials for full unlinkability, zero-knowledge proofs, and a phone companion over QuantumLink.
PrimeID will be fully open source, since catalog apps on Prime must be open source with reproducible builds.
Honest limits and open questions
Limits to state openly in the pitch:
•	The demo issuer is a mock. Everything else in the flow is real cryptography.
•	In v1 the verifier trusts the issuer’s signature plus Prime’s answer. Zero-knowledge proofs would be stronger, and they are not novel here: projects like zkPassport and Anon Aadhaar already exist.
•	The issuer signature and bound key repeat across verifiers, so they could link a user until batch or BBS+ credentials arrive.
•	Fully offline revocation is a hard problem. Short expiry is the v1 answer.
•	Apple, Google and the EU are building phone ID wallets. PrimeID’s difference is air-gapped hardware and the trusted screen.
Questions to confirm with Foundation’s team:
•	☐ Can third-party apps get the low-level NFC card access needed to read an e-passport chip?
•	☐ Can apps use the secure element directly, or only the app’s sandboxed key storage?
•	☐ Does KeyOS offer app or device attestation, so a verifier can tell the answer came from a real Prime?
•	☐ Can the simulator fake camera input for scanning QR codes during testing?
