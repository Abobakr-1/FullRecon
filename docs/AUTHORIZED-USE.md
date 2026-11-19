# Authorized use notice

FullRecon is licensed under the MIT License (see [LICENSE](../LICENSE)).

The MIT License grants broad freedom to use, modify and redistribute this
software. It does **not** grant permission to access any computer system.

## Intended use

FullRecon is a reconnaissance tool for:

- bug bounty programs, within the program's published scope and rules,
- penetration tests performed under a signed engagement or written permission,
- systems you own or operate,
- deliberately vulnerable lab environments you control.

## Prohibited use

Using FullRecon against systems you are not authorized to test may violate
criminal and civil law, including but not limited to:

- the Computer Fraud and Abuse Act (United States, 18 U.S.C. § 1030),
- the Computer Misuse Act 1990 (United Kingdom),
- the Cybercrime Act and equivalent statutes in the EU, Australia, Canada and
  elsewhere,
- the terms of service of the target's hosting provider.

You are solely responsible for:

1. obtaining explicit authorization before scanning,
2. staying inside the agreed scope and permitted techniques,
3. respecting rate limits and not disrupting the target,
4. handling any discovered data lawfully and confidentially,
5. reporting vulnerabilities only through the program's official channel.

The author accepts no liability for misuse of this software or for any damage
arising from its use. See the warranty disclaimer in [LICENSE](../LICENSE).

## Design safeguards

FullRecon enforces several limits by design, described in the README:

- scope (in-scope/out-of-scope domains and CIDRs) is checked before every
  connection,
- non-interactive runs require an explicit `--authorized` flag,
- requests are rate limited per host,
- discovered secrets are redacted and never used or validated,
- there is no exploitation, authentication bypass or credential testing.

These safeguards reduce accidental harm; they do not constitute authorization.