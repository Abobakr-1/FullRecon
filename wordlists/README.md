# Wordlists

| File | Use with | Contents |
|---|---|---|
| `subdomains.txt` | `--subdomain-wordlist wordlists/subdomains.txt --bruteforce` | Common subdomain labels |
| `directories.txt` | `--wordlist wordlists/directories.txt` | Directories and files for content discovery |

The built-in default wordlist lives in `fullrecon/data/content_wordlist.txt` and
is used when `--wordlist` is not supplied.

For deeper coverage, point `--wordlist` at a larger list such as SecLists
`Discovery/Web-Content/raft-medium-directories.txt`. Large lists are slow: keep
`--rate-limit` modest so the target stays healthy and you stay inside the
program's rules.
