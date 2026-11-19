# Publishing FullRecon to GitHub

The repository in this directory is already initialised, committed and pointed
at `https://github.com/Abobakr-1/FullRecon.git`. Only the push is left, because
pushing requires **your** GitHub authentication.

## 1. Move the project somewhere permanent

This working copy lives in the agent build directory, which can be replaced by a
tool update. Copy it to a normal location first.

**Windows (PowerShell):**

```powershell
robocopy "C:\Users\PC\AppData\Local\alphacode\builds\current\FullRecon" "C:\Users\PC\Projects\FullRecon" /E
cd C:\Users\PC\Projects\FullRecon
git status
```

**Linux / WSL:**

```bash
cp -r "/mnt/c/Users/PC/AppData/Local/alphacode/builds/current/FullRecon" ~/FullRecon
cd ~/FullRecon
git status
```

If `git status` shows a clean tree, the `.git` directory came along and your
commit history is intact.

If you copied the files *without* `.git`, recreate the repository:

```bash
git init
git add -A
git commit -m "FullRecon 1.0.0: automated reconnaissance framework"
git branch -M main
git remote add origin https://github.com/Abobakr-1/FullRecon.git
```

## 2. Create the repository on GitHub

Either use the web UI — **github.com → New repository → name `FullRecon` → Public
→ do not add a README, .gitignore or license** (the repo already has them) — or
use the CLI:

```bash
gh auth login                       # follow the browser flow
gh repo create Abobakr-1/FullRecon --public --source=. --remote=origin --push
```

`gh repo create --push` performs step 3 for you.

## 3. Push

```bash
git push -u origin main
```

### Authentication

Use one of these. **Never paste a password or token into a chat.**

| Method | How |
|---|---|
| **GitHub CLI** (easiest) | `gh auth login`, choose *HTTPS*, authenticate in the browser. `gh` stores the credential for you. |
| **Git Credential Manager** | Just run `git push`. On Windows it opens a browser window; on Linux install `git-credential-manager`. |
| **SSH key** | `ssh-keygen -t ed25519 -C "you@example.com"`, add `~/.ssh/id_ed25519.pub` to *GitHub → Settings → SSH and GPG keys*, then `git remote set-url origin git@github.com:Abobakr-1/FullRecon.git` and push. |
| **Personal access token** | Fine-grained token with *Contents: Read and write* for this repo. When git prompts for a password, paste the token. Do not save it in a file in this repo. |

Windows note: Git for Windows bundles Credential Manager, so a plain `git push`
usually opens a browser sign-in window.

## 4. Verify the upload

```bash
git ls-remote origin            # should list HEAD and refs/heads/main
git log --oneline -n 3
git status                      # "Your branch is up to date with 'origin/main'"
```

Then open <https://github.com/Abobakr-1/FullRecon> and confirm:

- [ ] README renders with the banner, feature table, installation and usage.
- [ ] `install.sh` shows as executable (mode 100755).
- [ ] `LICENSE`, `CONTRIBUTING.md`, `config/`, `docs/`, `tests/`, `wordlists/` are present.
- [ ] `FullRecon-Results/`, `results/`, `__pycache__/`, `*.egg-info/` are **absent**.
- [ ] No `.env`, token, credential or personal configuration file is present.

## 5. Recommended repository settings

```
Description : Automated reconnaissance framework for bug bounty hunters
              and authorized penetration testers
Website     : (leave empty)
Topics      : recon bugbounty security-tools osint subdomain-enumeration
              pentesting python cybersecurity infosec dns-enumeration
License     : MIT (already in LICENSE)
```

Then:

- **Settings → General → Features**: enable *Issues* and *Discussions* if you
  want them; disable *Wiki* unless you plan to use it.
- **Settings → Branches → Add branch protection rule** for `main` once you have
  collaborators: require pull requests and a passing `pytest` check.
- **Actions** (optional): add `.github/workflows/tests.yml`:

```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.11", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: pytest -q
```

The suite needs no network or external tools, so it runs cleanly in CI.

## 6. Tag the release (optional)

```bash
git tag -a v1.0.0 -m "FullRecon 1.0.0"
git push origin v1.0.0
```

Then **Releases → Draft a new release → choose tag v1.0.0**, and paste the
highlights from the commit message.

## 7. Screenshots for the README

The `assets/` directory already contains real captured output:

| File | Contents |
|---|---|
| `assets/sample-terminal-output.txt` | An actual `fullrecon -d scanme.nmap.org` run |
| `assets/sample-summary.txt` | The `summary.txt` that run produced |
| `assets/sample-report.html` | The HTML report it produced |
| `assets/help-output.txt` | `fullrecon --help` |
| `assets/modules-output.txt` | `fullrecon --list-modules` |

To add images, take a terminal screenshot of a run (Windows Terminal: `Alt+Print`,
or `Win+Shift+S`), save as `assets/screenshot-scan.png`, and add:

```markdown
![FullRecon scan](assets/screenshot-scan.png)
```

Do not fabricate screenshots. The text files above are genuine captures, which
is why the README quotes them instead of promising images.

## 8. If the push is rejected

| Message | Cause | Fix |
|---|---|---|
| `remote: Repository not found` | Repo does not exist yet, or the token lacks access | Create it on GitHub, or check the token's repository access |
| `Updates were rejected because the remote contains work` | You initialised GitHub with a README | `git pull --rebase origin main` then push |
| `Permission denied (publickey)` | SSH key not registered | Use HTTPS, or add the key to GitHub |
| `Authentication failed` | Wrong or expired credential | `gh auth login` again, or clear Credential Manager entry for github.com |
| `fatal: not a git repository` | You copied files without `.git` | Follow the "recreate the repository" block in step 1 |