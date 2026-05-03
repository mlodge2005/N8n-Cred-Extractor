# Help guide: N8n Cred Extractor

**For people and for AI assistants:** If you are an AI reading this document, treat it as the official user guide for the **N8n Cred Extractor** project. Your job is to help the user follow these steps on their own computer, in plain language, and to remind them of the **limitations** section so they do not misunderstand what the tool can see.

**Project home on GitHub:** [https://github.com/johndoe/N8n-Cred-Extractor](https://github.com/johndoe/N8n-Cred-Extractor)

---

## What this program does (in everyday language)

This is a small **helper program** that reads **exported n8n workflow files** (the kind you save as `.json` from the n8n admin area). It does **not** connect to n8n over the internet and does **not** log into anyone’s account.

It does two main things:

1. **Lists credential “bookmarks”**  
   In an export, n8n usually stores *which saved credential* a node uses (a name and an internal id). That is like a label pointing at a locker; it is **not** the same as the password or API key sitting inside the locker.

2. **Looks for secrets typed directly into the workflow**  
   Sometimes a password, API key, or similar value was pasted into a node’s settings. If that text is actually present inside the JSON file, the program can copy those values into a spreadsheet-style report.

The end result is a **CSV file** (opens in Excel, Google Sheets, and similar apps) so you can review, clean up, or rotate credentials in one place.

---

## What you need on your computer

- A copy of this project folder on your machine (see the **footer** for how to get it from GitHub).
- **Node.js** installed (the same kind of “runtime” many small developer tools use). If you are not sure, ask your AI assistant or IT helper: “Do I have Node.js installed?” The project expects a normal current Node.js version; if `npm install` works, you are usually fine.

---

## How the program runs (step by step)

1. You tell the program **where your workflow JSON files live** and **where to save the report**, using a small settings file named `.env` (see footer).
2. You open a terminal in the project folder (on Windows this is often **PowerShell** or **Command Prompt**; on Mac/Linux, **Terminal**).
3. You run **one command** that installs dependencies the first time (`npm install`), and another command that runs the extractor (`npm run extract:n8n-creds`). The exact commands are in the project’s `README.md` and repeated in the footer below.
4. The program walks through the folder you chose, opens each `.json` file, checks whether it looks like an n8n workflow, reads each node, and builds rows for the spreadsheet.
5. When it finishes, it prints a **short summary** (counts only). It is written **not** to print your secret values on the screen, so you are less likely to accidentally expose them in a screenshot or screen share.
6. You open the **clean** CSV in your spreadsheet app for the main list, and optionally the **review** CSV if you want to double-check filtered rows.

---

## What the columns in the CSV mean (simple version)

| Column            | Plain meaning |
|-------------------|----------------|
| **Owner**         | Always set to “N8n” for this tool. |
| **Service**       | The type of integration or credential name when known. |
| **Account**       | Often the friendly name n8n shows for a saved credential. |
| **URL**           | Filled when the tool thinks the finding is tied to a web address. |
| **Username / Email / Phone** | Filled only when the text clearly looks like that kind of value. |
| **Password**      | Used for **literal** secrets found in the JSON. For normal n8n credential “bookmarks,” this is usually **empty** on purpose. |
| **Miscellaneous** | Technical breadcrumbs: which file, which workflow, which node, which field path, and sometimes a credential id. |
| **Notes**         | A short label such as “n8n credential reference” or “hardcoded API key” so you know what kind of row it is. |

---

## Important limitations (please read this)

- **Exports are not the same as n8n’s secret vault.**  
  Saved credentials in n8n Cloud or on a server are stored securely. A workflow export normally contains **references** (name/id), **not** decrypted passwords or OAuth tokens. Do not assume the CSV will list every secret n8n “knows”; it lists what appears in the **files you exported**.

- **The tool can miss secrets.**  
  Secrets inside expressions, code nodes, or unusual field names might not be detected. This is pattern-based, not magic.

- **The tool can sometimes flag things that are not secrets.**  
  For example, long IDs that look “random” might appear even when they are just document or resource identifiers. Always use human judgment before rotating or deleting anything.

- **It only reads files you point it at.**  
  If your workflows are not in the folder you configured, they will not appear in the report.

- **n8n versions change over time.**  
  This project was built and tested in an environment where **n8n was version 2.18.5**. Newer or older n8n versions may export JSON in slightly different shapes. The tool may still work, but if something looks wrong, compare with a fresh export from your current n8n version.

- **Not a security audit or legal advice.**  
  This is a convenience tool for inventory and cleanup. It does not replace professional security review, compliance work, or your organization’s policies.

---

## Using this document with an AI (LLM)

You may upload **this entire HELP.md file** to an AI chat and say something like:

> “Read HELP.md and walk me through setting this up on my computer. Ask me what operating system I use and where I saved my n8n JSON exports.”

A good AI answer should: confirm Node.js, guide you to clone or download the repo, help you create `.env` from `.env.example`, and remind you that **credential references are not the same as decrypted secrets**.

---

## Footer: Get the project from GitHub and set up `.env`

### Part A — Get a copy onto your device

**Option 1 — Download as a ZIP (easiest if you do not use Git)**

1. Open the repository in your browser: [https://github.com/johndoe/N8n-Cred-Extractor](https://github.com/johndoe/N8n-Cred-Extractor)
2. Click the green **Code** button, then choose **Download ZIP**.
3. Unzip the file somewhere you can find it, for example your **Documents** folder or **Downloads**.
4. Remember the **full path** to that unzipped folder (you will need it when opening a terminal “inside” that folder).

**Option 2 — Clone with Git (if you already use Git)**

1. Install Git if you do not have it (from [https://git-scm.com](https://git-scm.com) or your usual method).
2. In a terminal, go to the parent folder where you want the project to live, then run:

   ```bash
   git clone https://github.com/johndoe/N8n-Cred-Extractor.git
   cd N8n-Cred-Extractor
   ```

### Part B — Create your `.env` settings file

1. Inside the project folder, find the file named **`.env.example`**.  
2. **Make a copy** of it and rename the copy to **`.env`** (exactly that name, starting with a dot).  
   - On Windows, if File Explorer complains about the name, you can create it in Notepad: save as `.env` with “All files” as the type, or ask an AI for the exact clicks for your Windows version.
3. Open **`.env`** in a text editor. You should see lines like:

   - **`N8N_WORKFLOWS_DIR=`**  
     Put the path to the folder that contains your **exported n8n workflow `.json` files** (and any subfolders you want included).  
     - You may use a **relative** path from the project folder (for example `marcuslodge-workflows/marcuslodge-workflows`) or a **full** path (for example `C:\Users\YourName\Documents\n8n-exports`).  
     - Use the style of slashes your examples use: Windows often accepts `\` or `/` in paths inside `.env`.

   - **`OUTPUT_CSV=`**  
     Path for the **high-confidence** report (`n8n-credentials-clean.csv` by default).

   - **`REVIEW_CSV=`**  
     Path for **borderline** detections you may want to check by hand (`n8n-credentials-review.csv` by default). That file has an extra **Reason** column explaining why something was not promoted to the clean file.

   - **`EXTRACTION_MODE=`**  
     Use **`strict`** (default) for only strong, node-aware matches, or **`loose`** for broader scanning with more noise.

4. Save the file.

### Part C — Install and run (same on Windows / Mac / Linux, small path differences)

1. Open a terminal **in the project folder** (the same folder as `package.json`).
2. Run:

   ```bash
   npm install
   ```

   Wait until it finishes without errors.

3. Run:

   ```bash
   npm run extract:n8n-creds
   ```

4. Read the summary in the terminal, then open the CSV path it prints (or the path you set in `OUTPUT_CSV`) in Excel or another spreadsheet program.

If anything fails, copy the **error message text** (not your secret values) into a message to a technical friend or to an AI, along with which step you were on.

---

*This help file describes the N8n Cred Extractor maintained at [https://github.com/johndoe/N8n-Cred-Extractor](https://github.com/johndoe/N8n-Cred-Extractor). Workflow export behavior depends on your n8n edition and version; this guide assumes familiarity with exporting workflows from the n8n admin console.*
