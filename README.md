# SBOM-Generator

A powerful Python tool to generate Software Bill of Materials (SBOM) for projects in multiple programming languages. It parses dependency files, checks for vulnerabilities, outdated dependencies, and generates a CycloneDX JSON SBOM and Markdown report.

![Photo](https://github.com/Shok32/SBOM-Generator/blob/main/SBOM.png)

Commands in the therminal:
![Photo](https://github.com/Shok32/SBOM-Generator/blob/main/Commands.png)

## Features
- Supported Languages: Python (requirements.txt, poetry.lock), JavaScript (package.json), Ruby (Gemfile.lock), Java (pom.xml), PHP (composer.json), Go (go.mod), Swift (Package.swift).
- Vulnerability Scanning: Checks vulnerabilities via OSV API and GitHub Advisory Database (GraphQL).
- Outdated Dependencies: Identifies outdated packages for PyPI and npm with update commands.
- License Information: Extracts license details for PyPI and npm packages.
- Output: Generates a CycloneDX JSON SBOM (sbom.json) and a Markdown report (report.md).
- Rich Console Output: Displays results in colorful tables using the rich library.

## Installation

1. Clone the repository:

   git clone https://github.com/YOUR_USERNAME/SBOM-Generator.git
   cd SBOM-Generator
   
   Install dependencies:
   
 pip install -r requirements.txt 
 (Optional) Obtain API keys: 

OSV API Key: Create at Google Cloud Console for vulnerability scanning. 
 
GitHub Token: Generate at GitHub Settings with repo scope for Advisory Database. 
 Usage 
Run the tool with the following command: 

 python SBOM.py --path <project_dir> --output sbom.json --report report.md [options]

 Command-Line Options
| Flag | Description | Example |
|----------|----------|----------|
| --path    | Path to the project directory containing dependency files (default: .)   | --path ./my-project   |
| --output    |  Output path for the SBOM JSON file (default: sbom.json)  |  --output sbom.json |
| --report    | Output path for the Markdown report   | --report report.md   |
| --check-vulns    | Enable vulnerability scanning via OSV and GitHub Advisory   | --check-vulns    |
| --check-outdated    | Check for outdated dependencies (PyPI, npm)   | --check-outdated   |
| --osv-api-key    | OSV API key for vulnerability scanning   | --osv-api-key YOUR_KEY   |
| --github-token    | GitHub token for Advisory Database   | --github-token ghp_...   |
| --proxy    | HTTP/HTTPS proxy (e.g.,http://proxy:8080)   | --proxy http://proxy:8080  |
| --verbose    | Enable detailed logging   | --verbose   |

Examples 
Basic SBOM generation: 

 python SBOM.py --path ./examples --output sbom.json --report report.md --verbose 
 
 With vulnerability and outdated checks: 
 
 python SBOM.py --path ./examples --output sbom.json --check-vulns --check-outdated --report report.md --osv-api-key YOUR_OSV_KEY --github-token YOUR_GITHUB_TOKEN --verbose 
 
 Using a proxy: 
 
 python SBOM.py --path ./examples --output sbom.json --check-vulns --proxy http://proxy:8080 --verbose

 Supported Dependency Files 
Python: requirements.txt, poetry.lock 
 
JavaScript: package.json 
 
Ruby: Gemfile.lock 
 
Java: pom.xml 
 
PHP: composer.json 
 
Go: go.mod 
 
Swift: Package.swift 
 Example Output 
plaintext 
 SBOM Results
              Dependencies
| Name  | Version  | Ecosystem | License  |
|:------------- |:---------------:|:-------------:| -------------:|
|requests       │ 2.31.0          │ pypi          │ Apache        |
|express        │ 4.18.2          │ npm           │ MIT           │
|monolog/monolog│ 2.9.1           │ composer      │ Unknown       │
| github.com/gorilla/mux│ 1.8.0   │ golang        │ Unknown       │
Contributing 

Feel free to open issues or submit pull requests. Suggestions for new features (e.g., additional languages, GUI) are welcome! 
License 

This project is licensed under the MIT License. See the LICENSE file for details.
Contact 

Created by Shok32 - feel free to reach out via GitHub issues.
