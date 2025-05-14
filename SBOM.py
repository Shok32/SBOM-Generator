import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict
from xml.etree import ElementTree as ET

import requests
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.output.json import JsonV1Dot4
from packageurl import PackageURL
from rich.console import Console
from rich.table import Table
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import requirements
from toml import load as toml_load

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Инициализация rich для цветного вывода
console = Console()

class SBOMGenerator:
    """Класс для генерации SBOM, проверки уязвимостей и устаревших зависимостей."""

    def __init__(
        self,
        project_path: str,
        check_vulns: bool = False,
        check_outdated_enabled: bool = False,
        osv_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
        proxy: Optional[str] = None
    ):
        self.project_path = Path(project_path)
        self.check_vulns = check_vulns
        self.check_outdated_enabled = check_outdated_enabled
        self.osv_api_key = osv_api_key
        self.github_token = github_token
        self.bom = Bom()
        self.vulnerabilities: Dict[str, List[Dict]] = {}
        self.outdated: Dict[str, Dict] = {}
        self.licenses: Dict[str, str] = {}
        self.cache_file = self.project_path / "sbom_cache.json"
        self.cache = self._load_cache()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0"
        })
        if self.osv_api_key:
            self.session.headers["Authorization"] = f"Bearer {self.osv_api_key}"
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _load_cache(self) -> Dict:
        """Загрузка кэша API-ответов."""
        try:
            if self.cache_file.exists():
                with self.cache_file.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка загрузки кэша: {e}")
        return {"vulnerabilities": {}, "outdated": {}, "licenses": {}}

    def _save_cache(self):
        """Сохранение кэша API-ответов."""
        try:
            with self.cache_file.open("w", encoding="utf-8") as f:
                json.dump({
                    "vulnerabilities": self.vulnerabilities,
                    "outdated": self.licenses
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Ошибка сохранения кэша: {e}")

    def parse_requirements(self, file_path: Path) -> List[Component]:
        """Парсинг requirements.txt (Python)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                for req in requirements.parse(f):
                    if req.name:
                        version = req.specs[0][1] if req.specs else None
                        purl = PackageURL(type="pypi", name=req.name, version=version) if version else None
                        component = Component(name=req.name, version=version, purl=purl)
                        components.append(component)
                        logger.info(f"Добавлена зависимость (Python): {req.name}=={version or 'unknown'}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_poetry_lock(self, file_path: Path) -> List[Component]:
        """Парсинг poetry.lock (Python)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                poetry_data = toml_load(f)
                for package in poetry_data.get("package", []):
                    name = package.get("name")
                    version = package.get("version")
                    if name and version:
                        purl = PackageURL(type="pypi", name=name, version=version)
                        component = Component(name=name, version=version, purl=purl)
                        components.append(component)
                        logger.info(f"Добавлена зависимость (Python): {name}=={version}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_package_json(self, file_path: Path) -> List[Component]:
        """Парсинг package.json (JavaScript)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                package_data = json.load(f)
                for dep_type in ["dependencies", "devDependencies"]:
                    for name, version in package_data.get(dep_type, {}).items():
                        version = version.lstrip("^~") if version else None
                        purl = PackageURL(type="npm", name=name, version=version) if version else None
                        component = Component(name=name, version=version, purl=purl)
                        components.append(component)
                        logger.info(f"Добавлена зависимость (JavaScript): {name}=={version or 'unknown'}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_gemfile_lock(self, file_path: Path) -> List[Component]:
        """Парсинг Gemfile.lock (Ruby)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
                in_specs = False
                for line in lines:
                    if line.strip() == "GEM":
                        in_specs = True
                        continue
                    if in_specs and line.strip() == "":
                        in_specs = False
                        continue
                    if in_specs and line.strip().startswith("  "):
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1].startswith("(") and parts[1].endswith(")"):
                            name = parts[0]
                            version = parts[1].strip("()")
                            purl = PackageURL(type="rubygems", name=name, version=version)
                            component = Component(name=name, version=version, purl=purl)
                            components.append(component)
                            logger.info(f"Добавлена зависимость (Ruby): {name}=={version}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_pom_xml(self, file_path: Path) -> List[Component]:
        """Парсинг pom.xml (Java)."""
        components = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//mvn:dependency", ns):
                group_id = dep.find("mvn:groupId", ns)
                artifact_id = dep.find("mvn:artifactId", ns)
                version = dep.find("mvn:version", ns)
                if group_id is None or artifact_id is None:
                    logger.warning(f"Пропущена зависимость в {file_path}: отсутствует groupId или artifactId")
                    continue
                name = f"{group_id.text}:{artifact_id.text}"
                version_text = version.text if version is not None else None
                purl = PackageURL(
                    type="maven",
                    namespace=group_id.text,
                    name=artifact_id.text,
                    version=version_text
                ) if version_text else None
                component = Component(name=name, version=version_text, purl=purl)
                components.append(component)
                logger.info(f"Добавлена зависимость (Java): {name}=={version_text or 'unknown'}")
        except ET.ParseError as e:
            logger.error(f"Ошибка парсинга XML в {file_path}: {e}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_composer_json(self, file_path: Path) -> List[Component]:
        """Парсинг composer.json (PHP)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                composer_data = json.load(f)
                for dep_type in ["require", "require-dev"]:
                    for name, version in composer_data.get(dep_type, {}).items():
                        version = version.lstrip("^~") if version else None
                        purl = PackageURL(type="composer", name=name, version=version) if version else None
                        component = Component(name=name, version=version, purl=purl)
                        components.append(component)
                        logger.info(f"Добавлена зависимость (PHP): {name}=={version or 'unknown'}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_go_mod(self, file_path: Path) -> List[Component]:
        """Парсинг go.mod (Go)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
                in_require = False
                for line in lines:
                    line = line.strip()
                    if line == "require (":
                        in_require = True
                        continue
                    if in_require and line == ")":
                        in_require = False
                        continue
                    if in_require or (line.startswith("require ") and not in_require):
                        parts = line.replace("require ", "").strip().split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            purl = PackageURL(type="golang", name=name, version=version)
                            component = Component(name=name, version=version, purl=purl)
                            components.append(component)
                            logger.info(f"Добавлена зависимость (Go): {name}=={version}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    def parse_package_swift(self, file_path: Path) -> List[Component]:
        """Парсинг Package.swift (Swift)."""
        components = []
        try:
            with file_path.open("r", encoding="utf-8") as f:
                content = f.read()
                # Ищем зависимости в формате .package(name: "...", url: "...", from: "...")
                import re
                dep_pattern = r'\.package\s*\(\s*(name:\s*"([^"]+)".*?)?url:\s*"[^"]+",\s*from:\s*"([^"]+)"\s*\)'
                matches = re.findall(dep_pattern, content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    name = match[1] if match[1] else match[2].split("/")[-1].replace(".git", "")
                    version = match[2]
                    purl = PackageURL(type="swift", name=name, version=version) if version else None
                    component = Component(name=name, version=version, purl=purl)
                    components.append(component)
                    logger.info(f"Добавлена зависимость (Swift): {name}=={version or 'unknown'}")
        except Exception as e:
            logger.error(f"Ошибка при парсинге {file_path}: {e}")
        return components

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type((requests.RequestException,)),
    )
    def check_vulnerabilities(self, components: List[Component]) -> None:
        """Проверка уязвимостей через OSV API и GitHub GraphQL API."""
        if not self.check_vulns:
            return

        for component in components:
            ecosystem = {
                "pypi": "PyPI",
                "npm": "npm",
                "rubygems": "RubyGems",
                "maven": "Maven",
                "composer": "Composer",
                "golang": "Go",
                "swift": "Swift"
            }.get(component.purl.type if component.purl else "pypi")
            if not ecosystem:
                continue
            dep_key = f"{component.name}=={component.version}"

            # Проверка кэша
            if dep_key in self.vulnerabilities:
                logger.info(f"Использован кэш уязвимостей для {dep_key}")
                continue

            # Проверка через OSV API
            if self.osv_api_key:
                try:
                    response = self.session.post(
                        "https://api.osv.dev/v1/query",
                        json={
                            "package": {"name": component.name, "ecosystem": ecosystem},
                            "version": component.version,
                        },
                        timeout=10,
                    )
                    response.raise_for_status()
                    vulns = response.json().get("vulns", [])
                    if vulns:
                        self.vulnerabilities[dep_key] = vulns
                        logger.warning(f"Обнаружены уязвимости для {dep_key}: {len(vulns)}")
                except requests.HTTPError as e:
                    if e.response.status_code == 403:
                        logger.error(
                            f"Ошибка 403 для {dep_key}: Доступ к OSV API запрещён. Проверьте API-ключ."
                        )
                    else:
                        logger.error(f"Ошибка OSV API для {dep_key}: {e}")
                except requests.RequestException as e:
                    logger.error(f"Сетевая ошибка OSV API для {dep_key}: {e}")
            else:
                logger.warning(f"OSV API-ключ не указан, пропускаем проверку для {dep_key}")

            # Проверка через GitHub GraphQL API
            if self.github_token:
                try:
                    query = """
                    query($ecosystem: SecurityAdvisoryEcosystem, $name: String!) {
                        securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $name) {
                            nodes {
                                advisory {
                                    ghsaId
                                    summary
                                    description
                                    identifiers {
                                        type
                                        value
                                    }
                                }
                                vulnerableVersionRange
                            }
                        }
                    }
                    """
                    variables = {
                        "ecosystem": ecosystem.upper(),
                        "name": component.name
                    }
                    response = self.session.post(
                        "https://api.github.com/graphql",
                        json={"query": query, "variables": variables},
                        timeout=10
                    )
                    response.raise_for_status()
                    data = response.json()
                    if "errors" in data:
                        logger.error(f"GraphQL ошибка для {dep_key}: {data['errors']}")
                        continue

                    vulnerabilities = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
                    github_vulns = []
                    for vuln in vulnerabilities:
                        version_range = vuln.get("vulnerableVersionRange", "")
                        if component.version in version_range or component.version == version_range:
                            advisory = vuln.get("advisory", {})
                            cve = next(
                                (id["value"] for id in advisory.get("identifiers", []) if id["type"] == "CVE"),
                                "N/A"
                            )
                            github_vulns.append({
                                "id": advisory.get("ghsaId", "N/A"),
                                "summary": advisory.get("summary", ""),
                                "details": advisory.get("description", ""),
                                "cve": cve
                            })
                    if github_vulns:
                        self.vulnerabilities.setdefault(dep_key, []).extend(github_vulns)
                        logger.warning(f"GitHub: Обнаружены уязвимости для {dep_key}: {len(github_vulns)}")
                except requests.RequestException as e:
                    logger.error(f"Ошибка GitHub GraphQL API для {dep_key}: {e}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type((requests.RequestException,)),
    )
    def check_outdated(self, components: List[Component]) -> None:
        """Проверка устаревших зависимостей через PyPI или npm API."""
        if not self.check_outdated_enabled:
            return

        for component in components:
            if not component.version:
                continue
            dep_key = f"{component.name}=={component.version}"

            # Проверка кэша
            if dep_key in self.outdated:
                logger.info(f"Использован кэш устаревших для {dep_key}")
                continue

            try:
                if component.purl and component.purl.type == "pypi":
                    response = self.session.get(f"https://pypi.org/pypi/{component.name}/json", timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    latest_version = data["info"]["version"]
                    license_info = data["info"].get("license", "Unknown")
                    if latest_version != component.version:
                        self.outdated[dep_key] = {
                            "latest_version": latest_version,
                            "ecosystem": "PyPI",
                            "update_cmd": f"pip install {component.name}=={latest_version}"
                        }
                        logger.warning(
                            f"Зависимость устарела: {dep_key} (последняя: {latest_version})"
                        )
                    self.licenses[dep_key] = license_info
                elif component.purl and component.purl.type == "npm":
                    response = self.session.get(f"https://registry.npmjs.org/{component.name}", timeout=10)
                    response.raise_for_status()
                    latest_version = response.json()["dist-tags"]["latest"]
                    license_info = response.json().get("license", "Unknown")
                    if latest_version != component.version:
                        self.outdated[dep_key] = {
                            "latest_version": latest_version,
                            "ecosystem": "npm",
                            "update_cmd": f"npm install {component.name}@{latest_version}"
                        }
                        logger.warning(
                            f"Зависимость устарела: {dep_key} (последняя: {latest_version})"
                        )
                    self.licenses[dep_key] = license_info
            except requests.RequestException as e:
                logger.error(f"Ошибка при проверке версии для {dep_key}: {e}")

    def generate_sbom(self) -> None:
        """Генерация SBOM на основе зависимостей для всех поддерживаемых экосистем."""
        files = {
            "Python": [
                self.project_path / "requirements.txt",
                self.project_path / "poetry.lock",
            ],
            "JavaScript": [self.project_path / "package.json"],
            "Ruby": [self.project_path / "Gemfile.lock"],
            "Java": [self.project_path / "pom.xml"],
            "PHP": [self.project_path / "composer.json"],
            "Go": [self.project_path / "go.mod"],
            "Swift": [self.project_path / "Package.swift"],
        }

        components = []
        found_files = False

        for ecosystem, paths in files.items():
            for path in paths:
                if path.exists():
                    found_files = True
                    logger.info(f"Обнаружен файл зависимостей: {path} ({ecosystem})")
                    try:
                        if ecosystem == "Python":
                            if path.name == "requirements.txt":
                                components.extend(self.parse_requirements(path))
                            elif path.name == "poetry.lock":
                                components.extend(self.parse_poetry_lock(path))
                        elif ecosystem == "JavaScript":
                            components.extend(self.parse_package_json(path))
                        elif ecosystem == "Ruby":
                            components.extend(self.parse_gemfile_lock(path))
                        elif ecosystem == "Java":
                            components.extend(self.parse_pom_xml(path))
                        elif ecosystem == "PHP":
                            components.extend(self.parse_composer_json(path))
                        elif ecosystem == "Go":
                            components.extend(self.parse_go_mod(path))
                        elif ecosystem == "Swift":
                            components.extend(self.parse_package_swift(path))
                    except Exception as e:
                        logger.error(f"Ошибка при обработке {path}: {e}")
                        continue
                else:
                    logger.debug(f"Файл {path} не найден")

        if not found_files:
            logger.error("Не найдены файлы зависимостей в проекте.")
            sys.exit(1)

        if not components:
            logger.error("Не удалось извлечь зависимости из файлов.")
            sys.exit(1)

        unique_components = {f"{c.name}:{c.version}:{c.purl.type if c.purl else 'unknown'}": c for c in components}
        self.bom.components.update(unique_components.values())
        logger.info(f"Добавлено {len(unique_components)} уникальных зависимостей в SBOM")

        self.check_vulnerabilities(list(unique_components.values()))
        self.check_outdated(list(unique_components.values()))
        self._save_cache()

    def display_results(self) -> None:
        """Вывод результатов в консоль с использованием rich."""
        console.print("\n[bold green]SBOM Results[/bold green]")

        # Таблица зависимостей
        table = Table(title="Dependencies")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="magenta")
        table.add_column("Ecosystem", style="yellow")
        table.add_column("License", style="blue")
        for component in self.bom.components:
            ecosystem = component.purl.type if component.purl else "unknown"
            dep_key = f"{component.name}=={component.version}"
            license_info = self.licenses.get(dep_key, "Unknown")
            table.add_row(component.name, component.version or "unknown", ecosystem, license_info)
        console.print(table)

        # Таблица уязвимостей
        if self.vulnerabilities:
            vuln_table = Table(title="Vulnerabilities")
            vuln_table.add_column("Dependency", style="cyan")
            vuln_table.add_column("Vulnerability ID", style="red")
            vuln_table.add_column("Summary", style="white")
            vuln_table.add_column("CVE", style="yellow")
            for dep, vulns in self.vulnerabilities.items():
                for vuln in vulns:
                    vuln_table.add_row(dep, vuln["id"], vuln["summary"], vuln.get("cve", "N/A"))
            console.print(vuln_table)
        else:
            console.print("[yellow]Уязвимости не найдены или проверка не выполнена из-за ошибок.[/yellow]")

        # Таблица устаревших зависимостей
        if self.outdated:
            outdated_table = Table(title="Outdated Dependencies")
            outdated_table.add_column("Dependency", style="cyan")
            outdated_table.add_column("Current Version", style="magenta")
            outdated_table.add_column("Latest Version", style="green")
            outdated_table.add_column("Ecosystem", style="yellow")
            outdated_table.add_column("Update Command", style="blue")
            for dep, info in self.outdated.items():
                name, version = dep.split("==")
                outdated_table.add_row(name, version, info["latest_version"], info["ecosystem"], info["update_cmd"])
            console.print(outdated_table)
        else:
            console.print("[yellow]Устаревшие зависимости не найдены или проверка не выполнена.[/yellow]")

    def save_sbom(self, output_file: str) -> None:
        """Сохранение SBOM в JSON-файл с красивым форматированием."""
        try:
            output = JsonV1Dot4(bom=self.bom)
            json_data = json.loads(output.output_as_string())
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            logger.info(f"SBOM успешно сохранён в {output_file}")
        except Exception as e:
            logger.error(f"Ошибка при сохранении SBOM: {e}")
            sys.exit(1)

    def save_report(self, report_file: str) -> None:
        """Сохранение отчёта в Markdown-файл."""
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(f"# SBOM Report\n\nGenerated on {datetime.now().isoformat()}\n\n")
                f.write("## Dependencies\n\n")
                f.write("| Name | Version | Ecosystem | License |\n")
                f.write("|------|---------|-----------|---------|\n")
                for component in self.bom.components:
                    ecosystem = component.purl.type if component.purl else "unknown"
                    dep_key = f"{component.name}=={component.version}"
                    license_info = self.licenses.get(dep_key, "Unknown")
                    f.write(f"| {component.name} | {component.version or 'unknown'} | {ecosystem} | {license_info} |\n")

                if self.vulnerabilities:
                    f.write("\n## Vulnerabilities\n\n")
                    f.write("| Dependency | Vulnerability ID | Summary | CVE |\n")
                    f.write("|------------|------------------|---------|-----|\n")
                    for dep, vulns in self.vulnerabilities.items():
                        for vuln in vulns:
                            f.write(f"| {dep} | {vuln['id']} | {vuln['summary']} | {vuln.get('cve', 'N/A')} |\n")
                else:
                    f.write("\n## Vulnerabilities\n\nNo vulnerabilities found or check failed due to errors.\n")

                if self.outdated:
                    f.write("\n## Outdated Dependencies\n\n")
                    f.write("| Dependency | Current Version | Latest Version | Ecosystem | Update Command |\n")
                    f.write("|------------|-----------------|----------------|-----------|----------------|\n")
                    for dep, info in self.outdated.items():
                        name, version = dep.split("==")
                        f.write(f"| {name} | {version} | {info['latest_version']} | {info['ecosystem']} | `{info['update_cmd']}` |\n")
                else:
                    f.write("\n## Outdated Dependencies\n\nNo outdated dependencies found or check not performed.\n")

            logger.info(f"Отчёт успешно сохранён в {report_file}")
        except Exception as e:
            logger.error(f"Ошибка при сохранении отчёта: {e}")
            sys.exit(1)

def main():
    """Основная функция CLI."""
    parser = argparse.ArgumentParser(description="Генерация SBOM для Python, JavaScript, Ruby, Java, PHP, Go и Swift")
    parser.add_argument(
        "--path",
        default=".",
        help="Путь к проекту (где находятся requirements.txt, poetry.lock, package.json, Gemfile.lock, pom.xml, composer.json, go.mod или Package.swift)",
    )
    parser.add_argument(
        "--output",
        default="sbom.json",
        help="Путь к выходному файлу SBOM (JSON)",
    )
    parser.add_argument(
        "--report",
        help="Путь к файлу отчёта (Markdown)",
    )
    parser.add_argument(
        "--check-vulns",
        action="store_true",
        help="Проверять уязвимости через OSV API и GitHub Advisory",
    )
    parser.add_argument(
        "--check-outdated",
        action="store_true",
        help="Проверять устаревшие зависимости",
    )
    parser.add_argument(
        "--osv-api-key",
        help="API-ключ для OSV API",
    )
    parser.add_argument(
        "--github-token",
        help="GitHub токен для Advisory Database",
    )
    parser.add_argument(
        "--proxy",
        help="HTTP/HTTPS прокси (например, http://proxy:8080)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Включить подробное логирование",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    generator = SBOMGenerator(
        args.path,
        args.check_vulns,
        args.check_outdated,
        args.osv_api_key,
        args.github_token,
        args.proxy
    )
    generator.generate_sbom()
    generator.display_results()
    generator.save_sbom(args.output)
    if args.report:
        generator.save_report(args.report)

if __name__ == "__main__":
    main()
