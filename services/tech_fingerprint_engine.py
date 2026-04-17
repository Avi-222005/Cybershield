import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
    import dns.reversename
except Exception:
    dns = None


DEFAULT_THRESHOLD = 35
SCAN_CACHE_TTL_SECONDS = 300


class TechFingerprintEngine:
    def __init__(self, data_root: Optional[Path] = None):
        base_root = Path(__file__).resolve().parent.parent
        self.data_root = data_root or (base_root / "tech stack")
        self.technologies_path = self.data_root / "technologies"
        self.categories_path = self.data_root / "categories.json"
        self.groups_path = self.data_root / "groups.json"
        self.schema_path = self.data_root / "schema.json"

        self._load_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._loaded = False

        self.technologies: List[Dict[str, Any]] = []
        self.technology_by_name: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[int, Dict[str, Any]] = {}
        self.groups: Dict[int, Dict[str, Any]] = {}
        self.scan_cache: Dict[str, Dict[str, Any]] = {}

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "CyberShield-TechFingerprint/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

        self.max_html_chars = 2_000_000
        self.max_inline_script_chars = 450_000
        self.max_text_chars = 450_000
        self.max_css_chars = 300_000

    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^a-z0-9-]", "-", str(value or "").lower())
        slug = re.sub(r"-+", "-", slug).strip("-")
        return slug

    @staticmethod
    def _to_list(value: Any) -> List[Any]:
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    def _read_json(self, file_path: Path) -> Dict[str, Any]:
        with file_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}

    def _load_technology_files(self) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        if not self.technologies_path.exists():
            return merged

        for json_file in sorted(self.technologies_path.glob("*.json")):
            payload = self._read_json(json_file)
            for name, config in payload.items():
                if isinstance(config, dict):
                    merged[name] = config
        return merged

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        with self._load_lock:
            if self._loaded:
                return

            categories_data = self._read_json(self.categories_path) if self.categories_path.exists() else {}
            groups_data = self._read_json(self.groups_path) if self.groups_path.exists() else {}
            technologies_data = self._load_technology_files()

            self.setCategories(categories_data)
            self.setGroups(groups_data)
            self.setTechnologies(technologies_data)
            self._loaded = True

    def setGroups(self, data: Dict[str, Any]) -> None:
        groups: Dict[int, Dict[str, Any]] = {}
        for key, group in data.items():
            try:
                group_id = int(key)
            except Exception:
                continue
            if isinstance(group, dict):
                groups[group_id] = {
                    "id": group_id,
                    "name": str(group.get("name", "")),
                    "slug": self._slugify(str(group.get("name", ""))),
                }
        self.groups = groups

    def setCategories(self, data: Dict[str, Any]) -> None:
        categories: Dict[int, Dict[str, Any]] = {}
        for key, category in data.items():
            try:
                category_id = int(key)
            except Exception:
                continue
            if not isinstance(category, dict):
                continue
            categories[category_id] = {
                "id": category_id,
                "name": str(category.get("name", "")),
                "slug": self._slugify(str(category.get("name", ""))),
                "priority": int(category.get("priority", 0) or 0),
                "groups": [int(group_id) for group_id in category.get("groups", []) if str(group_id).isdigit()],
            }
        self.categories = categories

    def _compile_regex(self, pattern_text: str, is_regex: bool = True) -> re.Pattern:
        text = str(pattern_text or "")
        if not is_regex:
            text = re.escape(text)

        try:
            return re.compile(text, re.IGNORECASE)
        except re.error:
            try:
                return re.compile(re.escape(str(pattern_text or "")), re.IGNORECASE)
            except re.error:
                return re.compile(r"$.")

    def parsePattern(self, pattern: Any, is_regex: bool = True) -> Dict[str, Any]:
        if isinstance(pattern, dict):
            return {key: self.parsePattern(value, is_regex=is_regex) for key, value in pattern.items()}

        raw = str(pattern)
        segments = raw.split(r"\;")

        value = segments[0] if segments else ""
        attrs: Dict[str, str] = {}

        for segment in segments[1:]:
            if ":" not in segment:
                continue
            attr_key, attr_value = segment.split(":", 1)
            attrs[attr_key.strip()] = attr_value.strip()

        confidence_raw = attrs.get("confidence", "100")
        try:
            confidence = int(confidence_raw)
        except Exception:
            confidence = 100

        return {
            "value": value,
            "regex": self._compile_regex(value, is_regex=is_regex),
            "confidence": max(0, min(100, confidence)),
            "version": attrs.get("version", ""),
        }

    def _transform_patterns(self, patterns: Any, case_sensitive: bool = False, is_regex: bool = True) -> Any:
        if not patterns:
            return []

        if isinstance(patterns, (str, int, float, list)):
            patterns = {"main": patterns}

        parsed: Dict[str, List[Dict[str, Any]]] = {}
        if not isinstance(patterns, dict):
            return []

        for key, value in patterns.items():
            normalized_key = str(key) if case_sensitive else str(key).lower()
            parsed[normalized_key] = [
                self.parsePattern(item, is_regex=is_regex)
                for item in self._to_list(value)
            ]

        return parsed["main"] if "main" in parsed else parsed

    def setTechnologies(self, data: Dict[str, Any]) -> None:
        technologies: List[Dict[str, Any]] = []

        for name, payload in data.items():
            if not isinstance(payload, dict):
                continue

            technology = {
                "name": name,
                "slug": self._slugify(name),
                "description": payload.get("description") or None,
                "website": payload.get("website") or None,
                "icon": payload.get("icon") or None,
                "cpe": payload.get("cpe") or None,
                "pricing": payload.get("pricing") or [],
                "categories": [int(category_id) for category_id in payload.get("cats", []) if str(category_id).isdigit()],
                "headers": self._transform_patterns(payload.get("headers")),
                "cookies": self._transform_patterns(payload.get("cookies")),
                "meta": self._transform_patterns(payload.get("meta")),
                "dns": self._transform_patterns(payload.get("dns")),
                "html": self._transform_patterns(payload.get("html")),
                "scriptSrc": self._transform_patterns(payload.get("scriptSrc")),
                "scripts": self._transform_patterns(payload.get("scripts")),
                "url": self._transform_patterns(payload.get("url")),
                "text": self._transform_patterns(payload.get("text")),
                "css": self._transform_patterns(payload.get("css")),
                "robots": self._transform_patterns(payload.get("robots")),
                "excludes": [
                    {
                        "name": item.get("value", ""),
                        "confidence": item.get("confidence", 100),
                    }
                    for item in self._transform_patterns(payload.get("excludes"))
                    if isinstance(item, dict) and item.get("value")
                ],
                "implies": [
                    {
                        "name": item.get("value", ""),
                        "confidence": item.get("confidence", 100),
                        "version": item.get("version", ""),
                    }
                    for item in self._transform_patterns(payload.get("implies"))
                    if isinstance(item, dict) and item.get("value")
                ],
            }

            technologies.append(technology)

        self.technologies = technologies
        self.technology_by_name = {tech["name"]: tech for tech in technologies}

    def getTechnology(self, name: str) -> Optional[Dict[str, Any]]:
        return self.technology_by_name.get(str(name or ""))

    def getCategory(self, category_id: int) -> Optional[Dict[str, Any]]:
        return self.categories.get(int(category_id))

    def _normalize_target(self, target_input: str) -> Tuple[str, str]:
        raw = str(target_input or "").strip()
        if not raw:
            return "", ""

        if not re.match(r"^https?://", raw, re.IGNORECASE):
            raw = f"https://{raw}"

        parsed = urlparse(raw)
        host = parsed.netloc.strip().lower()
        if not host:
            return "", ""

        return raw, host

    def _extract_meta(self, soup: BeautifulSoup) -> Dict[str, List[str]]:
        meta_map: Dict[str, List[str]] = {}
        for tag in soup.find_all("meta"):
            key = (tag.get("name") or tag.get("property") or tag.get("http-equiv") or "").strip().lower()
            content = (tag.get("content") or "").strip().lower()
            if not key:
                continue
            meta_map.setdefault(key, [])
            if content:
                meta_map[key].append(content)
            else:
                meta_map[key].append("")
        return meta_map

    def _extract_cookie_map(self, response: requests.Response) -> Dict[str, List[str]]:
        cookie_map: Dict[str, List[str]] = {}
        for cookie in response.cookies:
            name = str(cookie.name or "").strip().lower()
            value = str(cookie.value or "").strip().lower()
            if not name:
                continue
            cookie_map.setdefault(name, []).append(value)

        set_cookie_header = response.headers.get("Set-Cookie", "")
        if set_cookie_header:
            chunks = [chunk.strip() for chunk in set_cookie_header.split(",") if chunk.strip()]
            for chunk in chunks:
                pair = chunk.split(";", 1)[0]
                if "=" not in pair:
                    continue
                cookie_name, cookie_value = pair.split("=", 1)
                key = cookie_name.strip().lower()
                value = cookie_value.strip().lower()
                if not key:
                    continue
                cookie_map.setdefault(key, []).append(value)

        return cookie_map

    def _extract_scripts(self, soup: BeautifulSoup, final_url: str) -> Tuple[List[str], str]:
        srcs: List[str] = []
        inline_parts: List[str] = []

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                srcs.append(urljoin(final_url, src).lower())
                continue

            text = script.get_text(" ", strip=True)
            if text:
                inline_parts.append(text)

        inline_blob = "\n".join(inline_parts)
        if len(inline_blob) > self.max_inline_script_chars:
            inline_blob = inline_blob[: self.max_inline_script_chars]

        return srcs, inline_blob.lower()

    def _extract_css_signals(self, soup: BeautifulSoup, final_url: str) -> str:
        css_fragments: List[str] = []

        for style_tag in soup.find_all("style"):
            text = style_tag.get_text(" ", strip=True)
            if text:
                css_fragments.append(text)

        css_links = []
        for link_tag in soup.find_all("link"):
            rel = [str(item).lower() for item in self._to_list(link_tag.get("rel"))]
            href = str(link_tag.get("href") or "").strip()
            if not href:
                continue
            if "stylesheet" in rel or href.lower().endswith(".css"):
                css_links.append(urljoin(final_url, href))

        parsed_final = urlparse(final_url)
        same_host = parsed_final.netloc.lower()

        fetched = 0
        for css_url in css_links:
            if fetched >= 3:
                break
            parsed_css = urlparse(css_url)
            if parsed_css.netloc.lower() != same_host:
                continue
            try:
                res = self.session.get(css_url, timeout=(4, 10), allow_redirects=True)
                if res.status_code >= 400:
                    continue
                css_fragments.append((res.text or "")[:120_000])
                fetched += 1
            except requests.RequestException:
                continue

        css_blob = "\n".join(css_fragments).lower()
        if len(css_blob) > self.max_css_chars:
            css_blob = css_blob[: self.max_css_chars]

        return css_blob

    def _extract_robots(self, final_url: str) -> str:
        parsed = urlparse(final_url)
        if not parsed.scheme or not parsed.netloc:
            return ""

        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            response = self.session.get(robots_url, timeout=(4, 8), allow_redirects=True)
            if response.status_code >= 400:
                return ""
            return (response.text or "")[:120_000].lower()
        except requests.RequestException:
            return ""

    def _collect_dns_signals(self, hostname: str) -> Dict[str, List[str]]:
        records: Dict[str, List[str]] = {
            "a": [],
            "aaaa": [],
            "cname": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "soa": [],
            "ptr": [],
        }

        if not hostname:
            return records

        if dns is not None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4

            for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
                try:
                    answers = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
                    if not answers:
                        continue
                    for answer in answers:
                        if rtype == "MX":
                            value = f"{answer.preference} {str(answer.exchange).rstrip('.').lower()}"
                        elif rtype == "TXT":
                            if hasattr(answer, "strings") and answer.strings:
                                value = "".join(
                                    p.decode() if isinstance(p, bytes) else str(p)
                                    for p in answer.strings
                                )
                            else:
                                value = str(answer).strip('"')
                        else:
                            value = str(answer).rstrip(".").lower()
                        records[rtype.lower()].append(value)
                except Exception:
                    continue

            for ip in records["a"][:2] + records["aaaa"][:2]:
                try:
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = resolver.resolve(str(rev_name), "PTR", raise_on_no_answer=False)
                    if not ptr_answers:
                        continue
                    for answer in ptr_answers:
                        records["ptr"].append(str(answer).rstrip(".").lower())
                except Exception:
                    continue

        records = {key: list(dict.fromkeys(values)) for key, values in records.items()}
        return records

    def _collect_site_data(self, target_input: str) -> Dict[str, Any]:
        target_url, hostname = self._normalize_target(target_input)
        if not target_url:
            return {"error": "Target is required and must be a valid URL or domain."}

        try:
            response = self.session.get(target_url, timeout=(5, 12), allow_redirects=True)
        except requests.RequestException as exc:
            return {"error": f"Request failed: {exc}"}

        html = response.text or ""
        if len(html) > self.max_html_chars:
            html = html[: self.max_html_chars]

        final_url = response.url or target_url
        soup = BeautifulSoup(html, "html.parser")

        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        script_src, inline_scripts = self._extract_scripts(soup, final_url)
        css_blob = self._extract_css_signals(soup, final_url)

        text_blob = soup.get_text(" ", strip=True).lower()
        if len(text_blob) > self.max_text_chars:
            text_blob = text_blob[: self.max_text_chars]

        headers_map: Dict[str, List[str]] = {}
        for key, value in response.headers.items():
            lower_key = str(key).lower()
            headers_map.setdefault(lower_key, []).append(str(value).lower())

        meta_map = self._extract_meta(soup)
        cookie_map = self._extract_cookie_map(response)
        robots_text = self._extract_robots(final_url)
        dns_map = self._collect_dns_signals(hostname)

        return {
            "target": target_input,
            "normalized_target": target_url,
            "hostname": hostname,
            "final_url": final_url,
            "status_code": int(response.status_code),
            "title": title,
            "headers": headers_map,
            "html": html.lower(),
            "meta": meta_map,
            "cookies": cookie_map,
            "scriptSrc": script_src,
            "scripts": inline_scripts,
            "url": final_url.lower(),
            "text": text_blob,
            "css": css_blob,
            "dns": dns_map,
            "robots": robots_text,
        }

    def resolveVersion(self, pattern: Dict[str, Any], match_value: str) -> str:
        template = str(pattern.get("version") or "")
        if not template:
            return ""

        regex = pattern.get("regex")
        if not isinstance(regex, re.Pattern):
            return ""

        match = regex.search(str(match_value or ""))
        if not match:
            return ""

        resolved = template
        groups = [match.group(0)] + list(match.groups())

        for index, token in enumerate(groups):
            token_text = str(token or "")
            if len(token_text) > 50:
                continue

            ternary_pattern = re.compile(rf"\\{index}\?([^:]*):(.*)$")
            ternary_match = ternary_pattern.search(resolved)
            if ternary_match:
                resolved = resolved.replace(
                    ternary_match.group(0),
                    ternary_match.group(1) if token_text else ternary_match.group(2),
                )

            resolved = resolved.replace(f"\\{index}", token_text)

        resolved = re.sub(r"\\\d", "", resolved).strip()
        if len(resolved) > 32:
            resolved = resolved[:32]

        return resolved

    def analyzeOneToOne(self, technology: Dict[str, Any], source_type: str, value: str) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        patterns = technology.get(source_type, [])

        if not isinstance(patterns, list):
            return detections

        for pattern in patterns:
            regex = pattern.get("regex") if isinstance(pattern, dict) else None
            if not isinstance(regex, re.Pattern):
                continue
            if regex.search(value):
                detections.append(
                    {
                        "technology": technology,
                        "pattern": pattern,
                        "source": source_type,
                        "value": value,
                        "version": self.resolveVersion(pattern, value),
                    }
                )

        return detections

    def analyzeOneToMany(self, technology: Dict[str, Any], source_type: str, values: List[str]) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        patterns = technology.get(source_type, [])

        if not isinstance(patterns, list):
            return detections

        for value in values:
            for pattern in patterns:
                regex = pattern.get("regex") if isinstance(pattern, dict) else None
                if not isinstance(regex, re.Pattern):
                    continue
                if regex.search(value):
                    detections.append(
                        {
                            "technology": technology,
                            "pattern": pattern,
                            "source": source_type,
                            "value": value,
                            "version": self.resolveVersion(pattern, value),
                        }
                    )

        return detections

    def analyzeManyToMany(self, technology: Dict[str, Any], source_type: str, values: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        patterns_map = technology.get(source_type, {})

        if not isinstance(patterns_map, dict):
            return detections

        for key, patterns in patterns_map.items():
            lowered_key = str(key).lower()
            source_values = values.get(lowered_key, [])
            if not source_values:
                continue
            if not isinstance(patterns, list):
                continue

            for pattern in patterns:
                regex = pattern.get("regex") if isinstance(pattern, dict) else None
                if not isinstance(regex, re.Pattern):
                    continue
                for value in source_values:
                    if regex.search(value):
                        detections.append(
                            {
                                "technology": technology,
                                "pattern": pattern,
                                "source": source_type,
                                "value": value,
                                "version": self.resolveVersion(pattern, value),
                            }
                        )

        return detections

    def analyze(self, items: Dict[str, Any], technologies: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        relations = {
            "headers": self.analyzeManyToMany,
            "html": self.analyzeOneToOne,
            "meta": self.analyzeManyToMany,
            "cookies": self.analyzeManyToMany,
            "scriptSrc": self.analyzeOneToMany,
            "scripts": self.analyzeOneToOne,
            "url": self.analyzeOneToOne,
            "text": self.analyzeOneToOne,
            "css": self.analyzeOneToOne,
            "dns": self.analyzeManyToMany,
            "robots": self.analyzeOneToOne,
        }

        active_technologies = technologies or self.technologies
        detections: List[Dict[str, Any]] = []

        for technology in active_technologies:
            for source_type, analyzer in relations.items():
                if source_type not in items:
                    continue
                source_value = items[source_type]
                if source_type in ("html", "scripts", "url", "text", "css", "robots"):
                    detections.extend(analyzer(technology, source_type, str(source_value or "")))
                elif source_type == "scriptSrc":
                    detections.extend(analyzer(technology, source_type, source_value or []))
                else:
                    detections.extend(analyzer(technology, source_type, source_value or {}))

        return detections

    def _get_category_names(self, category_ids: List[int]) -> List[str]:
        names: List[str] = []
        for category_id in category_ids:
            category = self.getCategory(category_id)
            if category and category.get("name"):
                names.append(str(category["name"]))
        return list(dict.fromkeys(names))

    @staticmethod
    def _best_version(current: str, candidate: str) -> str:
        current = str(current or "")
        candidate = str(candidate or "")

        if not candidate:
            return current
        if len(candidate) > 24:
            return current
        if candidate.isdigit() and len(candidate) >= 6:
            return current
        if len(candidate) > len(current):
            return candidate
        return current

    def _resolve_raw(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        resolved_map: Dict[str, Dict[str, Any]] = {}

        for detection in detections:
            technology = detection.get("technology")
            if not isinstance(technology, dict):
                continue

            name = str(technology.get("name") or "")
            if not name:
                continue

            pattern = detection.get("pattern", {})
            confidence = int(pattern.get("confidence", 100) or 100)
            version = str(detection.get("version") or "")

            if name not in resolved_map:
                resolved_map[name] = {
                    "technology": technology,
                    "name": name,
                    "confidence": 0,
                    "version": "",
                    "signals": set(),
                }

            resolved_map[name]["confidence"] = min(100, int(resolved_map[name]["confidence"]) + confidence)
            resolved_map[name]["version"] = self._best_version(resolved_map[name]["version"], version)
            resolved_map[name]["signals"].add(str(detection.get("source") or ""))

        resolved = list(resolved_map.values())
        self.resolveExcludes(resolved)
        self.resolveImplies(resolved)

        for item in resolved:
            if isinstance(item.get("signals"), set):
                item["signals"] = sorted(item["signals"])

        return resolved

    def resolveExcludes(self, resolved: List[Dict[str, Any]]) -> None:
        changed = True
        while changed:
            changed = False
            by_name = {str(item.get("name")): item for item in resolved}

            for item in list(resolved):
                technology = item.get("technology", {})
                excludes = technology.get("excludes", []) if isinstance(technology, dict) else []

                for excluded in excludes:
                    excluded_name = str(excluded.get("name") or "")
                    if not excluded_name:
                        continue
                    if excluded_name not in by_name:
                        continue

                    current = by_name.get(item.get("name"))
                    conflict = by_name.get(excluded_name)
                    if not current or not conflict:
                        continue

                    current_conf = int(current.get("confidence", 0) or 0)
                    conflict_conf = int(conflict.get("confidence", 0) or 0)

                    to_remove = conflict if current_conf >= conflict_conf else current
                    if to_remove in resolved:
                        resolved.remove(to_remove)
                        changed = True
                        break

                if changed:
                    break

    def resolveImplies(self, resolved: List[Dict[str, Any]]) -> None:
        changed = True
        while changed:
            changed = False
            by_name = {str(item.get("name")): item for item in resolved}

            for item in list(resolved):
                technology = item.get("technology", {})
                implies = technology.get("implies", []) if isinstance(technology, dict) else []

                for implied in implies:
                    implied_name = str(implied.get("name") or "")
                    if not implied_name:
                        continue

                    implied_tech = self.getTechnology(implied_name)
                    if not implied_tech:
                        continue

                    implied_conf = int(implied.get("confidence", 100) or 100)
                    inherited_conf = min(int(item.get("confidence", 0) or 0), implied_conf)
                    implied_version = str(implied.get("version") or "")

                    existing = by_name.get(implied_name)
                    if existing:
                        boosted = max(int(existing.get("confidence", 0) or 0), inherited_conf)
                        existing["confidence"] = boosted
                        existing["version"] = self._best_version(existing.get("version", ""), implied_version)
                        continue

                    resolved.append(
                        {
                            "technology": implied_tech,
                            "name": implied_name,
                            "confidence": inherited_conf,
                            "version": implied_version,
                            "signals": ["implied"],
                        }
                    )
                    changed = True

            if changed:
                self.resolveExcludes(resolved)

    def _normalization_map(self) -> Dict[str, str]:
        return {
            "apache": "Apache HTTP Server",
            "nginx": "nginx",
            "wordpress": "WordPress",
            "openssh": "OpenSSH",
            "php": "PHP",
            "microsoft asp.net": "Microsoft ASP.NET",
        }

    def _normalized_name(self, technology_name: str) -> str:
        key = str(technology_name or "").strip().lower()
        if not key:
            return ""
        return self._normalization_map().get(key, technology_name)

    def _category_name_to_id(self, name: str) -> Optional[int]:
        needle = str(name or "").strip().lower()
        if not needle:
            return None
        for category_id, category in self.categories.items():
            if str(category.get("name", "")).strip().lower() == needle:
                return category_id
        return None

    def _add_or_update_custom_detection(
        self,
        resolved: List[Dict[str, Any]],
        name: str,
        confidence: int,
        category_names: List[str],
        website: Optional[str] = None,
    ) -> None:
        if not name:
            return

        existing = next((item for item in resolved if item.get("name") == name), None)
        category_ids = []
        for category_name in category_names:
            category_id = self._category_name_to_id(category_name)
            if category_id is not None:
                category_ids.append(category_id)

        custom_technology = {
            "name": name,
            "slug": self._slugify(name),
            "description": None,
            "website": website,
            "icon": None,
            "cpe": None,
            "pricing": [],
            "categories": category_ids,
            "headers": [],
            "cookies": [],
            "meta": [],
            "dns": [],
            "html": [],
            "scriptSrc": [],
            "scripts": [],
            "url": [],
            "text": [],
            "css": [],
            "robots": [],
            "excludes": [],
            "implies": [],
        }

        if existing:
            existing["confidence"] = max(int(existing.get("confidence", 0) or 0), confidence)
            existing["technology"]["categories"] = list(
                dict.fromkeys(existing["technology"].get("categories", []) + category_ids)
            )
            signals = existing.get("signals", [])
            if isinstance(signals, list) and "custom" not in signals:
                signals.append("custom")
            existing["signals"] = signals
            return

        resolved.append(
            {
                "technology": custom_technology,
                "name": name,
                "confidence": max(0, min(100, confidence)),
                "version": "",
                "signals": ["custom"],
            }
        )

    def _apply_cybershield_enhancements(self, items: Dict[str, Any], resolved: List[Dict[str, Any]]) -> None:
        headers = items.get("headers", {})
        html = str(items.get("html", ""))
        script_src = items.get("scriptSrc", [])
        url = str(items.get("url", ""))

        header_blob = " ".join(
            f"{key} {' '.join(values)}"
            for key, values in headers.items()
            if isinstance(values, list)
        )
        script_blob = " ".join([str(src) for src in script_src])

        if any(token in header_blob for token in ("cf-ray", "cloudflare", "cf-cache-status", "cf_clearance", "__cf_bm")):
            self._add_or_update_custom_detection(resolved, "Cloudflare", 95, ["Security", "CDN"], website="https://www.cloudflare.com")

        if any(token in header_blob for token in ("akamai", "imperva", "sucuri", "f5", "cloudfront", "fastly")):
            self._add_or_update_custom_detection(resolved, "WAF/CDN", 70, ["Security", "CDN"])

        if "recaptcha" in script_blob or "grecaptcha" in html:
            self._add_or_update_custom_detection(resolved, "Google reCAPTCHA", 90, ["Security"])

        if "hcaptcha" in script_blob or "hcaptcha" in html:
            self._add_or_update_custom_detection(resolved, "hCaptcha", 90, ["Security"])

        security_header_names = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        present_security_headers = [name for name in security_header_names if name in headers]
        if len(present_security_headers) >= 2:
            confidence = min(95, 40 + (len(present_security_headers) * 8))
            self._add_or_update_custom_detection(resolved, "Security Headers", confidence, ["Security"])

        if any(token in url for token in ("vercel.app", "netlify.app", "herokuapp.com", "onrender.com")):
            if "vercel.app" in url:
                self._add_or_update_custom_detection(resolved, "Vercel", 75, ["Hosting"])
            if "netlify.app" in url:
                self._add_or_update_custom_detection(resolved, "Netlify", 75, ["Hosting"])
            if "herokuapp.com" in url:
                self._add_or_update_custom_detection(resolved, "Heroku", 75, ["Hosting"])
            if "onrender.com" in url:
                self._add_or_update_custom_detection(resolved, "Render", 75, ["Hosting"])

        if any(token in header_blob for token in ("x-powered-by: express", "express", "fastapi", "laravel", "django", "asp.net")):
            self._add_or_update_custom_detection(resolved, "API Framework Hints", 55, ["Web frameworks"])

        if "id=\"root\"" in html or "id='root'" in html or "__next" in html:
            self._add_or_update_custom_detection(resolved, "SPA Architecture", 55, ["JavaScript frameworks"])

    def _section_from_categories(self, categories: List[str], name: str) -> str:
        lowered_name = str(name or "").lower()
        lowered = [str(category).lower() for category in categories]

        if any(token in lowered_name for token in ("wordpress", "drupal", "joomla", "shopify", "magento")):
            return "CMS"
        if any(token in lowered_name for token in ("nginx", "apache", "iis", "litespeed", "openresty", "cloudflare")):
            return "Server"

        if any("security" in category or "privacy" in category for category in lowered):
            return "Security"
        if any("analytics" in category or "marketing" in category for category in lowered):
            return "Analytics"
        if any("payment" in category for category in lowered):
            return "Payment"
        if any("hosting" in category for category in lowered):
            return "Hosting"
        if any("cms" in category or "blog" in category or "ecommerce" in category for category in lowered):
            return "CMS"
        if any("web server" in category or "cdn" in category or "server" in category for category in lowered):
            return "Server"
        if any("programming" in category or "database" in category for category in lowered):
            return "Backend"
        if any("framework" in category or "javascript" in category or "font" in category or "web development" in category for category in lowered):
            return "Frontend"

        return "Other"

    def _legacy_categorized_map(self, detected: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        legacy: Dict[str, List[str]] = {
            "Server": [],
            "Framework": [],
            "CMS": [],
            "CDN": [],
            "Language": [],
            "Security": [],
            "Analytics": [],
            "Hosting": [],
        }

        for item in detected:
            name = str(item.get("name") or "")
            categories = [str(cat).lower() for cat in item.get("categories", [])]

            if any("web server" in cat or cat == "cdn" or "server" in cat for cat in categories):
                legacy["Server"].append(name)
            if any("framework" in cat for cat in categories):
                legacy["Framework"].append(name)
            if any("cms" in cat or "blog" in cat or "ecommerce" in cat for cat in categories):
                legacy["CMS"].append(name)
            if any("cdn" in cat for cat in categories):
                legacy["CDN"].append(name)
            if any("programming" in cat for cat in categories):
                legacy["Language"].append(name)
            if any("security" in cat for cat in categories):
                legacy["Security"].append(name)
            if any("analytics" in cat for cat in categories):
                legacy["Analytics"].append(name)
            if any("hosting" in cat for cat in categories):
                legacy["Hosting"].append(name)

        for key in list(legacy.keys()):
            legacy[key] = sorted(list(dict.fromkeys(legacy[key])))
            if not legacy[key]:
                legacy.pop(key, None)

        return legacy

    def _build_output(self, collected: Dict[str, Any], resolved: List[Dict[str, Any]], threshold: int) -> Dict[str, Any]:
        normalized = [item for item in resolved if int(item.get("confidence", 0) or 0) >= threshold]
        normalized.sort(key=lambda item: int(item.get("confidence", 0) or 0), reverse=True)

        detected: List[Dict[str, Any]] = []
        grouped: Dict[str, List[Dict[str, Any]]] = {
            "Frontend": [],
            "Backend": [],
            "CMS": [],
            "Server": [],
            "Security": [],
            "Analytics": [],
            "Hosting": [],
            "Payment": [],
            "Other": [],
        }
        categorized_verbose: Dict[str, List[str]] = {}

        for item in normalized:
            technology = item.get("technology", {})
            category_names = self._get_category_names(technology.get("categories", []))
            section = self._section_from_categories(category_names, item.get("name", ""))

            row = {
                "name": str(item.get("name") or ""),
                "normalized_name": self._normalized_name(str(item.get("name") or "")),
                "version": str(item.get("version") or ""),
                "confidence": int(item.get("confidence", 0) or 0),
                "categories": category_names,
                "website": technology.get("website"),
                "section": section,
                "signals": item.get("signals", []),
            }
            detected.append(row)

            grouped.setdefault(section, []).append(row)

            for category_name in category_names:
                categorized_verbose.setdefault(category_name, []).append(row["name"])

        for section_name in list(grouped.keys()):
            grouped[section_name] = sorted(
                grouped[section_name],
                key=lambda row: (-(int(row.get("confidence", 0) or 0)), row.get("name", "")),
            )
            if not grouped[section_name]:
                grouped.pop(section_name, None)

        for category_name in list(categorized_verbose.keys()):
            categorized_verbose[category_name] = sorted(list(dict.fromkeys(categorized_verbose[category_name])))

        legacy_categorized = self._legacy_categorized_map(detected)
        technologies = [item["name"] for item in detected]

        summary = {
            "total": len(detected),
            "high_confidence": len([item for item in detected if int(item.get("confidence", 0) or 0) >= 80]),
            "frameworks": [item["name"] for item in grouped.get("Frontend", [])[:12]],
            "servers": [item["name"] for item in grouped.get("Server", [])[:12]],
            "security": [item["name"] for item in grouped.get("Security", [])[:12]],
        }

        return {
            "target": str(collected.get("target") or ""),
            "url": str(collected.get("final_url") or ""),
            "detected": detected,
            "summary": summary,
            "grouped": grouped,
            "technologies": technologies,
            "categorized": legacy_categorized,
            "categorized_verbose": categorized_verbose,
            "metadata": {
                "final_url": str(collected.get("final_url") or ""),
                "title": str(collected.get("title") or ""),
                "status_code": int(collected.get("status_code") or 0),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    def _cache_get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._cache_lock:
            item = self.scan_cache.get(cache_key)
            if not item:
                return None
            if now > item.get("expires_at", 0):
                self.scan_cache.pop(cache_key, None)
                return None
            payload = item.get("payload")
            if not isinstance(payload, dict):
                return None
            return json.loads(json.dumps(payload))

    def _cache_set(self, cache_key: str, payload: Dict[str, Any]) -> None:
        with self._cache_lock:
            self.scan_cache[cache_key] = {
                "expires_at": time.time() + SCAN_CACHE_TTL_SECONDS,
                "payload": json.loads(json.dumps(payload)),
            }

    def analyze_target(self, target_input: str, threshold: int = DEFAULT_THRESHOLD) -> Dict[str, Any]:
        self._ensure_loaded()

        target = str(target_input or "").strip()
        if not target:
            return {"error": "Target is required."}

        normalized_threshold = max(0, min(100, int(threshold)))
        cache_key = f"v1:{target.lower()}:{normalized_threshold}"
        cached = self._cache_get(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        collected = self._collect_site_data(target)
        if "error" in collected:
            return collected

        analysis_items = {
            "headers": collected.get("headers", {}),
            "html": collected.get("html", ""),
            "meta": collected.get("meta", {}),
            "cookies": collected.get("cookies", {}),
            "scriptSrc": collected.get("scriptSrc", []),
            "scripts": collected.get("scripts", ""),
            "url": collected.get("url", ""),
            "text": collected.get("text", ""),
            "css": collected.get("css", ""),
            "dns": collected.get("dns", {}),
            "robots": collected.get("robots", ""),
        }

        detections = self.analyze(analysis_items)
        resolved = self._resolve_raw(detections)
        self._apply_cybershield_enhancements(analysis_items, resolved)

        output = self._build_output(collected, resolved, normalized_threshold)
        output["cached"] = False

        self._cache_set(cache_key, output)
        return output


_ENGINE_SINGLETON: Optional[TechFingerprintEngine] = None
_ENGINE_SINGLETON_LOCK = threading.Lock()


def get_tech_fingerprint_engine() -> TechFingerprintEngine:
    global _ENGINE_SINGLETON

    if _ENGINE_SINGLETON is not None:
        return _ENGINE_SINGLETON

    with _ENGINE_SINGLETON_LOCK:
        if _ENGINE_SINGLETON is None:
            _ENGINE_SINGLETON = TechFingerprintEngine()
    return _ENGINE_SINGLETON
