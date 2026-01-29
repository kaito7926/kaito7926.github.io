---
title: (English) Cybersecurity Students Writeup 2025
date: 2025-10-21 07:38:33
top_img: /img/SinhVienANM/sinhvien.png
cover: /img/SinhVienANM/sinhvien.png
categories:
  - Web Exploit
  - Writeup CTF
toc: true
---
> In this cybersecurity student competition, our team made it to the finals of Group B, and below are the web challenges we solved, mainly web challenge sections.
# Challenge Leak Force
![alt text](/img/SinhvienANM/image.png)
First, in the challenge, we'll see a login page. Let's create an account and log in. The HTTP history looks like this:
![alt text](/img/SinhvienANM/image-1.png)
As we can see, when logging in, it fetches a random `/api/profile?id=1492` and returns a response with the user's information:
```json
{"id":1492,"fullName":"solve 123","username":"anhphuc","email":"anhphuc@example.com","description":"New user","avatar":"https://i.pinimg.com/1200x/d3/88/5e/d3885e4a5748dddbb9b874dc0cf6fabd.jpg","birthdate":null,"gender":null,"company":null}
```
After reviewing it, I discovered that this web application has an IDOR vulnerability that allows viewing other people's account information by changing the ID parameter:
![alt text](/img/SinhvienANM/image-2.png)
And the source code shows that we have an admin page user. After logging in, the flag will be displayed as follows:
```html

<!-- Admin panel (visible only for admin user) -->

<div id="adminPanel" class="card p-3 mt-4 d-none">

<h5 class="card-title">Admin: User Management</h5>

<div class="table-responsive">

<table class="table table-sm table-striped mb-0">

<thead>

<tr>

<th>ID</th>

<th>Username</th>

<th>Name</th>

<th>Email</th>

<th>Actions</th>

</tr>

</thead>
<tbody id="adminUserTable"></tbody>

</table>

</div>

</div>
[.....]

<!-- Modal for flag -->

<div class="modal fade" id="flagModal" tabindex="-1" aria-hidden="true">

<div class="modal-dialog modal-dialog-centered">

<div class="modal-content p-4">

<h5 class="modal-title"><i class="bi bi-trophy"></i> FLAG</h5>

<pre id="flagContent" class="bg-light p-2 rounded"></pre>

<div class="text-end">
<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>

</div>
</div>

</div>

</div>
```
Okay, so we can identify the vulnerability now. How can we get the Admin user? Luckily, this application has a user password update function. We can update the current user's password.
![alt text](/img/SinhvienANM/image-3.png)

535
Ah, I found the admin ID is 1. So now, let's assume we can exploit the password update to update the admin ID. Yes, we can update it. Let's see:
![alt text](/img/SinhvienANM/image-4.png)
Now we can log in with the admin user and proceed to get the token.
![alt text](/img/SinhvienANM/image-5.png)
Then, proceed to retrieve the flag by sending the admin token and successfully get the FLAG.
![alt text](/img/SinhvienANM/image-6.png)
This part took me quite a long time even though it's easy because many people accessing the server might update the admin password repeatedly, making authentication impossible.

## Challenge ZC-1
![alt text](/img/SinhvienANM/image-7.png)
Let's analyze the first challenge. When I accessed the website, I saw that it returned a 404. I thought the challenge was faulty, but when I asked the author, they said that's how it is :v
![alt text](/img/SinhvienANM/image-8.png)
There's not much to do here, let's delve into the source code to analyze in detail why.
Source Code: <a href="https://github.com/capt-bl4ck0ut/Challenge-Web/tree/main/SVANM-2025/ZC_1/public">ZC-1</a>
The source code has two parts: app1 and app2. App1 uses (Django + DRF, port 8000) and app2 uses (PHP Apache, port not published), which is why the application returns a 404 not found error. After examining the structure of app1, it has routes <b>/gateway/user/</b> used to create new users.
```py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
# from . import views

gateway_router = DefaultRouter()
gateway_router.register('', GatewayViewSet, basename='gateway')

user_router = DefaultRouter()
user_router.register('', UserViewSet, basename='user')

urlpatterns = [
    path('', include(gateway_router.urls)),
    path('user/',include(user_router.urls))
    # path('auth')
]
```
With the corresponding username, password, and email parameters:
```py
from rest_framework import serializers

from gateway.models import User


class UserSerializer(serializers.ModelSerializer): 
class Meta: 
model = User 
fields = ['username', 'email']


class AuthSerializer(serializers.ModelSerializer): 
email = serializers.EmailField(required=False) 
class Meta: 
model = User 
fields = ['username', 'email','password']
```
Go to <b>/auth/token/</b> route to get the token or recreate the token of the newly created user
```py
urlpatterns = [ 
[....] 
path('auth/token/', TokenObtainPairView.as_view(), name='token_pair'), 
path('auth/refresh-token/', TokenRefreshView.as_view(), name='token_refresh'),
]
```
Then we can pass data via the route <b>/gateway/transport</b> to receive a compressed file from the user
```py

@action(detail=False, methods=['post'], url_path='transport')

def transport(self, request: Request, *args, **kwargs):

file = request.FILES["file"].file

if not check_file(file):

return Response(data="Invalid file")

file.seek(0)

msg = transport_file(str(request.user.id), file)

return Response(data=msg)
```
Then call the checkfile function to check the allowed file type
```py
STORAGE_URL = env("STORAGE_URL",default="http://127.0.0.1:8002")
ALLOW_STORAGE_FILE = ("".txt",".docx",".png",".jpg",".jpeg")
```
```py

def check_file(file): 
try: 
with zipfile.ZipFile(file,"r") as zf: 
namelist = zf.namelist() 
if len([f for f in namelist if not f.endswith(allow_storage_file)]) > 0: 
return False 
except: 
return False 

return True
```
then call <b>transport_file()</b> to push the file straight to <b>app2/src/storage.php</b>
```py
def transport_file(id, file): 
try: 
res = requests.post( 
url= storage_url + "/storage.php", 
files={
"id":(None,id),

"file":file

},

allow_redirects=False,

timeout=2

)
return "OK"

except Exception as e:

return "ERR"
```
Next, it will call <b>/gateway/health?module=...</b> call requests.get(STORAGE_URL + module) and only return “OK/ERR” according to the HTTP status, not the body.

```py
def health_check(module):

try:

res = requests.get(storage_url + module, timeout=2)

if res.status_code == 200:

return True

return False

except:

return False
```
And in app2, in the file <b>storage.php</b>, use the <b>gemorroj/archive7z</b> library to wrap 7-Zip to extract the correct file we uploaded to <b>/var/html/storage/<id></b> (id is the user's UID)
```php
<?php

require "vendor/autoload.php";

use Archive7z\Archive7z;

if(isset($_POST['id']) && isset($_FILES['file'])){ 
$storage_dir = __DIR__ . "/storage/" . $_POST['id']; 

if(!is_dir($storage_dir)){ 
mkdir($storage_dir); 
} 

$obj = new Archive7z($_FILES["file"]["tmp_name"]); 
$obj->setOutputDirectory($storage_dir); 
$obj->extract();
}
?>
```
With the detailed analysis above and after further research, I discovered a vulnerability in 7z where symlinks can be used to arbitrarily overwrite files during extraction, causing <a href="https://security.snyk.io/research/zip-slip-vulnerability?utm_source=chatgpt.com">7z</a> and we can build a POC like this page <a href="https://book.jorianwoltjer.com/forensics/archives#zip-file-extracting-as-7z">POC</a>
## Exploitation.

Now let's create a user to get the corresponding token and UID

![alt text](/img/SinhvienANM/image-12.png)
Proceed to call /auth/token to authenticate the token with the username and password of the newly created user.
![alt text](/img/SinhvienANM/image-13.png)
Get user_id
![alt text](/img/SinhvienANM/image-14.png)
Next, we have the exploitation process
1. First, we create a valid file in app1 to check and compress it into a zip file
2. Then create a revershell file <a href="https://pentestmonkey.net/tools/web-shells/php-reverse-shell?utm_source=chatgpt.com">Revershell PHP</a> using 7z to zip it
3. Then put the two files into one arbitrary file
4. Proceed to upload the shell
5. Then call gateway/health/?module=/storage/$USER_ID/shell.php to activate our uploaded shell
Below, I will summarize the above processes step by step as follows:
![alt text](/img/SinhvienANM/image-15.png)
![alt text](/img/SinhvienANM/image-16.png)
![alt text](/img/SinhvienANM/image-17.png)
Now the server revershell has successfully received the shell from our trigger.
![alt text](/img/SinhvienANM/image-18.png)
Then, interacting with the command, we get the FLAG:
<b>CSCV2025{Z1p_z1P_21p_Ca7_c47_c@t__}</b> Unfortunately, I solved this problem at the last minute and couldn't submit it :v

## Challenge PortfolioS
![alt text](/img/SinhvienANM/image-19.png)
First, when you enter the challenge, it will display the login and registration page. Let's try creating a new user. After logging in, it redirects to the main page, and the HTTP history is as follows:
![alt text](/img/SinhvienANM/image-20.png)
After entering any value, it will save it as portfolio_<RANDOM>.md and has a download function.
![alt text](/img/SinhvienANM/image-21.png)
And the downloaded value has the format of an md file as follows:
![alt text](/img/SinhvienANM/image-22.png)
We can't do much here, let's go into analyzing the <link href="https://github.com/capt-bl4ck0ut/Challenge-Web/tree/main/SVANM-2025/PortfolioS">Source Code</link> First, we will find where the flag is located. I found it in the Dockerfile. The random value has 16 characters, and the application runs in Java. This challenge hints from the author that it's written in SpringBoot.

```dockerfile
FROM openjdk:17-jdk-slim

WORKDIR /app

COPY portfolio.war portfolio.war
COPY flag.txt /flag.txt

RUN groupadd -r webgroup && \
useradd -r -g webgroup -m -d /home/web web && \

mkdir -p /app/data && \
chown -R web:webgroup /app && \

chmod 555 /app/portfolio.war && \

chmod 770 /app/data && chown web:webgroup /app/data && \

RAND_NAME=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16) && \

mv /flag.txt "/${RAND_NAME}" && \

rm -f /flag.txt && \

chown root:root "/${RAND_NAME}" && chmod 444 "/${RAND_NAME}"

USER web

EXPOSE 8989

ENTRYPOINT ["java", "-jar", "/app/portfolio.war"]

```
In the nginx route we can see it will block us to /internal/testConnection
```nginx
events {}

http {
server {
listen 80;

location = /internal/testConnection {
return 403;

}

location / {
proxy_pass http://app:8989;

proxy_set_header Host $host:8989;
proxy_set_header X-Real-IP $remote_addr; 
}

}
}
```
After researching, I found that the server uses nginx version: <b>nginx/1.20.2</b>
![alt text](/img/SinhvienANM/image-23.png)
After researching, I found the document <a href="https://blog.bugport.net/exploiting-http-parsers-inconsistencies">Exploiting HTTP Parsers Inconsistencies</a> which can bypass it in Spring Boot by using the character <b>\x09</b>. Here, Spring Boot will remove the character, but on the nginx server, it doesn't allow us to bypass it. Let's do it as follows:
![alt text](/img/SinhvienANM/image-24.png)
Then, enter the random username and password parameters, and it will report an error: yes, we can see the source code in this internal route.

![alt text](/img/SinhvienANM/image-25.png)
In the source code, we can see the application This method uses the username and password directly appended to the parameters without input filtering, allowing an attacker to insert commands to RCE.

```java

@PostMapping({"/testConnection"})

public String testConnection(@RequestParam String username, @RequestParam String password, Model model) {

if ((username + password).length() >= 95) {
model.addAttribute("error", "Username + password to long.");

return "internal";

} else {
String baseUrl = "jdbc:h2:mem:test;";

String fullUrl = baseUrl + "USER=" + username + ";PASSWORD=" + password + ";";

```
Also, it uses a common error message, which can leak information through its error message.
```java

try {
model.addAttribute("message", "Connected successfully to: " + fullUrl);

var7 = "internal";

} catch (Throwable var10) {

if (conn != null) {

try {
conn.close();

} catch (Throwable var9) {
var10.addSuppressed(var9);

}

}

throw var10;

}

if (conn != null) {
conn.close();

}

return var7;

} catch (Exception var11) {
String var10002 = var11.getMessage();

model.addAttribute("error", "Connection failed: " + var10002 + " | URL: " + fullUrl);

return "internal";

}
}
```
After reviewing and investigating, I learned that this application has a vulnerability: <b>H2 JDBC Connection String Injection → RCE</b>. However, when I got to this point, I tried to find a way to call <b>ALIAS EXEC</b> to execute or even write to the file, but I still couldn't get the application to trigger RCE [......]
![alt text](/img/SinhvienANM/image-26.png)

