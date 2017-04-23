# PicoCTF-2017

## Weird RSA - 90

We have:
```
c: 95272795986475189505518980251137003509292621140166383887854853863720692420204142448424074834657149326853553097626486371206617513769930277580823116437975487148956107509247564965652417450550680181691869432067892028368985007229633943149091684419834136214793476910417359537696632874045272326665036717324623992885
p: 11387480584909854985125335848240384226653929942757756384489381242206157197986555243995335158328781970310603060671486688856263776452654268043936036556215243
q: 12972222875218086547425818961477257915105515705982283726851833508079600460542479267972050216838604649742870515200462359007315431848784163790312424462439629
dp: 8191957726161111880866028229950166742224147653136894248088678244548815086744810656765529876284622829884409590596114090872889522887052772791407131880103961
dq: 3570695757580148093370242608506191464756425954703930236924583065811730548932270595568088372441809535917032142349986828862994856575730078580414026791444659
```

The techique of solving RSA with dp and dq could be found online.
Check out at Wikipedia: <https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Example><br/>
Here is a simple approach using Sage Math

```python
sage: d = inverse_mod(65537,phi)
sage: qi = pow(q,-1,p)
sage: m1 = pow(c,dp,p)
sage: m2 = pow(c,dq,q)
sage: h = (qi*(int(m1)-int(m2)))%p
sage: m = int(m2) + h*q
sage: hex(int(m))[2:-1].decode("hex")
'Theres_more_than_one_way_to_RSA'
```
<hr>

## Hashchain - 90

From the hint, weakness of MD5: too fast to calculate!

First I was thinking of storing a few thousand user ID and seed, so that I can pick one as I get the flag. But then I realize the seed is actually md5(userID), so the process is a lot easier.

```
☕️ ➜  pico2017 nc shell2017.picoctf.com 5715

*******************************************
***            FlagKeeper 1.1           ***
*  now with HASHCHAIN AUTHENTICATION! XD  *
*******************************************

Would you like to register(r) or get flag(f)?

r/f?

f
This flag only for user 3862
Please authenticate as user 3862
27e9bcd092c58f7c358d490ce67c5eb4
Next token?

```
Just need a simple code to get the hash that is previous to the given one in the chain
```python
import md5

seed = "3862"
check = "27e9bcd092c58f7c358d490ce67c5eb4"

hashc = seed
prev = ""

while True:
	prev = hashc
	hashc = md5.new(hashc).hexdigest()
	if hashc == check:
		print prev
		break    

```
Submit the hash and I got the flag
```python
fd25d5eb5ccaee7cd9e19aa19a6716c7
Hello user 3862! Here's the flag: b41769e77d350c3d5655eab553221f0c
```
<hr>

### Broadcast - 120

```python
e = 3
c1 = 261345950255088824199206969589297492768083568554363001807292202086148198632298416227800170521403879169323939870136918495166376001415603107530798184803733942230649625863328280827871999560410058158409477539013408803889636337981870043792827095136037430392653831785807945977864288192407940225619843273330120029313
c2 = 147535246350781145803699087910221608128508531245679654307942476916759248403409499940709875170482499717373851969854700407365859710668248221534523112910895863625501694252104929562808450560410931902051428001118134260015071473417379253511812576559427770355902270332217159041674805147868562215268081818231962157802
c3 = 633230627388596886579908367739501184580838393691617645602928172655297372237425265855898468213006428127058041006464863408951623696827190570241149630919096283514787011922034385643767864879634861850565793738024061098801151563062727926809059198778760627479771564465550880228117974715945657575773914891371732645934
n1 = 1001191535967882284769094654562963158339094991366537360172618359025855097846977704928598237040115495676223744383629803332394884046043603063054821999994629411352862317941517957323746992871914047324555019615398720677218748535278252779545622933662625193622517947605928420931496443792865516592262228294965047903627
n2 = 405864605704280029572517043538873770190562953923346989456102827133294619540434679181357855400199671537151039095796094162418263148474324455458511633891792967156338297585653540910958574924436510557629146762715107527852413979916669819333765187674010542434580990241759130158992365304284892615408513239024879592309
n3 = 1204664380009414697639782865058772653140636684336678901863196025928054706723976869222235722439176825580211657044153004521482757717615318907205106770256270292154250168657084197056536811063984234635803887040926920542363612936352393496049379544437329226857538524494283148837536712608224655107228808472106636903723
```

This is the basic case of Hastad's Broadcast attack on RSA, we have 
```python
c1 = m^3 (mod n1)
c2 = m^3 (mod n2)
c3 = m^3 (mod n3)
```
Using the Chinese Remainder Theorem (crt() in sage), we can easily computer the `M=m^3`
```python
sage: M = crt([c1,c2,c3],[n1,n2,n3])
sage: m = M1 ** (1/3)
sage: hex(int(m))[2:-1].decode("hex")
'broadcast_with_small_e_is_killer_67051493201'
```
<hr>

## SmallRSA - 120

This RSA has a really large encryption exponent e ( e~ the size of N) and from the hint, we can guess that d should be small

Using the Wiener's attack on small private key
<https://en.wikipedia.org/wiki/Wiener%27s_attack><br>

k/d is somewhere among the convergents of e/N

```python
sage: lst = continued_fraction(e/n)
sage: conv = lst.convergents()
sage: for i in conv:
....: 
....:     k = i.numerator()
....:     d = i.denominator()
....: 
....:     try:
....:         m = hex(int(pow(c,d,n)))[2:-1].decode("hex")
....:         if "flag" in m:
....:             print m
....:     except:
....:         continue
....:     
flag{Are_any_RSA_vals_good_13441315963}
```
<hr>

## SmallSign - 140

We have to forge a RSA signature of a challenge in 60 sec, given the ability to query signature of any number we want, before the challenge appears/or we run out of time. 

Here is the idea, 
let `s[i]` be the signature of `m[i]`, ignore the fact that there's hashing, the encryption should be like:
 `s[i] = m[i]^d mod N`

So, the challenge give us a `m`, ask us for `s`, then if we have all the prime factors of `m` and their signatures, we can surely reconstruct `s`.
 `m = m[1]*m[2]*m[3]*...*m[n]`
then 
 `s = ( s[1]*s[2]*s[3]*...*s[n] ) mod N`

Since the challenge gave us 60s (I think it's actually 30s :( ), we have to query all the possible signatures of primes we can (about ~600 primes), and wish for a smooth number as our "challenge"
Here is my script:

```python
from pwn import *

lstPrime[] = ['''<list of first 600 primes here>''']

test_data = 600

while (True):
	host, port = "shell2017.picoctf.com", 5596
	r = remote(host, port)

	rule = re.compile('[0-9]')
	data = r.readuntil("(-1 to stop):")
	data = rule.findall(data)
	data = "".join(data)
	data = data[2:-6]

	n = int(data)
	lstSign = []

	count = 0

	print "start collecting data"
	
	try:
		while count<=test_data:
    
    			r.writeline(str(lstPrime[count]))

    			data = r.readuntil("(-1 to stop):")
    
    			# print data

    			chal = rule.findall(data)[:-1]
    			chal = "".join(chal)
    			chal = int(chal)

    			lstSign.append(chal)
    			count += 1
    			# print count
	except:
		print "query out of time"
		test_data -= 10
		print "try smaller test data", test_data
		continue

	print "finish colelcting data"
	r.writeline("-1")

	data = r.readuntil("challenge:")
	print data
	
	chal = rule.findall(data)
	chal = "".join(chal)
	chal = int(chal)
	print "challenge:", chal

	i = 0
	s = 1
	found = True
	print ""
	while (chal<>1):
    
    		if i>=count:
        		print "not found"
        		found = False
			break

    		if (chal % lstPrime[i] == 0):
			s = s * lstSign[i]
        		chal = chal/lstPrime[i]
        		print lstPrime[i], lstSign[i]
    		else:
        		i += 1
        		continue

	if (not found):
		r.close()
		print "Cannot find sign of divisor, try again ..."
	else:
		
		print "N: ", n
		sign = s%n 
		
		print "\n", sign
		r.writeline(str(sign))
		print r.readall() 
		break
	
