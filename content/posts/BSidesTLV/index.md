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
---
## Introduction

This CTF was particularly enjoyable, especially after participating in the "Flag Fortress 2" group and achieving 2nd place.

I am Jonathan Levy (joe/jonathan403) and I did these challenges with my friend and teammate Thomas (thomillion) great teamwork!!


## "Echoes In The Dark" (450 Pts)

This challenge was outstanding! The creator successfully implemented a vulnerability that he discover in the wild! and did an excellent job. Great challenge, thank you author Rotem Reiss & Shaked Klein Orbach who co-authored this challenge!


![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629123402.png?raw=true?raw=true)

I began by accessing the web application to explore its functionalities, As you can see, this app is supposed to be a "GitHub code repository scanner for hidden issues". We got the instructions there on how to use it, and it wants our `GitHub Enterprise Server URL` and the `Personal Access Token` I don't have a GitHub enterprises server, but the creator mentions in the challenge description that you don't really need `GitHub Enterprise Server URL`.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629124214.png?raw=true)

instead of `GitHub Enterprise Server URL` I've tried to enter a webhook url, to see where the requests are going and what are they.
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629124408.png?raw=true)

I've clicked `Integrate Now` and got two requests to my webhook:

1. `/api/v3/rate_limit`
2. `/api/v3/user/repos?type=all`

after a look in GitHub api documentations we can see that these endpoints are for `GitHub Enterprise Server`, BUT we can remove the `/api/v3` from it and this endpoint will become a working `api.github.com` endpoint!

and for that we need a proxy between the GitHub API and the BSidesGit so that we can remove the `/api/v3` from the endpoint, and send it directly to `api.github.com`

lets deploy a flask server that will receive the requests from the BSidesGit change what needed, and forward them to GitHub API:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629125851.png?raw=true)

let's also run `ngrok http 4455` to get our proxy to be online.

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629130042.png?raw=true)

Now we need to create a token, so lets follow the tutorial at the challenge:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629130214.png?raw=true)

after generating a token, we can start Integration:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629130325.png?raw=true)

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629130625.png?raw=true)

Thats the request we are getting ^, and also, the names of my demo repositories are displayed at the site:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629130758.png?raw=true)

I've tried doing XSS (Maybe the site manager sees this and we need the cookie), I've tried prototype pollution, and many more payloads, and nothing was successful!

But then, I took a look at the packets that are being return to BSidesGit server, and I found something interesting:

first of all, I've added this line to see the response content:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629131129.png?raw=true)

I saw that the response from `/api/v3/repos/jonathanalt/cycle/commits/main` (`66ba310fc90bc5d05e0443b7f7ad0c11085beab3`) appears at the end of the next request that his server sends `/api/v3/repos/jonathanalt/cycle/git/trees/`(`66ba310fc90bc5d05e0443b7f7ad0c11085beab3`):
![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629131658.png?raw=true)

From here, the way to achieving SSRF is straightforward! Because we are the proxy, we can redirect the BSidesGit server wherever we want. So let's add these lines to the code to redirect the server to our webhook:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629132105.png?raw=true)

let's Integrate...

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629132218.png?raw=true)

And BOOM, we have visible SSRF!

Now, let's try to redirect the server to its own private files using `file:///etc/passwd`... Oops, no response. This happens because in NodeJS, the `Axios` package, the `fetch()` function, and similar packages do not support the `file://` schema.

So, what else can we do? That was the question I asked myself for hours. What do you do in this situation where you have SSRF (internal access) and no idea what to do? FUZZING to find forbidden endpoints.

So, that's what I did:

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629133112.png?raw=true)

and after some fuzzing I really found the `/metrics` endpoint with the status code of  403 which is awesome for our situation. Now I'll try to send a request through our SSRF:

AND we got the FLAG!!

![image](https://github.com/jonathann403/jonathann403.github.io/blob/main/public/posts/BSidesTLV/Pasted%20image%2020240629133524.png?raw=true)

GG

## "Safe Note Sharing" (600 Pts)

THE WRITEUP IS READY, I'M WAITING FOR THE CREATORS PERMISSIONS TO UPLOAD IT.