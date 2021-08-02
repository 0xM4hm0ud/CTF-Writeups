# Expic 
<img src="Images/challenge.png" width="500" >

So after downloading the zip file, I unzipped it and checked what kind of file it is:

<img src="Images/file.png" width="800" >

So I checked the file with exiftool and found a string:

<img src="Images/exiftool.png" width="800" >

It's an hex string, I decoded it and got a pastebin link:

<img src="Images/hex.png" width="800" >

On the pastebin site we found a base64 string:

<img src="Images/base64.png" width="800" >

After decoding it we got the flag:

<img src="Images/flag.png" width="800" >

Flag: RTL{10bba9a52417095de51db9456361d744}
