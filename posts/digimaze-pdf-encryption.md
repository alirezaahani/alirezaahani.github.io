---
title: Digimaze pdf encryption 
layout: posts.liquid
is_draft: false
published_date: 2025-05-26 23:42:00 +0330
description: Attempt at breaking the Digimaze pdf encryption 
---
<p class="notice" style="color: red">
This post is for educational purposes only. The author does not endorse piracy or unauthorized access to copyrighted material.
</p>

[DigiMaze](https://digimaze.org/) is a digital library developed by [BioMaze education group](https://biomaze.ir/), offering users access to a range of e-books, mostly academic textbooks, supplementary learning materials, exam preparation books, accessible via smartphone, tablet or a PC. All purchased books remain permanently in the user's account, and a sample preview is available before purchase. 

This business model is similar to other competitors in the same space such as [Gajino](https://app.gajino.com/) from [Gaj education group](https://www.gaj.ir/), you buy access to the book for a limited time and you have access to all their books.

To investigate I first installed the app on my PC, they offer versions for Android, iOS and Windows (10 and 11). I found two installed apps: `digimaze` and `Digimaze PDF Reader`. The first one seems like a classic Windows app (with .exe, .dll files installed into `Program Files`) and the second seems like a Microsoft Store App (which is kinda odd.).

You use the Digimaze app to browser your account, purchase subscription, etc. When you open a book from the app, the pdf reader launches. The main app only opens books when run as administrator, other times it just refuses to open the pdf reader, I have not investigated the reason for this, Their guide suggests running the app always as administrator, An awful security practice. 

The main app is installed inside:  
```
C:\Program Files (x86)\Viranegar\digimaze
```
It appears to be a Flutter app, the compiled `app.so` from Dart is not very big (16MB in size). I tried Ghidra on it, but no success (I haven't dealt with Flutter apps before so I am not sure what extra things I need to do).

The pdf reader is installed inside: (which has limited permissions)
```
C:\Program Files\WindowsApps\com.vnegar.digimaze.reader_X.X.X.X_x64__YYYYY
```
It does not appear to be Flutter or C# app (the usual suspects for Iranian apps.). It looks like this (and the Digimaze app) was developed by [Viranegar](https://viranegar.com/).

The downloaded pdf files (and other files for the digimaze app) seem to be inside:
```
C:\Users\[USER]\AppData\Roaming\com.vnegar\digimaze
```
The pdfs are encrypted with passwords.

I did not have the patience to try to find how the passwords are retrived and sent to the pdf reader app, seeing how pdf reader could easily manipulate the pdf, I had a theory that the passwords are maybe inside the app's memory. 

Taskmgr has a cool feature where you can dump the whole memory of a program into a file, so I did, for the `RDPDFReader.exe` app. The dumps are stored inside:
```
C:\Users\[USER]\AppData\Local\Temp
```

I opened the dump using a hex editor, search for `.pdf`, and look what I found:

```
..........C:\Users\[USER]\AppData\Roaming\com.vnegar\digimaze\attachment_XXXXXXX.pdf***ftCQYnZ4jRSWni4k$doZPqhbtm8No!Yw..............................
```

The pdf and its password is literally stored next to each other, only separated by three stars. This is just too easy.
You can open the pdf using the password, and remove the password forever it by printing to pdf again.

Hopefully sometime I look more into these apps and I can find out from where was this password retrived.