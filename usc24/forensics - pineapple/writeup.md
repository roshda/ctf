# USC CTF 2024 - forensics/Pineapple
*published: 2024-11-30*

This is my writeup for the "Pineapple" (forensics - network analysis) challenge at USC CTF 2024. I played the CTF this weekend with Psi Beta Rho at UCLA. 


In this challenge, we were given a .pcapng file which is basically a type of packet capture file that shows intercepted network traffic. Our task was to examine this traffic to uncover any data that might reveal a flag.

I loaded pineapple.pcapng in Wireshark, a tool to analyze network traffic/packets. This shows all the packets in the capture, with info like source and destination IPs, protocols, and a summary for each packet. I filtered by HTTP traffic because it usually includes readable data, which could contain usernames, file uploads, or other useful information. 


Form Data and POST Requests

I first followed the HTTP stream for this application form url encoded packet and I saw this form data with some info:

- username: jbarker
- filename: hoolicon
- filepw: conjoined_TRIANGLES


This means that it probably had something to do with a file submission involving a filename (hoolicon) and an encryption key (conjoined_TRIANGLES) we could use to view the file.

Then I looked at another POST request (type of HTTP request used to send data to a server) TCP stream to find this data for this hoolicon file. (A TCP stream in Wireshark is a way to view the flow of data, packets, between two devices over the TCP (Transmission Control Protocol) as a stream/conversation)

It showed that the data was in 7z format which is like a compressed format that supports encryption as well.  


I also saw this metadata at the bottom showing that the flag image is probably in the archive …

```"f.l.a.g.i.m.g....p.n.g"```

Then I exported this. I saved the raw data as multipart_data.bin so I could use binwalk to extract the embedded 7z archive. The decimal part is saying that the first 175 bytes of the bin file are not in the 7zip archive format. (This is from any HTTP headers included when we downloaded the stream.)

```binwalk –extract multipart_data.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------
175           0xAF            7-zip archive data, version 0.4


I ran this command to cut out the 175 bytes of multipart_data.bin.

**rd@rd-Latitude-E7270**:~$ dd if=multipart_data.bin of=hoolicon.7z bs=1 skip=175
452819+0 records in
452819+0 records out
452819 bytes (453 kB, 442 KiB) copied, 2.089 s, 217 kB/s
```

This command extracted the .7z file from the binary data, saving it as hoolicon.7z

Since the old form data included filepw=conjoined_TRIANGLES, we used this as the password to decrypt the archive:

```rd@rd-Latitude-E7270:~$ 7z x hoolicon.7z -pconjoined_TRIANGLES

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz (406E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 452819 bytes (443 KiB)

Extracting archive: hoolicon.7z

WARNINGS:
There are data after the end of archive

--
Path = hoolicon.7z
Type = 7z
WARNINGS:
There are data after the end of archive
Physical Size = 452754
Tail Size = 65
Headers Size = 162
Method = LZMA2:19 7zAES
Solid = -
Blocks = 1

Everything is Ok

Archives with Warnings: 1

Warnings: 1
Size:       452550
Compressed: 452819
```


This produced the flagimg.png which showed the flag: 
```
CYBORG\{pe4cefaRe_4x09\}
```
Thanks for the challenges USC CTF team!



