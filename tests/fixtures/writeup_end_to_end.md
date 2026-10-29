---
title: Blackfield
tags: [htb, windows]
status: published
---

## Blackfield - 10.10.10.192

Notes drafted in the vault, see [[Kerberos Delegation Notes]].

### Enumeration

```
$ nmap -sC -sV -p- 10.10.10.192 -oA /home/jordan/htb/blackfield/nmap/full
```

My tun0 address was 10.10.14.37 for this session.

### Foothold

Dumped hashes with secretsdump:

```
svc_backup:1000:aad3b435b51404eeaad3b435b51404ee:9658d1d1dcd9250115e2205d9f48400d:::
```

NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c

### Loot

```
$ cat C:\Users\svc_backup\Desktop\user.txt
0123456789abcdef0123456789abcdef
```

Root flag: fedcba9876543210fedcba9876543210

Reported to a.reporter.personal@gmail.com and AWS_KEY=AKIAIOSFODNN7EXAMPLE was in env.

TODO: add the BloodHound screenshots.
