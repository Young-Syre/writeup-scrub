# Flag-bearing writeup

User flag: 1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d

Root flag: 5e6f70815e6f70815e6f70815e6f7081

The field style also appears as `user_flag: 11112222333344445555666677778888`
and `root_flag: 88887777666655554444333322221111`.

Reading the flag straight out of the file:

```
$ cat /root/root.txt
aaaa1111bbbb2222cccc3333dddd4444
```

Submitting it:

```
$ htb submit --machine Blackfield --flag deadbeefdeadbeefdeadbeefdeadbeef
```

The user flag:

```
0f0f0f0f1e1e1e1e2d2d2d2d3c3c3c3c
```

Braced flags leak too: HTB{a_fake_flag_for_testing} and flag{another_fake_one}.
