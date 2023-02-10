## Install MIT Kerberos 5 on Debian GNU, Ubuntu, and Devuan GNU+Linux

Davor Ocelic
Copyright  2006-2019 Davor Ocelic
Last update: Aug 24, 2019. — Add PKINIT instructions

This documentation is free; you can redistribute it and/or modify it under the terms of the [GNU](https://www.gnu.org/) General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

**Abstract**

The purpose of this article is to give you a straightforward, [Debian](https://www.debian.org/)/[Ubuntu](https://www.ubuntu.com/)/[Devuan](https://www.devuan.org/)-friendly way of installing and configuring MIT Kerberos 5.

By the end of this guide, you will have a functional Kerberos environment and one Kerberized service — the ability to login remotely to other machines in the network in a secure, encrypted and transparent way, without the need for typing in any passwords, and including SSH PKI authentication.

This article is part of [Spinlock Solutions](http://www.spinlocksolutions.com/)'s practical 3-piece introductory series to infrastructure-based Unix networks, containing [MIT Kerberos 5 Guide](http://techpubs.spinlocksolutions.com/dklar/kerberos.html), [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html) and [OpenAFS Guide](http://techpubs.spinlocksolutions.com/dklar/afs.html).

------

**Table of Contents**

[TOC]

## Introduction

Kerberos is a service that has been traditionally captivating system administrators' and advanced users' interest, but its seemingly high entry barrier and infrastructure requirements have been preventing many from using it.

Kerberos has already been the topic of numerous publications. Here, we will present only the necessary summary; enough information to establish the context and to achieve practical results.

You do not need to follow any external links; however, the links have been provided both throughout the article and listed all together at the end, to serve as pointers to more precise technical treatment of individual topics.

### The role of Kerberos within a network

Kerberos is intended to centrally authenticate users, hosts, and services on the network by verifying them against entries in the [Kerberos database](http://kerberos.org/software/tutorial.html#1.3.5.1).

These entries (called "[principal](http://kerberos.org/software/tutorial.html#1.3.2)s") consist of principal names, [secret key](http://kerberos.org/software/tutorial.html#1.3.4)s, key aging (expiry) information, and [Kerberos-specific](http://kerberos.org/software/tutorial.html#1.3.5.1) data. They are created or modified using a Kerberos-specific administrative tool called **kadmin**.

When users type in their principal name and password anywhere on the network (within a Kerberos [realm](http://kerberos.org/software/tutorial.html#1.3.1)), their input is authenticated in a secure way against the Kerberos database. In case of a successful authentication, the [KDC](http://kerberos.org/software/tutorial.html#1.3.5) ("`Key Distribution Center`") will *issue* users a "confirmation", called the [TGT](http://kerberos.org/software/tutorial.html#1.5.1) ("`Ticket-Granting Ticket`"). From that point on, and until their ticket expires, users will be transparently granted access to all network services they'll wish to use. (The TGT will not grant access by itself — instead, it will be used as the credential to automatically create further tickets for specific services, once users attempt to access them. Hence its name, the "Ticket-granting Ticket").

While the idea of a centralized network authentication is not unique, let's quickly identify Kerberos-specific elements in the authentication process:

- Kerberos is not in any way related to traditional system usernames or other data; Kerberos identity (or tickets) are obtained using a separate, Kerberos-specific mechanism. Arbitrary system user can obtain arbitrary Kerberos identity (provided they know the correct password (or have the correct PKI certificate when PKINIT is used)).

  Often times, however, the Kerberos identity is obtained as part of log-in to the system and, for convenience, an assumption is made that the person's system login name matches their Kerberos principal name. 

- The [Kerberos database](http://kerberos.org/software/tutorial.html#1.3.5.1) only contains the information necessary for Kerberos authentication; it does not (and can not) contain any other information, such as people's real names, Unix user and group IDs, etc. This makes Kerberos well-defined and easy to fit in a network infrastructure.

  When a central directory is required for users' real names, IDs, meta information and other network information, [OpenLDAP](http://www.openldap.org/) is often used in combination and installed after Kerberos as explained in another article from the series, the [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html).

- Thanks to the design of the protocol, users' passwords never travel the wire in any form; Kerberos thus allows for secure authentication in and over untrusted networks.

- Kerberos requires mutual authentication of users and services, preventing stealing of information.

  To achieve this, Kerberos uses its database to store host and service principals alongside the "real", person-owned principals. This is normal behavior and indeed, the host and service principals will account for the majority of output when you list database entries for the first time after installation.

- As users are only required to authenticate once (after which the TGT is used in place of the password to create further tickets), Kerberos offers a true SSO ("`Single Sign-On`") network solution.

You can find the complete Kerberos documentation at the [MIT Kerberos](http://web.mit.edu/kerberos/) website. Their on-line documentation is, however, only generated in multi-page HTML format — other more convenient formats (such as PostScript) are available within [Kerberos release](http://web.mit.edu/Kerberos/dist/index.html) tarballs.

### Glue layer: integrating Kerberos with system software

On all GNU/Linux-based platforms, [Linux-PAM](http://www.linux-pam.org/) is available for service-specific authentication configuration. [Linux-PAM](http://www.linux-pam.org/) is an implementation of PAM ("`Pluggable Authentication Modules`") from [Sun Microsystems](http://www.sun.com/).

Network services, instead of having hard-coded authentication interfaces and decision methods, invoke PAM through a standard, pre-defined interface. It is then up to PAM to perform any and all authentication-related work, and report the result back to the application.

Exactly how PAM reaches the decision is none of the services' business. In traditional set-ups, that is most often done by asking and verifying usernames and passwords. In advanced networks, that could be retina scans or — Kerberos tickets.

PAM will allow for inclusion of Kerberos into the authentication path of all services, regardless of whether they natively support Kerberos or not.

You can find the proper introduction (and complete documentation) on the [Linux-PAM](http://www.linux-pam.org/) website. Pay special attention to the [PAM Configuration File Syntax](http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html) page. Also take a look at the Linux-PAM(7) and pam(7) manual pages.

### Conventions

Let's agree on a few conventions before going down to work:

- Our platform of choice, where we will demonstrate a practical setup, will be [Debian GNU](https://www.debian.org/). The setup will also work on [Ubuntu](https://www.ubuntu.com/) and [Devuan GNU+Linux](https://www.devuan.org/), and if any notable differences exist they will be noted.

- Please run **dpkg -l sudo** to verify you have the package sudo installed.

  Sudo is a program that will allow you to carry out system administrator tasks from your normal user account. All the examples in this article requiring root privileges use sudo, so you will be able to copy-paste them to your shell.

  To install sudo if missing, run:

  ```
  su -c 'apt install sudo'
  ```

  If asked for a password, type in the root user's password.

  If you want to run sudo without requiring a password, run the following while replacing `USERNAME` with your login name:

  ```
  su -c 'echo "USERNAME ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers'
  ```

  

- Packages that we will install during the complete procedure will ask us a series of questions through the so-called *debconf* interface. To configure debconf to a known state, run:

  ```
  sudo dpkg-reconfigure debconf
  ```

  When asked, answer *interface*=`Dialog` and *priority*=`low`.

- Monitoring log files is crucial in detecting problems. The straightforward, catch-all routine to this is opening a terminal and running: 

  ```
  sudo tail -n0 -F /var/log/{*log,dmesg,messages,kerberos/{krb5kdc,kadmin,krb5lib}.log}
  ```

  The command will keep printing log messages to the screen as they arrive.

- For maximum convenience, the installation and configuration procedure we will show will set everything up on a single machine. It means that the Kerberos server, the SSH server, and the client connecting to them will be on the same machine with an IP address of `192.168.7.12`. You should use your own machine's network address in this place.

  To differentiate between client and server roles, the connecting client will be named `monarch.example.com`, the SSH server will be named `monarch.example.com` (same as the client), and the Keberos server will be named `krb1.example.com`. You can reuse these names, or even better replace them with your appropriate/existing hostnames.

  The following addition will be made to `/etc/hosts` to completely support this single-host installation scheme. **Note that the client machine's hostname parts (\*`monarch`\* in our example) must come before "krb1" in order for things to work as expected**: 

  ```
  192.168.7.12  monarch.example.com monarch krb1.example.com krb1
  ```

  ### Caution

  Note that in some installations the system's network hostname is assigned to the localhost address `127.0.0.1`. This can and will cause problems for network operations. Make sure that your `/etc/hosts` looks exactly like this, except for the actual network IP and hostnames:

  ```
  127.0.0.1  localhost
  192.168.7.12  monarch.example.com monarch krb1.example.com krb1
  ```

  

  Finally, test that the network setup works as expected. Pinging the hostnames should report proper FQDNs and IPs as shown: 

  ```
  ping -c1 localhost
  PING localhost (127.0.0.1) 56(84) bytes of data.
  ....
  
  ping -c1 monarch
  PING monarch.example.com (192.168.7.12) 56(84) bytes of data.
  ....
  
  ping -c1 krb1
  PING krb1.example.com (192.168.7.12) 56(84) bytes of data.
  ....
  ```

## Kerberos 5

Now when everything has been properly prepared, let's move forward.

### Server installation

Kerberos server installation basically consists of just two packages — the KDC (Key Distribution Center), which takes care of handling authentication requests and issuing Kerberos tickets, and kadmind (Kerberos master server), which allows *remote administration access* to the Kerberos database and carrying out of administrative tasks. 

```
sudo apt install krb5-{admin-server,kdc}
```

Here are the Debconf answers for reference. The listing here includes all questions; some were asked in Kerberos 1.6 packages and some are asked only in Kerberos 1.7 and newer, and their order has changed a little as well. In any case, it's no problem — just answer the subset of questions you are asked: 

```
Default Kerberos version 5 realm? EXAMPLE.COM
# (Your domain name in uppercase - a standard for naming Kerberos realms)

Add locations of default Kerberos servers to /etc/krb5.conf? Yes
# (Adding entries to krb.conf instead of DNS, for simplicity)

Kerberos servers for your realm: krb1.example.com
# (Make sure your DNS resolves krb1.example.com to
# the NETWORK IP of the server, NOT 127.0.0.1!). Hint is given in
# the section called “Conventions”.

Administrative server for your Kerberos realm: krb1.example.com
# (Make sure your DNS resolves krb1.example.com to
# the NETWORK IP of the server, NOT 127.0.0.1!). Same hint as above.

Create the Kerberos KDC configuration automatically? Yes

Run the Kerberos V5 administration daemon (kadmind)? Yes
```

As soon as the installation is done, the Kerberos admin server (**kadmind**) and the KDC will try to start. Start may fail since, initially, there are no Kerberos [realm](http://kerberos.org/software/tutorial.html#1.3.1)s created, which is fine.

### Initial configuration

To create the Kerberos realm, invoke:

```
sudo krb5_newrealm

This script should be run on the master KDC/admin server to initialize
a Kerberos realm.  It will ask you to type in a master key password.
This password will be used to generate a key that is stored in
/etc/krb5kdc/stash.  You should try to remember this password, but it
is much more important that it be a strong password than that it be
remembered.  However, if you lose the password and /etc/krb5kdc/stash,
you cannot decrypt your Kerberos database.
Loading random data
Initializing database '/var/lib/krb5kdc/principal' for realm 'EXAMPLE.COM',
master key name 'K/M@EXAMPLE.COM'
You will be prompted for the database Master Password.
It is important that you NOT FORGET this password.

Enter KDC database master key: PASSWORD

Re-enter KDC database master key to verify: PASSWORD
```



**Note that the command may pause for a significant amount of time after printing "Loading random data".**
To speed up the process and allow the kernel to generate enough random data to continue, login to the machine in another terminal and execute a couple commands, such as **`find /`** and/or type random text into the terminal.
Once enough random data has been collected, the command execution will continue.

Now that the realm has been created, we need to adjust the Kerberos config file, `/etc/krb5.conf`. That file should to be the same on all Kerberos servers and clients belonging to the same realm.

`/etc/krb5.conf` is split into sections; you should search for section "`[domain_realm]`" (not "`[realms]`") and append your definitions: 

```
.example.com = EXAMPLE.COM
example.com = EXAMPLE.COM
```

At the bottom of the file, you should add the logging section:

```
[logging]
	kdc = FILE:/var/log/kerberos/krb5kdc.log
	admin_server = FILE:/var/log/kerberos/kadmin.log
	default = FILE:/var/log/kerberos/krb5lib.log
```

To create the logging directory and set up permissions, run:

```
sudo mkdir /var/log/kerberos
sudo touch /var/log/kerberos/{krb5kdc,kadmin,krb5lib}.log
sudo chmod -R 750  /var/log/kerberos
```

You do not need to restart the log monitoring command you ran earlier (see [the section called “Conventions”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#conventions)) — the **tail -F** command will pick up new log files from the the `kerberos/` directory automatically.

To apply changes to the Kerberos server, run: 

```
sudo invoke-rc.d krb5-kdc restart
sudo invoke-rc.d krb5-admin-server restart
```

### Initial test

It is already the time to test the installation. We assume that both the admin server and the KDC can be restarted with no errors (which should be no problem to determine if you're monitoring the log files as advised).

As the first test, we will run command **kadmin.local** on the server. The **kadmin** command ordinarily requires principal name and password before letting anyone access the administrative interface. However, **kadmin.local** is a variant of the command that must be run locally on the same machine as the KDC, and with administrator privileges. It is then able to open the Kerberos database file directly (taking advantage of Unix file permissions), without requiring extra privileges and without using the **kadmind** (Kerberos master server) daemon.

The purpose of our running **kadmin.local** will be to print out the list of existing principals (user, host, and service accounts) in the database using the command **`listprincs`**. The whole session should look like this:

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  listprincs

K/M@EXAMPLE.COM
kadmin/admin@EXAMPLE.COM
kadmin/changepw@EXAMPLE.COM
kadmin/krb1.EXAMPLE.COM@EXAMPLE.COM
krbtgt/EXAMPLE.COM@EXAMPLE.COM

kadmin.local:  quit
```



### Note

If your output does not say `kadmin/krb1.*`EXAMPLE.COM`*@*`EXAMPLE.COM`*` but it says `kadmin/*`YOUR_HOSTNAME`*.*`EXAMPLE.COM`*@*`EXAMPLE.COM`*`, then that is fine but you need to open `/etc/hosts` to verify and make sure that *`YOUR_HOSTNAME`* —if it is listed there — appears associated to a real, valid network IP of the machine, and not to its local IP (127.*). 

In other words, if in your `/etc/hosts` you see something like:

```
127.0.0.1       localhost
127.0.1.1       ubuntu.example.com ubuntu
192.168.7.12    krb1.example.com krb1 monarch.example.com monarch
```

That would need to be adjusted to:

```
127.0.0.1       localhost
192.168.7.12    ubuntu.example.com ubuntu krb1.example.com krb1 monarch.example.com monarch
```





### Principal Names

In the test step above, you might have noticed [principal](http://kerberos.org/software/tutorial.html#1.3.2) names similar to `kadmin/admin@*`EXAMPLE.COM`*`. The general naming syntax for principals is`*`SPEC`*@*`REALM`*`, where *`SPEC`* by convention consists of components separated by "`/`", and the default *`REALM`* can be omitted.

In the case of principals related to system users, the first component identifies the user name, and the second component (if present) identifies user role. For regular users, there will usually be one principal with no special role, named simply `*`USERNAME`*`. But when administrative or other roles are required, there will be no need to condense them all to one "`admin`" principal — each user can simply be given conveniently named additional principals with special privileges, such as `*`USERNAME`*/admin`.

In the case of principals related to system services, the components will be used to identify service and hostname, such as`host/*`monarch.example.com`*` or `ldap/*`monarch.example.com`*`. ("host" is somewhat of a misnomer from today's perspective — it has nothing to do with host per-se, but is actually the service name for all remote shell protocols, such as rsh, rlogin and ssh).

### Access rights

Let's take a look at the `/etc/krb5kdc/kadm5.acl` file; it defines user access rights for the Kerberos database. For regular users with no special privileges, no action will be required. For admin users, we will want to grant all privileges, as hinted earlier in [the section called “Principal Names”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-princnames). To do this, make sure the following line is present in the file and enabled (that is, without the comment '`#`' character at the beginning): 

```
*/admin *
```

(While the above syntax might remind you of [shell globbing](http://tldp.org/LDP/abs/html/globbingref.html), it does not work that way. The only matching character supported is the asterisk ("`*`"), it does not match multiple components, and it can only be used in form of "`*`component`*/*`" or "`*/*`component`*`".)

Make sure to restart the admin server to apply `/etc/krb5kdc/kadm5.acl` changes: 

```
sudo invoke-rc.d krb5-admin-server restart
```

### Kerberos policies

Kerberos "policies" offer an elegant way to sort principals into a kind of categories and to automatically apply corresponding defaults onto newly created principals.

Let's create four basic policies: for admins, hosts, services and users. In this example, each policy will define minimum password strength (measured in number of character classes present in the password, from 1 to 5), but a few other options can be set — run **`addpol`** (the supported abbreviation of add_policy) if you're curious. 

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  add_policy -minlength 8 -minclasses 3 admin
kadmin.local:  add_policy -minlength 8 -minclasses 4 host
kadmin.local:  add_policy -minlength 8 -minclasses 4 service
kadmin.local:  add_policy -minlength 8 -minclasses 2 user

kadmin.local:  quit
```

### Creating first privileged principal

As you might have noticed, the **kadmin.local** command identified us as the principal `root/admin`. Still, that principal does not actually exist in the database so we might as well create it now. Once the principal is actually there, we'll be able to connect to the administrative server using **kadmin**from any machine within the Kerberos realm, and not just by using **kadmin.local** on the Kerberos server.

Creating a principal based on your regular identity (such as `*`USERNAME`*/admin`) is preferred over creating one called `root/admin`, and you are welcome to do so in your setup.

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  addprinc -policy admin root/admin

Enter password for principal "root/admin@EXAMPLE.COM": PASSWORD
Re-enter password for principal "root/admin@EXAMPLE.COM": PASSWORD
Principal "root/admin@EXAMPLE.COM" created.

kadmin.local:  quit
```

### Kadmin test

Now that the `root/admin` principal exists in the Kerberos database, we should be able to use **kadmin** just as we used **kadmin.local**. The only exception, of course, is that **kadmin** will prompt for a password to connect to the Kerberos admin server.

Double-check that all the permissions are granted to admin roles in the `/etc/krb5kdc/kadm5.acl` (as explained in [the section called “Access rights”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-access)), and that the admin server has been restarted to read the new configuration; then proceed to test **kadmin** connection:

```
kadmin -p root/admin
Authenticating as principal root/admin@EXAMPLE.COM with password.

Password for root/admin@EXAMPLE.COM: PASSWORD

kadmin:  listprincs

K/M@EXAMPLE.COM
root/admin@EXAMPLE.COM
kadmin/admin@EXAMPLE.COM
kadmin/changepw@EXAMPLE.COM
kadmin/history@EXAMPLE.COM
kadmin/krb1.EXAMPLE.COM@EXAMPLE.COM
krbtgt/EXAMPLE.COM@EXAMPLE.COM

kadmin:  quit
```

If there is a noticeable delay present before the kadmin password prompt appears, or if you notice a "`SERVER_NOT_FOUND`" warning printed to`/var/log/kerberos/krb5kdc.log`, look up [the section called “Error: SERVER_NOT_FOUND”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#err_server_not_found_krb5kdc) for a solution.

### Creating first unprivileged principal

Let's add a principal that will correspond to your regular, unprivileged user account. In our example, the username will be called "`jirky`". We've essentially performed this procedure for the `root/admin` principal above, but we'll repeat it here for your regular user account, using a different policy, and replacing *`jirky`* with your username.



```
kadmin -p root/admin
Authenticating as principal root/admin@EXAMPLE.COM with password.

Password for root/admin@EXAMPLE.COM: PASSWORD

kadmin:  addprinc -policy user jirky

Enter password for principal "jirky@EXAMPLE.COM": PASSWORD
Re-enter password for principal "jirky@EXAMPLE.COM": PASSWORD
Principal "jirky@EXAMPLE.COM" created.

kadmin:  quit
```

### Obtaining Kerberos ticket

As hinted in the introduction, each user is expected to type in the password once, to obtain the initial TGT (Ticket-granting Ticket). Obtained tickets are saved to a so-called *ticket cache*, which is most commonly a file named `/tmp/krb5cc_*`, stored on the user's workstation.

Let's run the **klist** command to inspect our ticket cache (run this command under your regular, non-privileged username). As one might guess, since we did not obtain any tickets yet, the cache will be empty: 

```
klist -f

klist: No credentials cache found (ticket cache FILE:/tmp/krb5cc_0)
```

Let's use **kinit** now to obtain the ticket, and then re-inspect the ticket cache. If the command seemingly "hangs" and does nothing, wait a few seconds — DNS misconfiguration may be causing a delay.

```
kinit jirky

Password for jirky@EXAMPLE.COM: PASSWORD
```



(You do not need to specify an explicit username if it is the same as your UNIX login name.)

```
klist -f

Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: jirky@EXAMPLE.COM

Valid starting     Expires            Service principal
11/22/06 22:30:36  11/23/06 08:30:33  krbtgt/EXAMPLE.COM@EXAMPLE.COM
renew until 11/23/06 22:30:34, Flags: FPRIA
```

If you remember the story from the beginning, you will recognize the "`krbtgt`" to be the Ticket-granting Ticket.

The meanings of each flag letter produced by the **klist** switch `-f` are not important at this stage, but long-term it is useful to get into the habit of using `-f`, and the flag descriptions can be looked up in the manpage klist(1).

All great. Let's run **`kdestroy`** to terminate the ticket now.

### Installing kerberized services

To actually use Kerberos, we need to install or configure versions of standard services that support Kerberos.

Each service may support Kerberos authentication either by having native Kerberos support, or by delegating the authentication work to the PAM subsystem (and since all relevant services support PAM, this means it is possible to Kerberize all network services).

Let's install `openssh-server` as our first and possibly the most important service.

```
sudo apt install openssh-server
```

To successfully connect to a certain service, the service must have a corresponding principal in the Kerberos database. This is because the Kerberos server acts as a trusted 3rd party and performs mutual authentication of both users and services as explained in [the section called “The role of Kerberos within a network”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#intro-krb).

The generic service name for telnet, rsh, ssh and related protocols is "`host`", so let's create the necessary principal with a randomly-generated password.

Please note that since Kerberos is based on the principle of shared secrets (as opposed to e.g. public-private key), the principal's key will need to exist in two places — one is obviously in the Kerberos database, and the other is in a file somewhere on the host where the service is running (e.g. in /etc/ on the SSH server machine).

In our example, since we are configuring the Kerberos and SSH server on the same machine, this will be the same host. In all other cases when these services are not on the same host, the procedure is exactly the same — you use kadmin on the client machine to connect to the Kerberos server, and then you call ktadd which will export the key to the local filesystem.

### Note

Traditionally, the default behavior of **ktadd** is such that it changes the principal's key to a random value before exporting it to a file. You can verify this by checking the principal's "kvno" (key version number) value, which will increase by 1 every time you call ktadd on the principal. This is done due to an assumption that the key should always exist in only two places (in the Kerberos database and exported into a file on the client), so whenever you call ktadd to export a key, it is a good time to change it to a fresh value for added security.

In any case, if you want to prevent this key randomization for some reason, use `ktadd ... -norandkey`. The `-norandkey` option is available from the **kadmin.local** shell. If/when you are using **kadmin** instead, the option `-norandkey` is available with package `krb5-user` version 1.15 and above (check with **dpkg -l krb5-user**). Also, it requires that the admin user has "extract-keys" privilege. This privilege must be granted to principals in `/etc/krb5kdc/kadm5.acl` explicitly as it is not included in "`*`". If you want to do this, your entry in `/etc/krb5kdc/kadm5.acl` should look like either of these (they are identical):

```
*/admin *e

*/admin admcilspe
```





```
kadmin -p root/admin
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  addprinc -policy service -randkey host/monarch.example.com

Principal "host/monarch.example.com@EXAMPLE.COM" created.

kadmin.local:  ktadd -k /etc/krb5.keytab host/monarch.example.com

Entry for principal host/monarch.example.com with kvno 2, encryption type aes256-cts-hmac-sha1-96 added to keytab WRFILE:/etc/krb5.keytab.
Entry for principal host/monarch.example.com with kvno 2, encryption type aes128-cts-hmac-sha1-96 added to keytab WRFILE:/etc/krb5.keytab.

kadmin:  quit
```



Now let's open the file `/etc/ssh/sshd_config` and modify or add the following lines:

```
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIKeyExchange yes
UsePAM yes
```



And to apply changes to the SSH server, run: 

```
sudo invoke-rc.d ssh restart
```

### PAM configuration

The next step in this article pertains to integrating Kerberos into the system authentication procedure. We want Kerberos tickets to be issued for users as they log in, without the need to run **kinit** manually after login.

On GNU/Linux and derivatives, this is done by simply altering [Linux-PAM](http://www.linux-pam.org/) configuration in `/etc/pam.d/` on all machines where the users are logging in.

As we have explained in [the section called “The role of Kerberos within a network”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#intro-krb), Kerberos alone does not help replace the usual password files (`/etc/passwd`, `/etc/shadow` or `/etc/group`). For now, your "kerberized" users will have to be present in both system password files and in Kerberos. (For a solution to that problem, see the next article in the series, the [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html).)

Our [Linux-PAM](http://www.linux-pam.org/) configuration will be defined so that *either* the usual password authentication *or* Kerberos authentication will need to succeed for the user to log in. This way, both users that will have no Kerberos entry (the system ones, such as `root`, `daemon`, `bin`, `sync`, `sys`, ...) and those that will (regular user accounts), will be able to log in.

System password in `/etc/shadow` will be tried first. If you want Kerberos tickets to be issued, this type of authentication **must fail** for regular users (otherwise their "system login" would succeed — resulting in the Kerberos part being skipped altogether and no tickets issued).

The most common way to make regular users have only one password (and that one being in Kerberos) is to replace their system password in`/etc/shadow` with a literal "`*K*`", which is not a valid password and also by spoken convention indicates that the "real" password is stored in Kerberos. This password can be set either by editing `/etc/shadow` file directly (i.e. with **`sudo vipw -s`**) or by invoking **`sudo usermod -p '\*K\*' \*`USERNAME`\*`**. Since maintaining this "*K*" convention is not an easy task if you don't have custom user management scripts, you can also just forget about it and lock out any user's system password with **`sudo usermod -L \*`USERNAME`\*`**.

Let's install the necessary Kerberos PAM module: 

```
sudo apt install libpam-krb5
```

Let's configure [Linux-PAM](http://www.linux-pam.org/). PAM configuration is quite fragile, so use the provided examples that have been verified to work. For any modifications, you will want to look at [PAM Configuration File Syntax](http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html) and pay special attention to seemingly insignificant variations — with PAM, they often make a whole world of difference.

To minimize the chance of locking yourself out of the system during PAM configuration phase, ensure right now that you have at least one root terminal window open and a copy of the files available *before* starting on PAM configuration changes. To do so, execute the following in a cleanly started shell and leave the terminal open: 

```
sudo su -
cd /etc
cp -a pam.d pam.d,orig
```

### Note

If you break logins with an invalid PAM configuration, the above will allow you to simply revert to a known-good state by using the open root terminal and executing: 

```
cp -a pam.d,orig/* pam.d/
```

The following PAM examples are complete; you should replace your existing configuration with the one shown below: 

#### /etc/pam.d/common-account



```
account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so
account requisite                       pam_deny.so
account required                        pam_permit.so
account required                        pam_krb5.so minimum_uid=1000
```



#### /etc/pam.d/common-auth



```
auth    [success=2 default=ignore]      pam_krb5.so minimum_uid=1000
auth    [success=1 default=ignore]      pam_unix.so nullok_secure try_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
autoh   optional                        pam_cap.so
```



#### /etc/pam.d/common-password



```
password        [success=2 default=ignore]      pam_krb5.so minimum_uid=1000
password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512
password        requisite                       pam_deny.so
password        required                        pam_permit.so
```



#### /etc/pam.d/common-session



```
session [default=1]                     pam_permit.so
session requisite                       pam_deny.so
session required                        pam_permit.so
session optional                        pam_krb5.so minimum_uid=1000
session required        pam_unix.so

# If elogind and libpam-elogind are installed:
session optional                        pam_elogind.so
```



If you have edited PAM configuration manually, restart the services you will be connecting to. This isn't strictly necessary, but it will verify early that the services can start properly as they will certainly re-read the PAM configuration.

### Installing kerberized clients

We can install one of the most commonly used clients nowadays - SSH:

```
sudo apt install openssh-client
```



### Testing the connection

As we have taken care of all the pre-requisites, we can try connecting.

(Just make sure that the user you will be connecting as actually exists on the machine. If you went with our example of *`jirky`*, make sure "jirky" is a valid, existing system user. You can do so with **`sudo adduser --disabled-password \*`jirky`\*`**.)

Obtain Kerberos ticket (you can do this as any user):

```
kinit jirky

Password for jirky@EXAMPLE.COM: PASSWORD
```

Verify you hold the Kerberos ticket with **`klist -f`** and then try connecting: 

```
ssh jirky@monarch.example.com

Welcome to Ubuntu 14.04.2 LTS (GNU/Linux 3.13.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '16.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

You have new mail.
logout
Connection closed.
```

**Congratulations! You have a working Kerberos setup**.

If anything is not working, proceed immediately below to [the section called “Troubleshooting Kerberos connection”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb_troubleshooting) — it contains an extensive list of possible errors and the corresponding solutions!

If everything is working, then you can skip that section and head directly to [the section called “PKINIT”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#PKINIT).

## Troubleshooting Kerberos connection

(Some of the items in this section refer to old "rsh" examples that used to be documented before the guide was updated to use SSH. Some of the errors these tools used to report are still valid, so they are left in the list as-is along with other items.)

### krb_sendauth failed: You have no tickets cached

```
ssh monarch.example.com


Trying krb4 rlogin...
krb_sendauth failed: You have no tickets cached
```

You have no valid Kerberos tickets, which can be verified by running **klist** (the output will either be empty or show expired tickets). Obtain a new ticket using **kinit**:

```
kinit PRINCIPAL_NAME
```

### Error: Server not found in Kerberos database

```
ssh monarch.example.com


error getting credentials: Server not found in Kerberos database
```

As explained in [the section called “The role of Kerberos within a network”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#intro-krb), both the users and the services must have an appropriate principal entry in the Kerberos database. While users are in form of *`NAME/ROLE`*, services are in form *`SERVICE-NAME/HOSTNAME`*. So you need to add a principal for service "`host`" (common name for all shell services), on host where the service is provided — *`monarch.example.com`*.

As most of the errors really boil down to this step, we also take care of re-initializing the ticket properly, to minimize the chance of a mistake. Execute this on the machine where the SSH service is running:

```
rm /etc/krb5.keytab # <-- Caution. Don't do this unless it's a test setup!

kdestroy

kadmin -p root/admin
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  delprinc host/monarch.example.com
Are you sure you want to delete the principal "host/monarch.example.com@EXAMPLE.COM"? (yes/no): yes
Principal "host/monarch.example.com@EXAMPLE.COM" deleted.
Make sure that you have removed this principal from all ACLs before reusing.

kadmin.local:  addprinc -policy service -randkey host/monarch.example.com

Principal "host/monarch.example.com@EXAMPLE.COM" created.

kadmin.local:  ktadd -k /etc/krb5.keytab host/monarch.example.com

kadmin.local: quit
```

### Error: No such file or directory

```
ssh monarch.example.com


Couldn't authenticate to server: Server rejected authentication (during sendauth exchange)
Server returned error code 60 (Generic error (see e-text))
Error text sent from server: No such file or directory
```

The above error indicates that we should pay attention to the "e-text" (error text returned to the client). The error text tells us, in kind of a confusing way (since — you see — there is no filename reported), that the `/etc/krb5.keytab` file on the server is missing altogether. This file needs to exist and contain the service key. The way to obtain the file and the key is to follow the recipe from [the section called “Error: Server not found in Kerberos database”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#err_server_not_found).

### Error: Key table entry not found

```
ssh monarch.example.com


Couldn't authenticate to server: Server rejected authentication (during sendauth exchange)
Server returned error code 60 (Generic error (see e-text))
Error text sent from server: Key table entry not found
```

The server did accept the connection, but the e-text "Key table entry not found" indicates that the service principal (created earlier,`host/*`monarch.example.com`*`) is not listed in the keytab file on SSH server. Follow the recipe in [the section called “Error: Server not found in Kerberos database”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#err_server_not_found).

### Error: Key version number for principal in key table is incorrect

```
ssh monarch.example.com


Couldn't authenticate to server: Server rejected authentication (during sendauth exchange)
Server returned error code 60 (Generic error (see e-text))
Error text sent from server: Key version number for principal in key table is incorrect
```

The service key has changed on the Kerberos server, and the service did not succeed in proving its identity to the Kerberos server — the file `/etc/krb5.keytab` on the service's machine did not contain the correct key. (Have in mind that the key will change when you run `ktadd` from within the **kadmin** shell, and the only way to prevent that from happening is to use **kadmin.local** interface and use **`ktadd -norandkey`** in it.) If curious, read up on `ktadd` behavior in kadmin(8). Follow the recipe in [the section called “Error: Server not found in Kerberos database”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#err_server_not_found).

### Error: Client not found in Kerberos database while getting initial credentials

```
kinit root/admin


kinit(v5): Client not found in Kerberos database while getting initial credentials
```

This is Kerberos way of saying "User not found". You either misspelled the principal name ("`root/admin`" in this case), or you didn't add the principal to the kerberos database in the first place. Adding a principal is performed using the **addprinc** command as shown in [the section called “Creating first privileged principal”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-adduser-priv) or [the section called “Creating first unprivileged principal”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-adduser-ticket).

### Error: Client not found in Kerberos database while initializing kadmin interface

```
kadmin -p root/admin


kadmin: Client not found in Kerberos database while initializing kadmin interface
```

This is Kerberos way of saying "User not found". You either misspelled the principal name ("`root/admin`" in this case), or you didn't add the principal to the kerberos database in the first place. Adding a principal is performed using the **addprinc** command as shown in [the section called “Creating first privileged principal”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-adduser-priv) or [the section called “Creating first unprivileged principal”](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#krb-adduser-ticket).

### Error: Decrypt integrity check failed

```
ssh monarch.example.com


Couldn't authenticate to server: Server rejected authentication (during sendauth exchange)
Server returned error code 31 (Decrypt integrity check failed)
Error text sent from server: Decrypt integrity check failed
```

This is Kerberos way of saying "Password incorrect". In this case, it means that the service key changed on the server, and your your ticket cache no longer contains the ticket with the correct key. Running **`kdestroy; kinit`** should obtain a new ticket and solve the problem.

### Error: Unsupported key table format version number while adding key to keytab

```
kadmin: ktadd -k /etc/krb5.keytab host/monarch.example.com


kadmin: Unsupported key table format version number while adding key to keytab
```

This usually happens when the local file to which you want to export the key (`/etc/krb5.keytab`) is in an incorrect format.

The most common reason why this would happen is if you have tried to create an empty file (using **touch** or similar commands) beforehand, and then export the key into it.

To verify that this is indeed the case, try running **klist** on the existing file to which you are attempting to export the key:

```
sudo klist -k /etc/keytab


klist: Unsupported key table format version number while starting keytab scan
```



The solution is to delete the incorrectly created keytab file and let the **ktadd** create it automatically, or to choose a different keytab file to which the intended key should be exported.

### Error: Wrong principal in request

```
ssh monarch.example.com


Couldn't authenticate to server: Server rejected authentication (during sendauth exchange)
Server returned error code 60 (Generic error (see e-text))
Error text sent from server: Wrong principal in request
```

TODO

### Error: SERVER_NOT_FOUND

```
kadmin -p root/admin

==> kerberos/krb5kdc.log <==
Jan 07 01:47:35 ubuntu krb5kdc[20837](info): AS_REQ (4 etypes {18 17 16 23}) 192.168.7.12: SERVER_NOT_FOUND: root/admin@EXAMPLE.COM for kadmin/krb1.example.com@EXAMPLE.COM, Server not found in Kerberos database
```

This error is emitted in the krb5kdc log file when the principal reported (`kadmin/krb1.*`example.com`*@*`EXAMPLE.COM`*`) is missing in the Kerberos database.
It usually happens when you are setting up a Kerberos server using a chosen hostname that does not match the hostname reported by the system command **hostname**.

Add the missing kadmin principal as follows:

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  addprinc -randkey -requires_preauth -allow_tgs_req  kadmin/krb1.example.com

WARNING: no policy specified for kadmin/krb1.example.com@EXAMPLE.COM; defaulting to no policy
Principal "kadmin/krb1.example.com@EXAMPLE.COM" created.

kadmin.local:  quit
```



### Error: UNKNOWN_SERVER

```
kadmin -p root/admin

==> kerberos/krb5kdc.log <==
Jan 07 01:47:35 ubuntu krb5kdc[20837](info): TGS_REQ (7 etypes {18 17 16 23 1 3 2}) 192.168.7.12: UNKNOWN_SERVER: authtime 1376929169, root/admin@EXAMPLE.COM for kadmin/krb1.example.com@EXAMPLE.COM, Server not found in Kerberos database
```

TODO

### Error: klogind: not authorized to login to account

```
ssh monarch.example.com

klogind: User root/admin@EXAMPLE.COM is not authorized to login to account root.
```

This error is emitted when the Kerberos principal name ("`root/admin`") does not exactly match the name of the user account to which it wants to log in to ("`root`"), and when the login allowance for that principal has not been added to file `~/.k5login`.

To add the permission, add the principal's full name to the file `~/.k5login` in the target account's home directory:

```
echo 'root/admin@EXAMPLE.COM' >> ~root/.k5login
```



### Error: Connection Refused

```
krb5-rsh -PN monarch.example.com


connect to address 192.168.7.12: Connection refused
Trying krb4 rlogin...
connect to address 192.168.7.12: Connection refused
trying normal rlogin (/usr/bin/netkit-rlogin)
exec: No such file or directory
```

Let's take a look at this. First of all, you can see that **krb5-rsh** has some fallbacks built-in. It first tries to connect using the Kerberos 5 protocol, then Kerberos 4, and then using the normal, non-kerberized rsh. We are only interested in the krb5 result. If any of the other two methods succeed (the krb4 or plain rsh), it's still not what we want (and you will probably want to disable them somehow, because no one setting up a new Kerberos realm in the 21st century should be running either krb4 or unprotected rsh).

So where's the problem? Assuming that you did everything right (installed krb5-rsh-server and restarted inetd), the problem is very simple. Namely, by default, kerberized servers in Debian do not accept unencrypted connections! So, on next attempt, add `-x` on the command line. 

```
krb5-rsh -PN -x monarch.example.com
```

### Error: Generic preauthentication failure while getting initial credentials

```
kinit jirky


kinit: Generic preauthentication failure while getting initial credentials
```

If using PKINIT, make sure that package `krb5-pkinit` is installed: **`apt-get install krb5-pkinit`**.

### Error: Pre-authentication failed: Invalid argument while getting initial credentials

```
kinit jirky -X pkinit_identities=FILE:jirkycert.pem,jirkykey.pem


kinit: Pre-authentication failed: Invalid argument while getting initial credentials
```

Data for `pkinit_identities` setting was not specified or it is invalid.
If you are relying on settings from `/etc/krb5.conf`, make sure there is a line such as `pkinit_identities = FILE:/path/to/cert.pem,/path/to/key.pem`. If you are relying on settings passed on command line, instead of `pkinit_identities` use `X509_user_identity`, such as **`kinit -V -X X509_user_identity=FILE:/path/to/cert.pem,/path/to/key.pem`**.

## PKINIT

### Introduction

In proper, infrastructure-based networks, users would authenticate to Kerberos once (at system login), and access all other services automatically and transparently from there.

However, traditionally with Kerberos this implied typing in a password, preventing use of more advanced login methods like smartcards, etc.

Also, often times users' desktops are installed ad-hoc and are not part of any formal infrastructure. Similarly, users might not want to bother setting up their machines as Kerberos clients, or might not even want to care about authentication systems used behind the scenes.
Such ad-hoc approaches are often characterized by users simply installing SSH private-public keys for achieving passwordless logins to remote systems. But in SSH key-based (passwordless) logins, there are no passwords involved and so there is nothing available for the KDC servers to verify and use as basis for issuing TGTs.

So, while smartcards and SSH keys can be used, users who log in this way will not be able to automatically obtain Kerberos tickets. They will need to manually run **kinit**, which effectively gets them back to password-based authentication. Additionally, this two-step approach may be even more unsuitable for hosts that rely on Kerberos for granting filesystem access, such as those using [OpenAFS](http://www.openafs.org/).

To solve this problem, PKINIT was developed as a preauthentication mechanism for Kerberos 5. It uses X.509 certificates to authenticate KDCs to clients and vice versa. Additionally, PKINIT can also be used to enable anonymity support, allowing clients to communicate securely with the KDCs or application servers without authenticating as a particular client principal.

### Server configuration

PKINIT configuration on the server requires package `krb5-pkinit`, some additional configuration files, X.509 certificate for Certificate Authority, and X.509 certificate for KDC.

For anonymous PKINIT, a KDC certificate is required. It is possible to use a commercially issued server certificate if that is what you have, but our example will show generating all certificates ourselves.

#### Package krb5-pkinit



```
apt-get install krb5-pkinit
```



#### /etc/krb5kdc/extensions.kdc

Create file `/etc/krb5kdc/extensions.kdc` with the following content:

```
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm=EXP:0,GeneralString:${ENV::REALM}
principal_name=EXP:1,SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:kdc_principals

[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:${ENV::REALM}
```



#### /etc/krb5kdc/extensions.client

Create file `/etc/krb5kdc/extensions.client` with the following content:

```
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

[princ_name]
realm=EXP:0,GeneralString:${ENV::REALM}
principal_name=EXP:1,SEQUENCE:principal_seq

[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals

[principals]
princ1=GeneralString:${ENV::CLIENT}
```



#### Certificate Authority (CA) files

Create Certificate Authority key and certificate as follows:

```
mkdir /etc/krb5

cd /etc/krb5kdc/

openssl genrsa -out cakey.pem 8192
openssl req -key cakey.pem -new -x509 -out ../krb5/cacert.pem -days 3650
```

All values asked during certificate creation can remain blank. Answer all fields with a dot (`.`) for this.

File `/etc/krb5/cacert.pem` needs to be present on all KDCs and client machines. Because of this, expiration time of 10 years (3650 days) was used in the above example.
File `cacert.key`, as all private keys, must be carefully protected, and it will be used when creating KDC and client certificates.

#### KDC files

Create KDC key, certificate request, and signed certificate as follows:

```
cd /etc/krb5kdc/

openssl genrsa -out kdckey.pem 8192
openssl req -key kdckey.pem -new -out kdccert.req

env REALM=EXAMPLE.COM openssl x509 -req -in kdccert.req -CAkey cakey.pem -CA ../krb5/cacert.pem \
  -out kdccert.pem -days 3650 -extfile extensions.kdc -extensions kdc_cert -CAcreateserial

rm kdccert.req
```

All values asked during certificate creation can remain blank. Answer all fields with a dot (`.`) for this.

File `kdccert.pem` needs to be copied to all KDCs. Because of this, expiration time of 10 years (3650 days) was used in the above example.
File `kdckey.pem`, as all private keys, must be carefully protected.

At this point you can examine the CA or KDC certificates with **`openssl x509 -in ../krb5/cacert.pem -text -noout`**. OpenSSL will not know how to display the principal name in the Subject Alternative Name extension, so it will appear as `othername:<unsupported>`. This is fine.

#### KDC configuration

After all the files above are in place, add the following to `/etc/krb5kdc/kdc.conf` into any section (either inside "`[kdcdefaults]`", or inside "`[realms]`" under the subsection for your realm):

```
pkinit_identity = FILE:/etc/krb5kdc/kdccert.pem,/etc/krb5kdc/kdckey.pem
pkinit_anchors = FILE:/etc/krb5/cacert.pem
kdc_tcp_ports = 88
```

And restart the KDC server:

```
sudo invoke-rc.d krb5-kdc restart
```



### Client configuration

#### Certificates

Each client who wishes to authenticate against the KDC in this way will need a certificate. Certificate for our example user *`jirky`* can be created as follows:

```
cd /etc/krb5kdc/

openssl genrsa -out jirkykey.pem 8192
openssl req -key jirkykey.pem -new -out jirky.req

env REALM=EXAMPLE.COM CLIENT=jirky openssl x509 \
    -CAkey cakey.pem -CA ../krb5/cacert.pem -req -in jirky.req \
    -extensions client_cert -extfile extensions.client \
    -days 3650 -out jirkycert.pem

rm jirky.req
```

All values asked during certificate creation can remain blank. Answer all fields with a dot (`.`) for this.

The first two commands can be executed on any host. The third command needs to be executed on the CA machine where `cakey.pem` exists. In our case this is the same machine as KDC, in the directory `/etc/krb5kdc/`.

Files `jirkycert.pem` and `jirkykey.pem` will need to be present on the machine from which the client will be authenticating.

As usual, you can examine the certificate with **`openssl x509 -in jirkycert.pem -text -noout`**. OpenSSL will not know how to display the principal name in the Subject Alternative Name extension, so it will appear as `othername:<unsupported>`. This is fine.

#### Preauthentication

Since PKINIT is a preauthentication mechanism for Kerberos, preauthentication must be enabled on principals wishing to authenticate using PKINIT.



This may already be a default setting thanks to this line in `/etc/krb5kdc/kdc.conf`:

```
...

[realms]
	EXAMPLE.COM = {
		...
		default_principal_flags = +preauth
		...
  }
```

If this setting is not present, you can add it to the config file to serve as the default, and/oror you can check individual principals for presence of this flag:

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  getprinc jirky

...
Attributes: REQUIRES_PRE_AUTH
...


kadmin.local:  modprinc +requires_preauth jirky

kadmin.local:  quit
```



#### Authentication keys

Sometimes it can be useful to remove all traditional authentication keys for a principal in the Kerberos database, to easier debug PKINIT-specific issues.



Also, if users will only ever authenticate using PKINIT, they don't need Kerberos keys at all.



Deleting keys for users or creating users with no keys in the first place can be done using the following commands:

```
sudo kadmin.local
Authenticating as principal root/admin@EXAMPLE.COM with password.

kadmin.local:  purgekeys -all jirky

kadmin.local:  addprinc +requires_preauth -nokey quirky

kadmin.local:  quit
```



#### KDC and client certificates

Client hosts must be configured to trust the issuing authority for the KDC certificate, and the authenticating clients need to have access to their own certificate and private key. This can be defined in either `/etc/krb5.conf` which is read by all Kerberos clients, or in-place during invocation of **kinit** and similar commands.



Specifying the CA cert in `/etc/krb5.conf` may be convenient because this file can and should be world-readable, but client keys are inherently private in nature and are best not kept or listed in a single place.



Thefore, for `cacert.pem` we will use `/etc/krb5.conf` and for client certificates and keys we will use in-place specification. So, we add this to `/etc/krb5.conf`:

```
...

[realms]
	EXAMPLE.COM = {
		...
		# For own certificate:
		pkinit_anchors = FILE:/etc/krb5/cacert.pem

		# Or for commercial certificate:
		#pkinit_anchors = DIR:/etc/ssl/certs
		#pkinit_eku_checking = kpServerAuth
		#pkinit_kdc_hostname = hostname.of.kdc.certificate,...

		...
  }
```



### Authentication

Finally, we are able to test client authentication using PKINIT!

As mentioned, in addition to eventual principal name, we will specify the location of the corresponding client certificate and private key:

```
kdestroy

kinit jirky -X X509_user_identity=FILE:jirkycert.pem,jirkykey.pem
```

If the KDC and client were properly configured, the above command has succeeded without asking for a password!

## Conclusion

At this point, you have a functional Kerberos installation!

You can rely on either system login or manually running **kinit** in obtaining Kerberos tickets and accessing Kerberized services. One of those services is the passwordless, Kerberos-secured SSH login that we've demonstrated in this guide.

**With a good foundation we've built, for further information on Kerberos, please refer to other available resources:**

- Official documentation: http://web.mit.edu/kerberos/krb5-1.8/
- Mailing lists: http://web.mit.edu/kerberos/mail-lists.html
- IRC: channel #kerberos at the Libera.Chat network (irc.libera.chat)
- For commercial consultation and infrastructure-based networks containing Kerberos, contact [Spinlock Solutions](http://www.spinlocksolutions.com/).



Remember that, as explained in this Guide, your user accounts still need to be created locally on all hosts the users wish to access. To solve that problem and achieve true centralized logins, follow the next article in the series, the [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html).

If you have followed the [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html) first and have come here to set up Kerberos as an afterthought, run **`sudo dpkg-reconfigure libpam-ldap`** to choose "Unix authentication" and "Kerberos authentication" instead of "LDAP Authentication", and re-visit the [OpenLDAP Guide](http://techpubs.spinlocksolutions.com/dklar/ldap.html) to verify that the resulting PAM configuration files have actually been re-generated and look like the Kerberos-related examples shown there.

If you have followed this [MIT Kerberos 5 Guide](http://techpubs.spinlocksolutions.com/dklar/kerberos.html) only as a pre-requisite for installing OpenAFS and do not want to use LDAP in combination, proceed to another article in the series, the [OpenAFS Guide](http://techpubs.spinlocksolutions.com/dklar/afs.html).

## Links

Platforms:
[GNU](https://www.gnu.org/) 
[Debian GNU](https://www.debian.org/) 

Kerberos:
[MIT Kerberos](http://web.mit.edu/kerberos/) 
[Heimdal Kerberos](http://www.pdc.kth.se/heimdal/) 
[Kerberos consortium](http://www.kerberos.org/) 

Kerberos specifics:
[Kerberos release](http://web.mit.edu/Kerberos/dist/index.html) 
[Kerberos database](http://kerberos.org/software/tutorial.html#1.3.5.1) 
[realm](http://kerberos.org/software/tutorial.html#1.3.1) 
[KDC](http://kerberos.org/software/tutorial.html#1.3.5) 
[principal](http://kerberos.org/software/tutorial.html#1.3.2) 
[secret key](http://kerberos.org/software/tutorial.html#1.3.4) 
[TGT](http://kerberos.org/software/tutorial.html#1.5.1) 

Glue layer:
[Linux-PAM](http://www.linux-pam.org/) 
[PAM Configuration File Syntax](http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html) 

Related infrastructural technologies:
[OpenLDAP](http://www.openldap.org/) 
[OpenAFS](http://www.openafs.org/) 
[FreeRADIUS](http://www.freeradius.org/) 

Commercial support:
[Spinlock Solutions](http://www.spinlocksolutions.com/) 

Misc:
[DocBook](http://www.docbook.org/) 