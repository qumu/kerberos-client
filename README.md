# Kerberos Client

This project allows making HTTP calls to a Kerberos protected server using SPNego/Negotiate protocol. It is heavily based on https://github.com/spring-projects/spring-security-kerberos/tree/master/spring-security-kerberos-samples/sec-server-client-auth.

The main differences are:

* Completely independent of Spring or Spring Security using `KerberosHttpClient`. Spring dependencies are only present in the project in order to execute it as Spring Boot application.
* That `KerberosHttpClient` allows `HOST_BASED` and `USER_BASED` `GSSName` generation for login to the Authentication Server. Besides, for host based names, the service type present in the SPN can be not only `HTTP` but any value (`HTTP`
is hardcoded into the default implementation of `SPNegoScheme`)

## Requirements

* Create a user (principal) in Windows Active Directory. In the `Account` tab set:

  - `SERV/yourusername.domain.com` as `User logon name`
  - `yourusername` as `User logon name (pre-Windows 2000)` if present

* In Windows, as Administrator, set an SPN for that user:

```
setspn -A SERV/yourusername.domain.com yourusername
```

* Then generate a `keytab` file:

```
ktpass /out C:\yourusername.keytab /mapuser yourusername@DOMAIN.COM /princ SERV/yourusername.domain.com@DOMAIN.COM /pass yourpassword /kvno 0
```

* Install and configure Kerberos in the host machine. This an example of `/etc/krb5.conf`:

```
[libdefaults]
    default_realm = DOMAIN.COM
    default_tkt_enctypes = arcfour-hmac-md5 des-cbc-crc des-cbc-md5
    default_tgs_enctypes = arcfour-hmac-md5 des-cbc-crc des-cbc-md5
    ticket_lifetime = 24h
    forwardable = yes
    dns_lookup_kdc = false

[realms]
    DOMAIN.COM = {
        kdc = yourActiveDirectoryHost.domain.com
        default_domain = domain.com
    }

[domain_realm]
    .domain.com = DOMAIN.COM

[logging]
 krb5 = SYSLOG:
 default = FILE:/var/logs/krb5.log
 admin_server = FILE:/var/logs/krb5.log
 kdc = FILE:/var/logs/krb5.log
```

* Ensure the `kdc` (Windows Active Directory domain in this case) is accessible from the current host


## Run the example


* Copy the `yourusername.keytab` into a location in the machine running the client. Put that location in this app config file `application.yml` along with the following:

- `access-url`: endpoint to access in the server. This has to contain a fully qualified domain name of the server host. This hostname has to be a user defined in the same Kerberos Realm / Domain Controller as the client if using `HOST_BASED` name strategy for GSS (i.e: `yourusername.domain.com`)
- `user-principal`: fully qualified SPN of the created user, i.e. `SERV/yourusername.domain.com@DOMAIN.COM`


* Launch `Kerberos Server` in a host named `yourusername.domain.com` if this client uses `HOST_BASED` name generation.


* Generate the JAR file:

```
./gradlew assemble
```

* Execute the client:

```
java -jar build/libs/kerberos-client-0.1.jar
```

* Config file `application.yml` can be overriden at execution time. Just provide a file with the same name in directory the previous command in executed from (not where the JAR lives) or give an extra command line attribute:

```
java -jar build/libs/kerberos-client-0.1.jar --spring.config.location=/path/to/propertiesFile.yml
```

## Limitations

- Only `HOST_NAME`-based naming for principals/SPNs is supported at the moment. This requires a proper hostname in the server aligned with a user principal in AD.
- Only GET requests can be performed at the moment, returning a String response


## Resources

* Using JGSS to generate and consume Kerberos/SPNEGO tokens [here](https://dmdaa.wordpress.com/2010/10/16/how-to-obtain-and-authenticate-kerberos-and-spnego-tokens-with-jgss)
* Simple example of high level Client/Server using GSS-API [here](http://thejavamonkey.blogspot.co.uk/2008/04/clientserver-hello-world-in-kerberos.html)
* More low level example of Client/Server, using mutual authentication checks [here](https://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/BasicClientServer.html), [here](https://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/SampleServer.java) and [here](https://docs.oracle.com/javase/7/docs/technotes/guides/security/jgss/tutorials/SampleClient.java)
* Spring Security Kerberos [docs](http://docs.spring.io/autorepo/docs/spring-security-kerberos/1.0.0.RC1/reference/htmlsingle/#setupmitkerberos)




