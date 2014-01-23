Mobile-ID
=========

[Mobile-ID](http://www.id.ee/?id=10995&&langchange=1) (Mobiil-ID) is a personal mobile identity in Estonia and Lithuania,
provided by an additional application on a SIM card. The good thing is that it 
is backed by government and provides the same level of security for authentication 
and digital signatures as a national ID card without the need of having a smart card reader.

Java and Mobile-ID
==================

The official Mobile-ID API is a SOAP web service, so it usually takes time to generate the code and
start using it in a Java application.

This small library tries to solve this problem: just add the [*mobileid.jar* (with dependencies)](http://mvnrepository.com/artifact/com.codeborne)
to your project and you have a working Mobile-ID support. It already contains all the generated classes (by axis v1) as well as a simplified API of our own.

The same jar works in Scala as well or any other JVM-based language.

You can also use Maven/Ivy/Gradle/SBT or your favorite dependency manager that can fetch jars from the github repo:

  [com.codeborne :: mobileid](https://raw.github.com/llyys/mobileid/tree/master/mvn)


Setting up tomcat webserver certificates 
=====

Certificates may be encoded as binary .DER or as ASCII .PEM

If you want then transforms can take one type of encoded certificate to another. (ie. PEM To DER conversion)

**PEM to DER**
$ openssl x509 -in cert.crt -outform der -out cert.der

**DER to PEM**
$ openssl x509 -in cert.crt -inform der -outform pem -out cert.pem

but they are the same thing in different encoding
###Create a keystore file.

To configure an id-card authentication you **must** create keystore file. 

All ID-card root certificates should be added to Java keystore-i width -trustcacerts keword

[List of these required root certificates](https://www.sk.ee/Repositoorium/SK-sertifikaadid/juursertifikaadid), use only those whose status is **Kehtiv**

    $ mkdir esteid
    $ cd esteid
    
    $ wget --no-check-certificate -nv -O "JUUR-SK.crt" https://www.sk.ee/upload/files/Juur-SK.pem.crt
    $ wget --no-check-certificate  -nv -O "EE-Certification-Centre-Root-CA.crt" https://www.sk.ee/upload/files/EE_Certification_Centre_Root_CA.pem.crt    
    $ wget --no-check-certificate  -nv -O "ESTEID-SK-2011.crt" https://www.sk.ee/upload/files/EID-SK_2011.pem.crt
    

now you should have *EE-Certification-Centre-Root-CA.crt ESTEID-SK-2011.crt JUUR-SK.crt*
files, in your esteid/ca folder

Now create a keystorefile witdh keytool 

    $ keytool -genkey -alias mydomain -keyalg RSA -keystore keystore.jks -keysize 2048
        
    $ keytool -trustcacerts -importcert -file "JUUR-SK.crt" -keystore keystore.jks -alias juur-sk
    $ keytool -trustcacerts -importcert -file "EE-Certification-Centre-Root-CA.crt" -keystore keystore.jks -alias EE-Certification-Centre-Root-CA
    $ keytool -trustcacerts -importcert -file "ESTEID-SK-2011.crt" -keystore keystore.jks -alias ESTEID-SK-2011

Setting up certs for accessing https://digidocservice.sk.ee/
=====

To access a https service via java you need to add https authentication certificate to keystore. 
First download certificate from the server

    $ openssl s_client -connect digidocservice.sk.ee:443 -showcerts |openssl x509 -outform PEM >digidocservice.pem
NB! this openssl process will not close after cert reading, so just press CTRL-C key and see if outputted digidocservice.pem file is not empty but 
has a text containing ***PEM*** -----BEGIN CERTIFICATE-----... and ends width -----END CERTIFICATE-----

Now add this https access certificate to java keystore width following command 

    $ keytool -trustcacerts -importcert -file "digidocservice.pem" -keystore keystore.jks -alias digidocservice


###Configure tomcat to enable ID-Card authorization.

go to the folder where you installed tomcat and open conf\server.xml file and copy just created **keystore.jks** to the same folder where is server.xml
edit server.xml 

     
    <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" 
    maxThreads="150" scheme="https" secure="true" 
    keystoreFile="conf/keystore.jks" keystorePass="password" keyAlias="mydomain" 
    truststoreFile="conf/keystore.jks" truststorePass="password" 
    clientAuth="true" sslProtocol="TLS" /> 

If you want to use client-certificate authentication only for certain webapps (or paths), you need to configure the connector with a truststore.
***You should not use certificate renogiation by setting clientAuth="want" this is not properly supported so just don't waste your time on this.***

but when you need to use other authorizatoin methods then do this via another connector port something like 443

    <Connector port="443" protocol="HTTP/1.1" SSLEnabled="true" 
    maxThreads="150" scheme="https" secure="true" 
    keystoreFile="conf/keystore.jks" keystorePass="password" keyAlias="mydomain" 
    truststoreFile="conf/keystore.jks" truststorePass="password" 
    clientAuth="false" sslProtocol="TLS" /> 


Usage
=====

Just use the public methods in [MobileIDAuthenticator](http://github.com/codeborne/mobileid/blob/master/src/com/codeborne/security/mobileid/MobileIDAuthenticator.java) class:

* startLogin(phoneNumber) - to initiate the login session, which will send a flash message to your mobile phone. The returned MobileIDSession contains the challenge code that you need to display to the user.
* waitForLogin(session) - to wait until user finally signs the challenge. This is a blocking call for simplicity.
* isLoginComplete(session) - if you want to do polling from the client side

See working example in [HelloMobileID.java](http://github.com/codeborne/mobileid/blob/master/test/com/codeborne/security/mobileid/HelloMobileID.java) - run the main() method.

