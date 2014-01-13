package com.codeborne.security.authenticator;

import org.apache.commons.codec.binary.Base64;
import sun.security.provider.X509Factory;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

public class SmartCardAuthenticator {
    public static SmartCardUserInfo getUserInfoFromRequest(HttpServletRequest request) throws CertificateException {
        SmartCardUserInfo user=new SmartCardUserInfo();
        X509Certificate cert = extractClientCertificate(request);
        String subjectDN = cert.getSubjectDN().getName();
        user.personalCode = subjectDN.replaceFirst(".*SERIALNUMBER=(\\d{11}),.*", "$1");
        user.userName = subjectDN;
        return user;
    }

    private static X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs != null && certs.length > 0) {
            return certs[0];
        }
        return null;
    }

}
