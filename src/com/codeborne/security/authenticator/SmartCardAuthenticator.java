package com.codeborne.security.authenticator;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import sun.security.provider.X509Factory;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

public class SmartCardAuthenticator {
    public static SmartCardUserInfo getUserInfoFromRequest(HttpServletRequest request) throws CertificateException {
        SmartCardUserInfo user=new SmartCardUserInfo();
        Object[] attribute = (Object[])request.getAttribute("javax.servlet.request.X509Certificate");
        if(attribute==null)
            return null;
        if(attribute.length==0)
            return null;
        Object cert=attribute[0];
        String subjectDN = null;

        if(java.security.cert.X509Certificate.class.isAssignableFrom(cert.getClass()))
        {
            java.security.cert.X509Certificate certificate = (java.security.cert.X509Certificate) cert;
            subjectDN = certificate.getSubjectDN().getName();
        }
        if(javax.security.cert.X509Certificate.class.isAssignableFrom(cert.getClass()))
        {
            java.security.cert.X509Certificate certificate = (java.security.cert.X509Certificate) cert;
            subjectDN = certificate.getSubjectDN().getName();
        }
        if(StringUtils.isNotBlank(subjectDN))
        {
            user.personalCode = subjectDN.replaceFirst(".*SERIALNUMBER=(\\d{11}),.*", "$1");
            user.userName = subjectDN;
        }
        return user;
    }

}
