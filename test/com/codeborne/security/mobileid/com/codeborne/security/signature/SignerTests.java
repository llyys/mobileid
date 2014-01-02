package com.codeborne.security.mobileid.com.codeborne.security.signature;

import com.codeborne.security.signature.MobileIDSigner;
import com.codeborne.security.signature.SignatureSession;
import com.codeborne.security.signature.Signer;
import com.codeborne.security.signature.SmartcardSigner;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;


public class SignerTests {
    //@Before
    public void setUp(){
        File keystore = new File(SignerTests.class.getProtectionDomain().getCodeSource().getLocation().getPath(), "keystore.jks");
        if (!keystore.exists())
            throw new RuntimeException("File not found: " + keystore.getAbsolutePath());

        System.setProperty("javax.net.ssl.trustStore", keystore.getAbsolutePath());
    }

    //@Test
    public void canExecuteMobileIdSigningIntegration() throws IOException, DigiDocException {
        File testFile = new File(SignerTests.class.getProtectionDomain().getCodeSource().getLocation().getPath(), "test.txt");
        MobileIDSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new MobileIDSigner("https://www.openxades.org:9443/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files);
            signer.mobileSign(session, "37903236510", "+3725227475", "Testimine", 0, true, true );
            if(signer.waitForSigning(session)){
                signer.getSignedDoc(session);
            }
        }finally {
            signer.closeSession(session);
        }
    }

    //@Test
    public void canExecuteSmartCardSigningIntegration() throws IOException, DigiDocException {
        File testFile = new File(SignerTests.class.getProtectionDomain().getCodeSource().getLocation().getPath(), "test.txt");
        SmartcardSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new SmartcardSigner("https://www.openxades.org:9443/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files);
            String cert="";
            String tokenId="";
            signer.PrepareSignature(session, cert, tokenId, "", "", "", "", "", "Testimine");
            signer.FinalizeSignature(session);
            SignedDoc doc = signer.getSignedDoc(session);

        }finally {
            signer.closeSession(session);
        }
    }


    @Test
    public void IsMessageDigestCalculationAccordingToSpeck() {
        String res = Signer.calculateMessageDigest("SHA-1", "VGhpcyBpcyBhIHRlc3QgZmlsZQ0Kc2Vjb25kbGluZQ0KdGhpcmRsaW5l");
        assertEquals("DkgfEv8kuG5ZlsZaECSD6pHypzg=", res);
    }

}
