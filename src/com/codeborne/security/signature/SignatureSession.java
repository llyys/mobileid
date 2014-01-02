package com.codeborne.security.signature;

import com.codeborne.security.digidoc.SignedDocInfo;
import ee.sk.digidoc.SignedDoc;

public class SignatureSession {
    public final int sessCode;
    public SignedDocInfo signedDocInfo;
    public SignedDoc sdoc;
    public String challengeID;
    public String personalCode;
    public String signature;
    public String signatureId;

    public SignatureSession(int sessCode, SignedDocInfo value, SignedDoc sdoc) {
        this.sessCode = sessCode;
        this.signedDocInfo = value;
        this.sdoc = sdoc;
    }
}
