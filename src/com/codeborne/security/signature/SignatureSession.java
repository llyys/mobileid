package com.codeborne.security.signature;

import com.codeborne.security.digidoc.SignedDocInfo;

import java.io.Serializable;

public class SignatureSession implements Serializable {
    public final int sessCode;
    public SignedDocInfo signedDocInfo;
    public String challengeID;
    public String personalCode;
    public String signature;
    public String signatureId;

    public SignatureSession(int sessCode, SignedDocInfo value) {
        this.sessCode = sessCode;
        this.signedDocInfo = value;
    }
}
