package com.codeborne.security.signature;

import com.codeborne.security.digidoc.SignedDocInfo;

import java.io.File;
import java.io.Serializable;
import java.util.List;

public class SignatureSession implements Serializable {
    public final int sessCode;
    public SignedDocInfo signedDocInfo;
    public String challengeID;
    public String personalCode;
    public String signature;
    public String signatureId;
    public boolean isCompact;
    public List<File> files;

    public SignatureSession(int sessCode, SignedDocInfo value) {
        this.sessCode = sessCode;
        this.signedDocInfo = value;
    }
}
