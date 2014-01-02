package com.codeborne.security.signature;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.SignedDocInfo;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;

import javax.xml.rpc.holders.IntHolder;
import javax.xml.rpc.holders.StringHolder;
import java.net.MalformedURLException;
import java.rmi.RemoteException;

import static com.codeborne.security.AuthenticationException.Code.valueOf;

public class MobileIDSigner extends Signer {

    private int retryCount = 60;
    private int pollIntervalMs = 3000;

    public MobileIDSigner(String digidocServiceURL, String serviceName) throws MalformedURLException {
        super(digidocServiceURL, serviceName);
    }

    public void mobileSign(SignatureSession session, String signerIDCode, String signersCountry, String signerPhoneNo, String serviceName, String additionalDataToBeDisplayed, String language, String role, String city, String stateOrProvince, String postalCode, String countryName, String signingProfile, String messagingMode, int asyncConfiguration, boolean returnDocInfo, boolean returnDocData){
        try {
            StringHolder status = new StringHolder();
            StringHolder statusCode = new StringHolder();
            StringHolder challengeID = new StringHolder();
            session.personalCode=signerIDCode;
            service.mobileSign(session.sessCode, signerIDCode, signersCountry, signerPhoneNo, serviceName, additionalDataToBeDisplayed, language, role, city, stateOrProvince, postalCode, countryName, signingProfile, messagingMode, asyncConfiguration, returnDocInfo, returnDocData, status, statusCode, challengeID);

            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            session.challengeID=challengeID.value;

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

    public void mobileSign(SignatureSession session, String signerIDCode, String signerPhoneNo, String serviceName,  int asyncConfiguration, boolean returnDocInfo, boolean returnDocData){
        String language = "EST";
        String signingProfile="";
        String messagingMode="asynchClientServer";

        mobileSign(session, signerIDCode, "EE", signerPhoneNo, serviceName, null, language, null, null, null, null, null, signingProfile, messagingMode, asyncConfiguration, returnDocInfo, returnDocData);
    }

    /**
     * In asynchronous Client-Server mode the application should keep up
     * sending a GetStatusInfo request to DigiDocService until signing process
     * is either successful or unsuccessful.
     *
     * GetStatusInfo request is for getting the information about the document in
     * session (signed) and it’s status.
     * GetStatusInfo request is also used in mobile signing in asynchronous Client-Server mode to get the signing process’es state information.
     */
    public String getStatusInfo(SignatureSession session, boolean waitSignature, boolean returnDocInfo){
        try{
            StringHolder status = new StringHolder();
            StringHolder statusCode = new StringHolder();
            SignedDocInfoHolder signedDocInfo = new SignedDocInfoHolder();
            service.getStatusInfo(session.sessCode, returnDocInfo, waitSignature, status, statusCode, signedDocInfo);

            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            return statusCode.value;

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

    public boolean waitForSigning(SignatureSession session) {
        int tryCount = 0;
        while (sleep(pollIntervalMs) && !isSigningComplete(session) && tryCount < retryCount) {
            tryCount++;
        }
        if (tryCount >= retryCount)
            throw new AuthenticationException(valueOf(getSigningStatus(session)));
        return true;
    }


    public boolean isSigningComplete(SignatureSession session) {
        String status = getStatusInfo(session, false, false);
        if ("OUTSTANDING_TRANSACTION".equals(status) || "REQUEST_OK".equals(status))
            return false;
        else if ("SIGNATURE".equals(status))
            return true;
        else
            throw new AuthenticationException(valueOf(status));
    }

    private String getSigningStatus(SignatureSession session) {
        StringHolder status = new StringHolder("OUTSTANDING_TRANSACTION");
        try {
            StringHolder signature = new StringHolder();
            IntHolder sesscode = new IntHolder(session.sessCode);
            service.getMobileCreateSignatureStatus(sesscode, false, status, signature);
            session.signature=signature.value;
        }
        catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
        return status.value;
    }
}
