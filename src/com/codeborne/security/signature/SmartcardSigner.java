package com.codeborne.security.signature;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.SignedDocInfo;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;
import org.apache.commons.codec.binary.Base64;
import sun.misc.Regexp;

import javax.xml.rpc.holders.StringHolder;
import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.rmi.RemoteException;

import static com.codeborne.security.AuthenticationException.Code.valueOf;

public class SmartcardSigner extends Signer{

    public SmartcardSigner(String digidocServiceURL, String serviceName) throws MalformedURLException {
        super(digidocServiceURL, serviceName);
    }

    /**
     * The request is used for digital signing preparation if signing with smartcard.
     * As a result of the request a new so called half-done signature is added to the
     * DigiDoc conteiner in session and the unique identifier of the signature and the
     * hash to be signed is returned. The hash should be forwarded to the the signing
     * software (ActiveX or Java Applet or JavaScript) of the user’s computer.
     *
     * @param session – An identifier of the active session.
     * @param signersCertificate - signer’s certificate transferred to HEX string format (from binary (DER) format).
     * @param signersTokenId - identifier of the private key’s slot on a smartcard.
     * @param role - The text of the role or resolution defined by the user
     * @param city - Name of the city, where it’s signed.
     * @param state - Name of the state, where it’s signed.
     * @param postalCode
     * @param country
     * @param signingProfile
     * @return – The hash to be signed as a hexadecimal string
     */
    public String PrepareSignature(SignatureSession session, String signersCertificate, String signersTokenId, String role, String city, String state, String postalCode, String country, String signingProfile){
        try {
            StringHolder status = new StringHolder();
            StringHolder signatureId = new StringHolder();
            StringHolder signedDocData = new StringHolder();
            StringHolder signedInfoDigest = new StringHolder();
            byte[] der=SmartcardSigner.convertPemToDer(signersCertificate);//PEM (base64) format certificate converted DER (Binary) format.
            String certHex=SmartcardSigner.bin2hex(der);//convert to hex cert format

            service.prepareSignature(session.sessCode, certHex, signersTokenId, role, city, state, postalCode, country, signingProfile, status, signatureId, signedInfoDigest);

            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            session.challengeID=signatureId.value;
            session.signatureId=signatureId.value;
            session.signature = signedInfoDigest.value;
            return signedInfoDigest.value;

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

    /**
     * The request is used for finalizing the digital signing while signing with smartcard.
     * With FinalizeSignature request the signature prepared at PrepareSignature step
     * is finished. A digitally signed signature is added to DigiDoc file and an OCSP
     * validity confirmation is taken.
     *
     * @param session
     * @return
     */
    public String FinalizeSignature(SignatureSession session, String signature) throws Exception {
        try {
            StringHolder status = new StringHolder();
            if(session.signatureId==null)
                session.signatureId="S"+(session.signedDocInfo.getSignatureInfo()==null?0:session.signedDocInfo.getSignatureInfo().length);

            session.signature=signature;
            SignedDocInfoHolder signedDocData = new SignedDocInfoHolder();

            service.finalizeSignature(session.sessCode, session.signatureId, session.signature, status, signedDocData);

            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            return getSignedDoc(session);
            //session.challengeID=signatureId.value;
            //return signedDocData.value;

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

    /**
     * Converts a byte array to hex string
     * @param arr byte array input data
     * @return hex string
     */
    private static char[] hexArray = "0123456789abcdef".toCharArray();
    public static String bin2hex(byte[] bytes)
    {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] convertPemToDer(String cert) {
        cert=cert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "");
        cert=cert.replaceAll("\n|\r", "");
        return Base64.decodeBase64(cert.getBytes());
    }
}
