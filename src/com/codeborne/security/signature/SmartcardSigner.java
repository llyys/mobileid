package com.codeborne.security.signature;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.SignedDocInfo;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;

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

            String certHex=SmartcardSigner.bin2hex(signersCertificate.getBytes());//convert to hex cert format

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
     * Converts a hex string to byte array
     * @param hexString input data
     * @return byte array
     */
    public static byte[] hex2bin(String hexString)
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            for(int i = 0; (hexString != null) &&
                    (i < hexString.length()); i += 2) {
                String tmp = hexString.substring(i, i+2);
                Integer x = new Integer(Integer.parseInt(tmp, 16));
                bos.write(x.byteValue());
            }
        } catch(Exception ex) {
            System.err.println("Error converting hex string: " + ex);
        }
        return bos.toByteArray();
    }

    /**
     * Converts a byte array to hex string
     * @param arr byte array input data
     * @return hex string
     */
    public static String bin2hex(byte[] arr)
    {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < arr.length; i++) {
            String str = Integer.toHexString((int)arr[i]);
            if(str.length() == 2)
                sb.append(str);
            if(str.length() < 2) {
                sb.append("0");
                sb.append(str);
            }
            if(str.length() > 2)
                sb.append(str.substring(str.length()-2));
        }
        return sb.toString();
    }

}