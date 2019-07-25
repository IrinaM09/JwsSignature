package com.company;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    private static void signatureGenerator(String payload) {
        MessageDigest digest;
        try {
            /* Compute Header */
            String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiIxMzNjMTE0NzA3NDBkN2VkMzNjODZjMzUwMWUzYWM4MjIxZmVjZTAzIn0";

            System.out.println("header: \n" + header);

            /*Compute String for {"SHA256":"<String>"} which will be the Payload */
            digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(payload.getBytes(UTF_8));
            String result = bytesToHex(encodedhash);

            String part2 = "{\"SHA256\":\"" + result + "\"}";

            System.out.println(part2);

            String encodedURL = Base64.getEncoder().encodeToString(part2.getBytes());
            encodedURL = encodedURL.replaceAll("\\+", "-");
            encodedURL = encodedURL.replaceAll("/", "_");
            encodedURL = encodedURL.replaceAll("=", "");


            System.out.println("payload: \n" + encodedURL);

            /* Compute signature */
            String signatureConcatenation = header + "." + encodedURL;

            File file = new File("cert.key");

            BufferedReader br = new BufferedReader(new FileReader(file));

            String privateKeyContent = "";
            int i;

            while ((i = br.read()) != -1)
                privateKeyContent += (char) i;

            privateKeyContent = privateKeyContent.replace("-----BEGIN RSA PRIVATE KEY-----", "");
            privateKeyContent = privateKeyContent.replace("-----END RSA PRIVATE KEY-----", "");
            privateKeyContent = privateKeyContent.replaceAll("\\s+", "");
            privateKeyContent = privateKeyContent.replaceAll("\n", "");
            privateKeyContent = privateKeyContent.replaceAll(" ", "");

            byte[] bytes = Base64.getDecoder().decode(privateKeyContent);

            DerInputStream derReader = new DerInputStream(bytes);
            DerValue[] seq = derReader.getSequence(0);

            BigInteger modulus = seq[1].getBigInteger();
            BigInteger publicExp = seq[2].getBigInteger();
            BigInteger privateExp = seq[3].getBigInteger();
            BigInteger prime1 = seq[4].getBigInteger();
            BigInteger prime2 = seq[5].getBigInteger();
            BigInteger exp1 = seq[6].getBigInteger();
            BigInteger exp2 = seq[7].getBigInteger();
            BigInteger crtCoef = seq[8].getBigInteger();

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey pKey = keyFactory.generatePrivate(keySpec);

            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(pKey);
            sign.update(signatureConcatenation.getBytes(UTF_8));
            String signedSignature = new String(Base64.getEncoder().encode(sign.sign()));

            signedSignature = signedSignature.replaceAll("\\+", "-");
            signedSignature = signedSignature.replaceAll("/", "_");
            signedSignature = signedSignature.replaceAll("=", "");

            System.out.println("JWS-signature: ");
            String signature = signatureConcatenation + "." + signedSignature;
            System.out.println(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        //PLEASE INSERT JSON PAYLOAD BELOW
        String payload = "{\"headers\":{\"Branch-Location\":\"RO\",\"X-Request-ID\":\"b7d96357-b320-4f54-bb02-1c4511e4b772\",\"PSU-IP-Address\":\"127.0.0.1\"},\"payload\":{\"endToEndIdentification\":\"test\",\"instructedAmount\":{\"currency\":\"RON\",\"amount\":\"101\"},\"creditorAccount\":{\"iban\":\"RO61TREZ27A660404200109X\"},\"creditorName\":\"PaySafe\"}}";
       // payload = "{\"headers\":{\"Branch-Location\":\"RO\",\"X-Request-ID\":\"35ffcd8e-3453-4dcc-a6cc-c74ea2344822\"},\"payload\":{\"access\":{\"balances\":[],\"transactions\":[]},\"recurringIndicator\":true,\"validUntil\":\"2019-11-01\",\"frequencyPerDay\":\"4\"}}";
        signatureGenerator(payload);
    }
}
