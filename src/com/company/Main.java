package com.company;

import sun.misc.IOUtils;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    private static void signatureGenerator(String payload) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(payload.getBytes(UTF_8));
            String result = bytesToHex(encodedhash);

            System.out.println(result);

            String part2 = "{\"SHA256\":" + result + "\"}";
            System.out.println(part2);

            String encodedURL = Base64.getUrlEncoder().encodeToString(part2.getBytes());
            encodedURL = encodedURL.replaceAll("\\+", "-");
            encodedURL = encodedURL.replaceAll("/", "_");
            encodedURL = encodedURL.replaceAll("=", "");
            System.out.println(encodedURL);

            String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiIxMzNjMTE0NzA3NDBkN2VkMzNjODZjMzUwMWUzYWM4MjIxZmVjZTAzIn0";

            String signatureConcatenation = header + "." + encodedURL;
            System.out.println(signatureConcatenation);

            File file = new File("cert.key");

            BufferedReader br = new BufferedReader(new FileReader(file));

            String privateKeyContent = "";
            int i;

            while ((i = br.read()) != -1)
                privateKeyContent += (char) i;

            System.out.println(privateKeyContent);

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
            System.out.println(pKey);

            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(pKey);
            sign.update(signatureConcatenation.getBytes("UTF-8"));
            String signedSignature = new String(Base64.getEncoder().encode(sign.sign()));

            System.out.println(signedSignature);

            signedSignature = signedSignature.replaceAll("\\+", "-");
            signedSignature = signedSignature.replaceAll("/", "_");
            signedSignature = signedSignature.replaceAll("=", "");

            System.out.println("result: ");
            String signature = signatureConcatenation + "." + signedSignature;
            System.out.printf(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static PrivateKey get(String filename)
            throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        String payload = "{\"headers\":{\"Branch-Location\":\"RO\",\"X-Request-ID\":\"b7d96357-b320-4f54-bb02-1c4511e4b772\",\"PSU-IP-Address\":\"127.0.0.1\"},\"payload\":{\"endToEndIdentification\":\"test\",\"instructedAmount\":{\"currency\":\"RON\",\"amount\":\"101\"},\"creditorAccount\":{\"iban\":\"RO61TREZ27A660404200109X\"},\"creditorName\":\"PaySafe\"}}";
        signatureGenerator(payload);
    }
}
