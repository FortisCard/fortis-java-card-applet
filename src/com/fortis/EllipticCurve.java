package com.fortis;

import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;

public class EllipticCurve {
    private static byte[] SBytes;
    private static byte[] GBytes;
    private static byte[] tmp;
    private static byte[] pointBytes;
    private static byte[] nBytes;

    private static byte[] K;
    private static byte[] V;

    private static short privateKeyIndex;
    private static Object[] privateKeyArray;
    private static jcmathlib.BigNat k;
    private static jcmathlib.ECPoint R;
    private static jcmathlib.BigNat n;
    private static jcmathlib.BigNat r;
    private static jcmathlib.BigNat z;
    private static jcmathlib.BigNat S;
    private static byte[] xR;

    public static void initTransient() {
        SBytes = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        GBytes = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        tmp = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        pointBytes = JCSystem.makeTransientByteArray((short) 33, JCSystem.CLEAR_ON_DESELECT);
        nBytes = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        K = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        V = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        privateKeyIndex = 0;
        privateKeyArray = JCSystem.makeTransientObjectArray((short) 5, JCSystem.CLEAR_ON_DESELECT);
        k = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        R = new jcmathlib.ECPoint(FortisApplet.SecP256k1);
        n = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        r = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        z = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        S = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        xR = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    }

    public static ECPrivateKey createECPrivateKey(byte elliptic_curve) {
        // Use the transient object array to store and reuse ECPrivateKey objects because Java is stupid
        ECPrivateKey privateKey = (ECPrivateKey) privateKeyArray[privateKeyIndex];
        if (privateKey == null) {
            privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            privateKeyArray[privateKeyIndex] = privateKey;
        } else {
            privateKey.clearKey();
        }
        privateKeyIndex = (short) ((short) ((privateKeyIndex + (short) 1)) % (short) privateKeyArray.length);

        switch (elliptic_curve) {
            case Constants.SECP256K1:
                privateKey.setFieldFP(jcmathlib.SecP256k1.p, (short) 0, (short) 32);
                privateKey.setA(jcmathlib.SecP256k1.a, (short) 0, (short) 32);
                privateKey.setB(jcmathlib.SecP256k1.b, (short) 0, (short) 32);
                privateKey.setG(jcmathlib.SecP256k1.G, (short) 0, (short) 65);
                privateKey.setR(jcmathlib.SecP256k1.r, (short) 0, (short) 32);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                break;
        }

        return privateKey;
    }

    // Serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form
    public static byte[] getPoint(ECPrivateKey privateKey, byte elliptic_curve) {
        privateKey.getS(SBytes, (short) 0);
        privateKey.getG(GBytes, (short) 0);

        switch(elliptic_curve) {
            // Compute public key = S * G
            case Constants.SECP256K1:
                FortisApplet.SecP256k1_G.multiplication(SBytes, (short) 0, (short) SBytes.length);
                FortisApplet.SecP256k1_G.encode(tmp, (short) 0, true);
                FortisApplet.SecP256k1_G.setW(GBytes, (short) 0, (short) GBytes.length); // Reset G
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                break;
        }

        Util.arrayCopyNonAtomic(tmp, (short) 0, pointBytes, (short) 0, (short) 33);
        return pointBytes;
    }


    /* NOTE: Only works for secp256k1 as of now
     * @returns recid
     * @modifies rBytes, sBytes
     */
    public static byte signTxHash(byte[] hash, short hashOffset, short hashLength,
                           ECPrivateKey privateKey,
                           byte[] rBytes, byte[] sBytes) {
        privateKey.getR(nBytes, (short) 0);
        n.fromByteArray(nBytes, (short) 0, (short) 32);

        // k = rand(1, n - 1)
        /** NOTE: Uses RFC-697 to generate k
         * @see https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
         */

        // K = 0x00 0x00 0x00 ... 0x00
        // V = 0x01 0x01 0x01 ... 0x01
        Util.arrayFillNonAtomic(K, (short) 0, (short) 32, (byte) 0x00);
        Util.arrayFillNonAtomic(V, (short) 0, (short) 32, (byte) 0x01);

        // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        privateKey.getS(SBytes, (short) 0);
        HMACSHA256.init(K, (short) 0, (short) K.length);
        HMACSHA256.doFinal(V, (short) 0, (short) V.length, tmp, (short) 0);
        tmp[0] = 0x00;
        HMACSHA256.doFinal(tmp, (short) 0, (short) 1, tmp, (short) 0);
        HMACSHA256.doFinal(SBytes, (short) 0, (short) SBytes.length, tmp, (short) 0);
        HMACSHA256.doFinal(hash, hashOffset, hashLength, K, (short) 0);

        // V = HMAC_K(V)
        HMACSHA256.init(K, (short) 0, (short) K.length);
        HMACSHA256.doFinal(V, (short) 0, (short) V.length, V, (short) 0);

        // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
        HMACSHA256.init(K, (short) 0, (short) K.length);
        HMACSHA256.doFinal(V, (short) 0, (short) V.length, tmp, (short) 0);
        tmp[0] = 0x01;
        HMACSHA256.doFinal(tmp, (short) 0, (short) 1, tmp, (short) 0);
        HMACSHA256.doFinal(SBytes, (short) 0, (short) SBytes.length, tmp, (short) 0);
        HMACSHA256.doFinal(hash, hashOffset, hashLength, K, (short) 0);

        // V = HMAC_K(V)
        HMACSHA256.init(K, (short) 0, (short) K.length);
        HMACSHA256.doFinal(V, (short) 0, (short) V.length, V, (short) 0);

        // Generate candidate k values
        do {
            HMACSHA256.init(K, (short) 0, (short) K.length);
            HMACSHA256.doFinal(V, (short) 0, (short) V.length, V, (short) 0);
            k.fromByteArray(V, (short) 0, (short) 32);
            if (k.isZero() || !k.isLesser(n)) {
                HMACSHA256.init(K, (short) 0, (short) K.length);
                HMACSHA256.doFinal(V, (short) 0, (short) V.length, tmp, (short) 0);
                tmp[0] = 0x00;
                HMACSHA256.doFinal(tmp, (short) 0, (short) 1, K, (short) 0);
                HMACSHA256.init(K, (short) 0, (short) K.length);
                HMACSHA256.doFinal(V, (short) 0, (short) V.length, V, (short) 0);
            }
        } while (k.isZero() || !k.isLesser(n));

        // R = k * G
        privateKey.getG(GBytes, (short) 0);
        R.setW(GBytes, (short) 0, (short) GBytes.length);
        R.multiplication(k);

        // Compute r = x_R mod n
        R.getX(xR, (short) 0);

        r.fromByteArray(xR, (short) 0, (short) 32);
        r.mod(n);
        r.copyToByteArray(rBytes, (short) 0);

        // s = k^-1 * (z + r * S) mod n
        z.fromByteArray(hash, hashOffset, hashLength);

        privateKey.getS(SBytes, (short) 0);
        S.fromByteArray(SBytes, (short) 0, (short) 32);

        k.modInv(n);
        r.modMult(S, n);
        r.modAdd(z, n);
        k.modMult(r, n);
        k.copyToByteArray(sBytes, (short) 0);

        // recid = y_R mod 2
        return R.isYEven() ? (byte) 0 : (byte) 1;
  }
}
