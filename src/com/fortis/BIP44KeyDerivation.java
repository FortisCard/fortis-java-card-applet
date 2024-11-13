package com.fortis;

import javacard.security.ECPrivateKey;
import javacard.framework.Util;
import javacard.framework.JCSystem;

public class BIP44KeyDerivation {
    private static byte[] data;
    private static byte[] I;
    private static byte[] indexBytes;

    private static byte[] IL;
    private static byte[] IR;

    private static byte[] nBytes;
    private static byte[] kIBytes;
    private static byte[] kParBytes;

    private static jcmathlib.BigNat n;
    private static jcmathlib.BigNat kPar;
    private static jcmathlib.BigNat kI;

    private static Object[] xprvArray;
    private static short xprvIndex;

    public static void initTransient() {
        data = JCSystem.makeTransientByteArray((short) 37, JCSystem.CLEAR_ON_DESELECT);
        I = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        indexBytes = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        IL = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        IR = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        nBytes = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        kIBytes = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        kParBytes = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        n = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        kPar = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        kI = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, FortisApplet.rm);
        xprvArray = JCSystem.makeTransientObjectArray((short) 5, JCSystem.CLEAR_ON_DESELECT);
        xprvIndex = 0;
    }

    public static ECPrivateKey deriveXprv(Xprv masterXprv, jcmathlib.BigNat purpose, jcmathlib.BigNat coin_type, jcmathlib.BigNat change, jcmathlib.BigNat address_index) {
        Xprv derivedXprv = masterXprv;

        derivedXprv = deriveBIP32ChildXprv(derivedXprv, purpose);
        derivedXprv = deriveBIP32ChildXprv(derivedXprv, coin_type);
        derivedXprv = deriveBIP32ChildXprv(derivedXprv, Constants.BIP44_HARDENED_BIT); // Account 0'
        derivedXprv = deriveBIP32ChildXprv(derivedXprv, change);
        derivedXprv = deriveBIP32ChildXprv(derivedXprv, address_index);

        return derivedXprv.privateKey;
    }

    public static Xprv deriveAccountXprv(Xprv coin_type) {
        return deriveBIP32ChildXprv(coin_type, Constants.BIP44_HARDENED_BIT); // Account 0'
    }

    public static Xprv deriveCoinTypeXprv(Xprv masterXprv, jcmathlib.BigNat purpose, jcmathlib.BigNat coin_type) {
        Xprv derivedXprv = masterXprv;

        derivedXprv = deriveBIP32ChildXprv(derivedXprv, purpose);
        derivedXprv = deriveBIP32ChildXprv(derivedXprv, coin_type);

        return derivedXprv;
    }

    private static Xprv deriveBIP32ChildXprv(Xprv parentXprv, jcmathlib.BigNat index) {
        index.copyToByteArray(indexBytes, (short) 0);

        if ((indexBytes[0] & 0x80) != 0) {
            // Hardened child
            data[0] = 0x00;
            parentXprv.privateKey.getS(data, (short) 1);
        } else {
            // Normal child
            Util.arrayCopyNonAtomic(EllipticCurve.getPoint(parentXprv.privateKey, parentXprv.elliptic_curve), (short) 0, data, (short) (0), (short) 33);
        }

        Util.arrayCopyNonAtomic(indexBytes, (short) 0, data, (short) 33, (short) 4);

        HMACSHA512.init(parentXprv.chainCode, (short) 0, (short) 32);
        HMACSHA512.doFinal(data, (short) 0, (short) 37, I, (short) 0);

        Util.arrayCopyNonAtomic(I, (short) 0, IL, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(I, (short) 32, IR, (short) 0, (short) 32);

        // Compute the child private key
        parentXprv.privateKey.getR(nBytes, (short) 0);
        n.fromByteArray(nBytes, (short) 0, (short) 32);

        parentXprv.privateKey.getS(kParBytes, (short) 0);
        kPar.fromByteArray(kParBytes, (short) 0, (short) 32);
        kI.fromByteArray(IL, (short) 0, (short) 32);
        kI.modAdd(kPar, n);

        // Check if derived key is invalid
        if (kI.isZero() || n.isLesser(kI)) {
            // Increment index and try again
            index.increment();
            return deriveBIP32ChildXprv(parentXprv, index);
        }
        ECPrivateKey childPrivateKey = EllipticCurve.createECPrivateKey(parentXprv.elliptic_curve);

        kI.copyToByteArray(kIBytes, (short) 0);
        childPrivateKey.setS(kIBytes, (short) 0, (short) 32);

        Xprv childXprv = (Xprv) xprvArray[xprvIndex];
        if (childXprv == null) {
            childXprv = new Xprv(IR, childPrivateKey, parentXprv.elliptic_curve);
            xprvArray[xprvIndex] = childXprv;
        } else {
            Util.arrayCopyNonAtomic(IR, (short) 0, childXprv.chainCode, (short) 0, (short) 32);
            childXprv.privateKey = childPrivateKey;
            childXprv.elliptic_curve = parentXprv.elliptic_curve;
        }
        xprvIndex = (short) ((short) (xprvIndex + 1) % (short) xprvArray.length);

        return childXprv;
    }
}
