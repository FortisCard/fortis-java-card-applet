package com.fortis;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class HMACSHA512 {
    private static final short BLOCK_SIZE = 128;
    private static final short OUTPUT_SIZE = 64;
    private static final byte IPAD = (byte) 0x36;
    private static final byte OPAD = (byte) 0x5c;

    private static byte[] key;
    private static byte[] ipadKey;
    private static byte[] opadKey;
    private static byte[] innerHash;

    public static void initTransient() {
        if (key == null) key = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        if (ipadKey == null) ipadKey = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        if (opadKey == null) opadKey = JCSystem.makeTransientByteArray(BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        if (innerHash == null) innerHash = JCSystem.makeTransientByteArray(OUTPUT_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void init(byte[] keyBuffer, short keyOffset, short keyLength) {
        Util.arrayFillNonAtomic(key, (short) 0, BLOCK_SIZE, (byte) 0);
        if (keyLength > BLOCK_SIZE) {
            FortisApplet.sha512.reset();
            FortisApplet.sha512.doFinal(keyBuffer, keyOffset, keyLength, key, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuffer, keyOffset, key, (short) 0, keyLength);
        }

        for (short i = 0; i < BLOCK_SIZE; i++) {
            ipadKey[i] = (byte) (key[i] ^ IPAD);
            opadKey[i] = (byte) (key[i] ^ OPAD);
        }
    }

    public static void doFinal(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        // Inner hash
        FortisApplet.sha512.reset();
        FortisApplet.sha512.update(ipadKey, (short) 0, BLOCK_SIZE);
        FortisApplet.sha512.doFinal(inBuffer, inOffset, inLength, innerHash, (short) 0);

        // Outer hash
        FortisApplet.sha512.reset();
        FortisApplet.sha512.update(opadKey, (short) 0, BLOCK_SIZE);
        FortisApplet.sha512.doFinal(innerHash, (short) 0, OUTPUT_SIZE, outBuffer, outOffset);

        // Clear sensitive data
        FortisApplet.sha512.reset();
    }
}
