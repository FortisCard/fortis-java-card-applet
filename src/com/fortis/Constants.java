package com.fortis;

import javacard.framework.JCSystem;

public class Constants {
    // Javacard instructions
    public static final byte INS_STORE_ENCRYPTED_MASTER_SEED = (byte) 0x10;
    public static final byte INS_SIGN_TRANSACTION = (byte) 0x20;
    public static final byte INS_ACCOUNT_DISCOVERY = (byte) 0x30;
    public static final byte INS_FIRMWARE_VERSION = (byte) 0x40;

    // Sizes
    // NOTE: Fingerprint is first 32 bits of sha256 of data
    public static final short ENCRYPTED_MASTER_SEED_LENGTH = 64;
    public static final short MASTER_SEED_FINGERPRINT_LENGTH = 4;
    public static jcmathlib.BigNat BIP44_HARDENED_BIT;
    public static final byte[] M_DEFAULT_KEY = new byte[]{0x42, 0x69, 0x74, 0x63, 0x6F, 0x69, 0x6E, 0x20, 0x73, 0x65, 0x65, 0x64}; // b'Bitcoin seed';
    public static final byte[] FIRMWARE_VERSION = new byte[]{0x01, 0x00, 0x00}; // [Major Version, Minor Version, Patch Version]

    // Elliptic curves
    public static final short FINITE_FIELD_SIZE = 256; // Keep as a constant for now as all implemented curves use a 256-bit field

    public static final byte SECP256K1 = (byte) 0x10;

    // Error codes
    public static final short SW_INCORRECT_PIN = (short) 0x9704;
    public static final short SW_TOO_MANY_INCORRECT_PIN = (short) 0x9700;

    public static void init() {
        BIP44_HARDENED_BIT = new jcmathlib.BigNat((short) 4, JCSystem.MEMORY_TYPE_PERSISTENT, FortisApplet.rm);
        BIP44_HARDENED_BIT.fromByteArray(new byte[]{(byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00}, (short) 0, (short) 4);
    }
}
