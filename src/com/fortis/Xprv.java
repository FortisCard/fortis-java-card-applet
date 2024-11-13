package com.fortis;

import javacard.security.ECPrivateKey;

public class Xprv {
    public byte[] chainCode;
    public ECPrivateKey privateKey;
    public byte elliptic_curve;

    public Xprv(byte[] chainCode, ECPrivateKey privateKey, byte elliptic_curve) {
        this.chainCode = chainCode;
        this.privateKey = privateKey;
        this.elliptic_curve = elliptic_curve;
    }
}
