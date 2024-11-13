package com.fortis;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class FortisApplet extends Applet {
    // State variables
    private static byte[] encryptedMasterSeed;
    private static short pinAttempts;
    private boolean initialized = false;
    private static byte[] masterSeedFingerprint; // first 32 bits of sha256 of master seed

    // State variables where internal state is transient
    public static MessageDigest sha256;
    public static MessageDigest sha512;
    private static AESKey aesKey;
    private static Cipher aesCipher;
    private static Signature ecSignature;

    // Elliptic curve constants state variables
    public static jcmathlib.ResourceManager rm;
    public static jcmathlib.ECCurve SecP256k1;
    public static jcmathlib.ECPoint SecP256k1_G;
    public static jcmathlib.BigNat n;

    // Transient variables
    private byte[] sha256Result;
    private byte[] signature;
    private byte[] I;
    private byte[] IL;
    private byte[] IR;
    private byte[] decryptedMasterSeed;
    private static Object[] masterXprvArray;
    private byte[] pin;

    private static byte[] indexBytes;
    private static jcmathlib.BigNat purpose;
    private static jcmathlib.BigNat coin_type;
    private static jcmathlib.BigNat change;
    private static jcmathlib.BigNat address_index;

    private static byte[] r;
    private static byte[] s;

    private FortisApplet() {
        jcmathlib.OperationSupport.getInstance().setCard(jcmathlib.OperationSupport.JCOP4_P71);
        if (!jcmathlib.OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FortisApplet().register();
    }

    public boolean select() {
        if (!initialized) {
            initialize();
        }

        return true;
    }

    public void deselect() {
        JCSystem.requestObjectDeletion();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case Constants.INS_STORE_ENCRYPTED_MASTER_SEED:
                storeEncryptedMasterSeed(apdu);
                break;
            case Constants.INS_SIGN_TRANSACTION:
                signTransaction(apdu);
                break;
            case Constants.INS_ACCOUNT_DISCOVERY:
                getAccountXpubData(apdu);
                break;
            case Constants.INS_FIRMWARE_VERSION:
                Util.arrayCopyNonAtomic(Constants.FIRMWARE_VERSION, (short) 0, buffer, (short) 0, (short) 3);
                apdu.setOutgoingAndSend((short) 0, (short) 3);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    public void initTransient() {
        sha256Result = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        signature = JCSystem.makeTransientByteArray((short) 96, JCSystem.CLEAR_ON_DESELECT);
        I = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        IL = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        IR = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        decryptedMasterSeed = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        masterXprvArray = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        pin = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        indexBytes = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        purpose = new jcmathlib.BigNat((short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        coin_type = new jcmathlib.BigNat((short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        change = new jcmathlib.BigNat((short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        address_index = new jcmathlib.BigNat((short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        n = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        r = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        s = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        EllipticCurve.initTransient();
        BIP44KeyDerivation.initTransient();
        HMACSHA512.initTransient();
        HMACSHA256.initTransient();

    }

    public void initialize() {
        if (initialized) {
            return;
        }

        encryptedMasterSeed = new byte[Constants.ENCRYPTED_MASTER_SEED_LENGTH];
        masterSeedFingerprint = new byte[Constants.MASTER_SEED_FINGERPRINT_LENGTH];
        pinAttempts = 0;

        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        ecSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false); // Only sign with precomputed hash

        rm = new jcmathlib.ResourceManager(Constants.FINITE_FIELD_SIZE);
        SecP256k1 = new jcmathlib.ECCurve(jcmathlib.SecP256k1.p, jcmathlib.SecP256k1.a, jcmathlib.SecP256k1.b, jcmathlib.SecP256k1.G, jcmathlib.SecP256k1.r, rm);
        SecP256k1_G = new jcmathlib.ECPoint(SecP256k1);
        SecP256k1_G.setW(jcmathlib.SecP256k1.G, (short) 0, (short) 65);

        Constants.init();
        initTransient();

        initialized = true;
    }

    private void storeEncryptedMasterSeed(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();

        if (dataLength != Constants.ENCRYPTED_MASTER_SEED_LENGTH + Constants.MASTER_SEED_FINGERPRINT_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA),
                       encryptedMasterSeed, (short) 0, Constants.ENCRYPTED_MASTER_SEED_LENGTH);
        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + Constants.ENCRYPTED_MASTER_SEED_LENGTH),
                       masterSeedFingerprint, (short) 0, Constants.MASTER_SEED_FINGERPRINT_LENGTH);
    }

    private void signTransaction(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();

        /** NOTE: Only supporting the use of account 0' and indices 0-255, so ADPU should be
          * PIN (32) + purpose (1) + coin_type (4) + account (0) + change (1) + address_index (1) + elliptic curve (1) + unsigned transaction (32) */
        if (dataLength != 72) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, pin, (short) 0, (short) 32);
        Util.arrayFillNonAtomic(pin, (short) 32, (short) 0, (byte) 0);

        short pathOffset = (short) (ISO7816.OFFSET_CDATA + 32);
        Util.arrayFillNonAtomic(indexBytes, (short) 0, (short) 4, (byte) 0);

        indexBytes[3] = buffer[pathOffset];
        purpose.fromByteArray(indexBytes, (short) 0, (short) 4);
        purpose.add(Constants.BIP44_HARDENED_BIT);

        coin_type.fromByteArray(buffer, (short) (pathOffset + 1), (short) 4);
        coin_type.add(Constants.BIP44_HARDENED_BIT);

        indexBytes[3] = buffer[(short) (pathOffset + 5)];
        change.fromByteArray(indexBytes, (short) 0, (short) 4);

        indexBytes[3] = buffer[(short) (pathOffset + 6)];
        address_index.fromByteArray(indexBytes, (short) 0, (short) 4);

        byte elliptic_curve = buffer[(short) (pathOffset + 7)];

        short txOffset = (short) (pathOffset + 8);
        short txLength = (short) 32;

        decryptMasterXprv(apdu, elliptic_curve);
        Xprv masterXprv = (Xprv) masterXprvArray[0];
        if (masterXprv == null) {
            return; // PIN incorrect, response already sent
        }
        ECPrivateKey privateKey = BIP44KeyDerivation.deriveXprv(masterXprv, purpose, coin_type, change, address_index);

        byte recid = EllipticCurve.signTxHash(buffer, txOffset, txLength, privateKey, r, s);
        privateKey.clearKey();

        // Returns [recid, r, s]
        buffer[0] = recid;
        Util.arrayCopyNonAtomic(r, (short) 0, buffer, (short) 1, (short) 32);
        Util.arrayCopyNonAtomic(s, (short) 0, buffer, (short) 33, (short) 32);
        apdu.setOutgoingAndSend((short) 0, (short) 65);
    }

    private void getAccountXpubData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();

        // PIN (32) + purpose (1) + coin_type (4) + elliptic curve (1)
        if (dataLength != 38) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, pin, (short) 0, (short) 32);
        Util.arrayFillNonAtomic(pin, (short) 32, (short) 0, (byte) 0);

        short pathOffset = (short) (ISO7816.OFFSET_CDATA + 32);
        Util.arrayFillNonAtomic(indexBytes, (short) 0, (short) 4, (byte) 0);

        indexBytes[3] = buffer[pathOffset];
        purpose.fromByteArray(indexBytes, (short) 0, (short) 4);
        purpose.add(Constants.BIP44_HARDENED_BIT);

        coin_type.fromByteArray(buffer, (short) (pathOffset + 1), (short) 4);
        coin_type.add(Constants.BIP44_HARDENED_BIT);

        byte elliptic_curve = buffer[(short) (pathOffset + 5)];

        decryptMasterXprv(apdu, elliptic_curve);
        Xprv masterXprv = (Xprv) masterXprvArray[0];
        if (masterXprv == null) {
            return; // PIN incorrect, response already sent
        }

        Xprv coin_typeXprv = BIP44KeyDerivation.deriveCoinTypeXprv(masterXprv, purpose, coin_type);
        Xprv accountXprv = BIP44KeyDerivation.deriveAccountXprv(coin_typeXprv);
        sha256.doFinal(EllipticCurve.getPoint(coin_typeXprv.privateKey, coin_typeXprv.elliptic_curve), (short) 0, (short) 33, sha256Result, (short) 0);
        sha256.reset();

        /**
         * Returns the following
         *
         * sha256Result: SHA256 of coin type public key [0:31]
         * chainCode: chain code of account extended key [32:63]
         * public key: 33-byte SEC1 compressed form of account public key [63:96]
         *
         * The rest can be calculated without the need of any sensitive data, so offload to the FortisWallet
         */
        Util.arrayCopyNonAtomic(sha256Result, (short) 0, buffer, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(accountXprv.chainCode, (short) 0, buffer, (short) 32, (short) 32);
        Util.arrayCopyNonAtomic(EllipticCurve.getPoint(accountXprv.privateKey, accountXprv.elliptic_curve), (short) 0, buffer, (short) 64, (short) 33);
        apdu.setOutgoingAndSend((short) 0, (short) 97);
    }

    private void decryptMasterXprv(APDU apdu, byte elliptic_curve) {
        aesKey.setKey(pin, (short) 0);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);

        aesCipher.doFinal(encryptedMasterSeed, (short) 0, Constants.ENCRYPTED_MASTER_SEED_LENGTH, decryptedMasterSeed, (short) 0);
        sha256.doFinal(decryptedMasterSeed, (short) 0, (short) 64, sha256Result, (short) 0);
        // Failed decryption
        if (Util.arrayCompare(sha256Result, (short) 0, masterSeedFingerprint, (short) 0, Constants.MASTER_SEED_FINGERPRINT_LENGTH) != 0) {
            pinAttempts++;

            if (pinAttempts >= 3) {
                Util.arrayFillNonAtomic(encryptedMasterSeed, (short) 0, Constants.ENCRYPTED_MASTER_SEED_LENGTH, (byte) 0);
                Util.arrayFillNonAtomic(masterSeedFingerprint, (short) 0, Constants.MASTER_SEED_FINGERPRINT_LENGTH, (byte) 0);
                pinAttempts = 0;
                ISOException.throwIt(Constants.SW_TOO_MANY_INCORRECT_PIN);
            } else {
                byte[] buffer = apdu.getBuffer();
                buffer[0] = (byte) pinAttempts;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                ISOException.throwIt(Constants.SW_INCORRECT_PIN);
            }
        }
        pinAttempts = 0;

        // Reinitialize to clear internal state
        Util.arrayFillNonAtomic(pin, (short) 0, (short) 32, (byte) 0);
        aesKey.setKey(pin, (short) 0);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        sha256.reset();

        if (pinAttempts > 0) {
            return;
        }

        HMACSHA512.init(Constants.M_DEFAULT_KEY, (short) 0, (short) Constants.M_DEFAULT_KEY.length);
        HMACSHA512.doFinal(decryptedMasterSeed, (short) 0, (short) 64, I, (short) 0);

        Util.arrayCopyNonAtomic(I, (short) 0, IL, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(I, (short) 32, IR, (short) 0, (short) 32);

        ECPrivateKey privateKey = EllipticCurve.createECPrivateKey(elliptic_curve);
        privateKey.setS(IL, (short) 0, (short) 32);

        Xprv masterXprv = (Xprv) masterXprvArray[0];
        if (masterXprv == null) {
            masterXprv = new Xprv(IR, privateKey, elliptic_curve);
            masterXprvArray[0] = masterXprv;
        } else {
            Util.arrayCopyNonAtomic(IR, (short) 0, masterXprv.chainCode, (short) 0, (short) 32);
            masterXprv.privateKey = privateKey;
            masterXprv.elliptic_curve = elliptic_curve;
        }
    }
}
