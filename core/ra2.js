import "../vendor/aes.js";
import "../vendor/sha1.js";
import "../vendor/jsencrypt.js";
import Base64 from './base64.js';

export class RA2Cipher {
    constructor(key) {
        // PRNG is used to generate IV for every encrypted message.
        // session key is also used as PRNG's seed.
        this._key = key;
        this._aes = new window.aesjs.AES(this._key);
        this._counter = new Uint8Array(16);
        this._iv = null;
        // a and b are parameters for PRNG.
        this._a = this._aes.encrypt(new Uint8Array(16));
        this._b = new Uint8Array(16);
        const v = this._a[0] >> 6;
        for (let i = 0; i < 15; i++) {
            this._b[i] = (this._a[i + 1] >> 6) | (this._a[i] << 2);
            this._a[i] = (this._a[i + 1] >> 7) | (this._a[i] << 1);
        }
        this._b[14] ^= v >> 1;
        const magic_numbers = new Uint8Array([0x0, 0x87, 0x0e, 0x89]);
        this._b[15] = 4 * this._a[15] ^ magic_numbers[v];
        this._a[15] = 2 * this._a[15] ^ magic_numbers[v >> 1];
    }

    encrypt(plaintext_msg) {
        this._compute_iv();
        let ctr = new window.aesjs.ModeOfOperation.ctr(this._key, new window.aesjs.Counter(this._iv));
        const encrypted = ctr.encrypt(plaintext_msg);
        const mac = this._mac(encrypted);
        let msg = new Uint8Array(encrypted.length + mac.length);
        msg.set(encrypted);
        msg.set(mac, encrypted.length);
        for (let i = 0; i < 16 && this._counter[i]++ === 255; i++);
        return msg;
    }

    decrypt(msg) {
        this._compute_iv();
        const encrypted = msg.subarray(0, msg.length - 16);
        const mac = this._mac(encrypted);
        for (let i = 0; i < 16; i++) {
            if (mac[i] != msg[msg.length - 16 + i]) {
                return undefined; // failed to authenticate the message
            }
        }
        let ctr = new window.aesjs.ModeOfOperation.ctr(this._key, new window.aesjs.Counter(this._iv));
        const decrypted = ctr.decrypt(encrypted);
        for (let i = 0; i < 16 && this._counter[i]++ === 255; i++);
        return decrypted;
    }

    _compute_iv() {
        this._iv = this._aes.encrypt(new Uint8Array(16));
        for (let i = 0; i < 16; i++) {
            this._iv[i] ^= this._counter[i] ^ this._a[i];
        }
        this._iv = this._aes.encrypt(this._iv);
    }

    _mac(encrypted, iv) {
        let c = this._aes.encrypt(new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        c[0] ^= (encrypted.length & 0xff00) >> 8;
        c[1] ^= encrypted.length & 0xff;
        c[2] ^= 0x80;
        for (let i = 0; i < 16; i++) {
            c[i] ^= this._b[i];
        }
        c = this._aes.encrypt(c);
        // compute the last block of CFB
        let buff = this._aes.encrypt(new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        ]));
        for (let i = 0, j = 0; i < encrypted.length; i++) {
            if (j === 16) {
                buff = this._aes.encrypt(buff);
                j = 1;
                buff[0] ^= encrypted[i];
            } else {
                buff[j] ^= encrypted[i];
                j++;
            }
        }
        if (encrypted.length % 16 != 0) {
            buff[encrypted.length % 16] ^= 0x80;
            for (let i = 0; i < 16; i++) {
                buff[i] ^= this._b[i];
            }
        } else {
            for (let i = 0; i < 16; i++) {
                buff[i] ^= this._a[i];
            }
        }
        buff = this._aes.encrypt(buff);
        let out = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            out[i] = this._iv[i] ^ buff[i] ^ c[i];
        }
        return out;
    }
}

export class RA2State {
    constructor() {
        this.state = 0;
        this._client_rsa_key = null;
        this._client_public_key = null;
        this._server_rsa_key = null;
        this._server_random = null;
        this._client_random = new Uint8Array(16);
        this._server_sha1 = null;
        this._client_sha1 = null;
        this._server_cipher = null;
        this._client_cipher = null;
        this._auth_type = undefined;
        if (window.crypto != undefined) {
            window.crypto.getRandomValues(this._client_random);
        } else if (window.msCrypto != undefined) {
            window.msCrypto.getRandomValues(this._client_random);
        } else {
            let rng = new window.SecureRandom();
            rng.nextBytes(this._client_random);
        }
    }

    get client_public_key() {
        return this._client_public_key;
    }

    get client_random_encrypted() {
        let msg = new Uint8Array(258);
        msg[0] = 1;
        const encrypted = Base64.decode(this._server_rsa_key.encrypt(this._client_random));
        msg.set(encrypted, 258 - encrypted.length);
        return msg;
    }

    get server_sha1() {
        return this._server_sha1;
    }

    get client_sha1() {
        return this._client_sha1;
    }

    get auth_type() {
        return this._auth_type;
    }

    set auth_type(t) {
        this._auth_type = t;
    }

    has_set_client_rsa_key() {
        return this._client_rsa_key !== null;
    }

    get_client_rsa_key() {
        return this._client_rsa_key.getPrivateKey();
    }

    set_client_rsa_key(key) {
        if (key !== null) {
            this._client_rsa_key = new window.JSEncrypt();
            this._client_rsa_key.setPrivateKey(key);
            this._set_client_public_key();
            return false;
        }
        do {
            this._client_rsa_key = new window.JSEncrypt({default_key_size: 2048});
            this._client_rsa_key.getKey();
        } while (this._client_rsa_key.key.n.bitLength() != 2048);
        this._set_client_public_key();
        return true;
    }

    parse_server_rsa_key(msg) {
        if (msg[0] !== 0 || msg[1] !== 0 || msg[2] !== 8 || msg[3] !== 0) {
            return false;
        }
        this._server_rsa_key = new window.JSEncrypt({default_key_size: 2048});
        const n = this._bigint_from_u8arr(msg.subarray(4, 260));
        const e = this._bigint_from_u8arr(msg.subarray(260, 516)).intValue();
        this._server_rsa_key.setPublicKey({
            n: n,
            e: e
        });
        let hash1 = window.sha1.create();
        let hash2 = window.sha1.create();
        hash1.update(msg);
        hash1.update(this._client_public_key);
        hash2.update(this._client_public_key);
        hash2.update(msg);
        this._server_sha1 = new Uint8Array(hash1.array());
        this._client_sha1 = new Uint8Array(hash2.array());
        return true;
    }

    parse_server_random(msg) {
        if (msg[0] !== 1 || msg[1] !== 0) {
            return false;
        }
        this._server_random = this._client_rsa_key.decrypt(Base64.encode(msg.subarray(2, 258)));
        return true;
    }

    set_cipher() {
        let client_key = window.sha1.create();
        let server_key = window.sha1.create();
        client_key.update(this._server_random);
        client_key.update(this._client_random);
        server_key.update(this._client_random);
        server_key.update(this._server_random);
        this._client_cipher = new RA2Cipher(new Uint8Array(client_key.array().slice(0, 16)));
        this._server_cipher = new RA2Cipher(new Uint8Array(server_key.array().slice(0, 16)));
    }

    make_message(data) {
        const encrypted = this._client_cipher.encrypt(data);
        let msg = new Uint8Array(data.length + 18);
        msg[0] = (data.length & 0xff00) >> 8;
        msg[1] = data.length & 0xff;
        msg.set(encrypted, 2);
        return msg;
    }

    decrypt(msg) {
        return this._server_cipher.decrypt(msg);
    }

    _set_client_public_key() {
        const client_n = new Uint8Array(this._client_rsa_key.key.n.toByteArray().slice(-256));
        let client_e = new Uint8Array(256);
        client_e[255] = this._client_rsa_key.key.e & 0xff;
        client_e[254] = (this._client_rsa_key.key.e & 0xff00) >> 8;
        client_e[253] = (this._client_rsa_key.key.e & 0xff0000) >> 16;
        client_e[252] = (this._client_rsa_key.key.e & 0xff000000) >> 24;
        this._client_public_key = new Uint8Array(516);
        this._client_public_key[2] = 0x08;
        this._client_public_key.set(client_n, 4);
        this._client_public_key.set(client_e, 260);
    }

    _bigint_from_u8arr(num) {
        let hex = "";
        for (let i = 0; i < num.length; i++) {
            let h = num[i].toString(16);
            h = h.length === 2 ? h : "0" + h;
            hex += h;
        }
        let bigint = new window.BigInteger(null);
        bigint.fromRadix(hex, 16);
        return bigint;
    }
}