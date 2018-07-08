import { Bytes32 } from 'thor-model-kit'
import { randomBytes } from 'crypto'
const Keythereum = require('keythereum')

/** to present encrypted private key in Ethereum keystore format. */
export type Keystore = {
    address: string
    id: string
    version: number
    meta?: Keystore.Meta
}

export namespace Keystore {
    /** extra meta info to describe the keystore */
    export type Meta = {
        identity: string
        provider: string
        [key: string]: any
    }

    /**
     * encrypt private key to keystore with given password
     * @param privateKey the private key to be encrypted
     * @param password 
     * @param meta extra meta info
     */
    export function encrypt(privateKey: Bytes32, password: string, meta?: Meta) {
        return new Promise<Keystore>(resolve => {
            Keythereum.dump(password, privateKey.bytes, randomBytes(32), randomBytes(16), {
                kdf: "scrypt",
                cipher: "aes-128-ctr",
                kdfparams: {
                    memory: 280000000,
                    dklen: 32,
                    n: 262144,
                    r: 8,
                    p: 1
                }
            }, (ks: Keystore) => {
                ks.meta = meta
                resolve(ks)
            })
        })
    }

    /**
     * decrypt private key from keystore
     * @param ks the keystore
     * @param password 
     */
    export function decrypt(ks: Keystore, password: string) {
        return new Promise<Bytes32>((resolve, reject) => {
            Keythereum.recover(password, ks, (r: Buffer | Error) => {
                if (!Buffer.isBuffer(r)) {
                    return reject(r)
                }
                resolve(new Bytes32(r))
            })
        })
    }

    /**
     * validate keystore data
     * @param ks the keystore
     */
    export function validate(ks: Keystore) {
        if (ks.version !== 1 && ks.version !== 3)
            throw new Error('invalid keystore: unsupported version')
        if (!/^[0-9a-f]{40}$/i.test(ks.address))
            throw new Error("invalid keystore: malformed address")
        if (!/^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/.test(ks.id))
            throw new Error("invalid keystore: malformed id")
    }
}