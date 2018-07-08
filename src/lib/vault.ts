import Path = require('path')
import { blake2b256, Address } from 'thor-model-kit'
import { Keystore } from './keystore'
import FS = require('fs-extra')

/**
 * manages accounts in keystore format stored in file system
 */
export class Vault {
    /**
     * the constructor
     * @param dir the directory of the vault
     */
    constructor(public readonly dir: string) { }
    /** list all managed accounts */
    async list() {
        await ensureDir(this.dir)

        let files = (await FS.readdir(this.dir)).filter(file => Path.extname(file) === keystoreFileExt)
        let accounts = []
        for (let file of files) {
            try {
                let path = Path.resolve(this.dir, file)
                let ks = await loadKeystore(path)
                accounts.push(newAccount(path, ks))
            } catch{
            }
        }
        return accounts
    }

    /**
     * import keystore as new account
     * @param ks the keystore
     */
    async import(ks: Keystore) {
        await ensureDir(this.dir)
        let path = await saveKeystore(this.dir, ks)
        return newAccount(path, ks)
    }
}

export namespace Vault {
    /** account interface */
    export interface Account {
        readonly address: Address
        readonly keystore: Keystore
        update(ks: Keystore): Promise<void>
        unlink(): Promise<void>
    }
}

function newAccount(path: string, ks: Keystore): Vault.Account {
    return {
        get address() { return Address.fromHex(ks.address, '') },
        get keystore() { return ks },
        async update(newKS: Keystore) {
            let newPath = await saveKeystore(Path.dirname(path), newKS)
            ks = newKS
            if (path !== newPath) {
                try {
                    await FS.unlink(path)
                } catch{ }
                path = newPath
            }
        },
        unlink() { return FS.unlink(path) }
    }
}
async function saveKeystore(dir: string, ks: Keystore) {
    Keystore.validate(ks)
    let ksData = JSON.stringify(ks)

    let path = Path.resolve(dir, fileName(ks.address, ksData))
    await writeFileAtomic(path, ksData)
    return path
}

async function loadKeystore(path: string) {
    if ((await FS.stat(path)).size > 4096)
        throw new Error("keystore file too large")

    let ksData = (await FS.readFile(path, { encoding: 'utf8' })) as string
    let ks = JSON.parse(ksData) as Keystore
    Keystore.validate(ks)

    if (Path.basename(path) !== fileName(ks.address, ksData))
        throw new Error("keystore file checksum incorrect")

    return ks
}

const keystoreFileExt = '.keystore'
function fileName(address: string, ksData: string) {
    let hash = blake2b256(ksData)
    return address + '-' + hash.bytes.slice(0, 4).toString('hex') + keystoreFileExt
}

async function ensureDir(dir: string) {
    if (!(await FS.pathExists(dir))) {
        await FS.ensureDir(dir)
        await FS.chmod(dir, 0o700)
    }
}

let tmpFileSuffix = Math.round(Math.random() * (2 ** 32))
async function writeFileAtomic(path: string, data: string) {
    let tempPath = path + '.tmp' + (tmpFileSuffix++)
    try {
        await FS.writeFile(tempPath, data, { encoding: 'utf8', mode: 0o600, flag: 'w' })
        await FS.rename(tempPath, path)
    } finally {
        try {
            await FS.unlink(tempPath)
        } catch { }
    }
}
