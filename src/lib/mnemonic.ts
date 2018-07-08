
import BIP39 = require('bip39')
import HDKey = require('hdkey')
import { randomBytes } from 'crypto'
import { Bytes32 } from 'thor-model-kit'

// see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const VET_DERIVATION_PATH = `m/44'/818'/0'/0/0`


/** generate mnemonic words */
export function generate() {
    return BIP39.generateMnemonic(128, randomBytes).split(' ')
}

/** 
 * derive private key from mnemonic words according to BIP39.
 * the derivation path is defined at https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
export function derivePrivateKey(words: string[]) {
    let seed = BIP39.mnemonicToSeed(words.join(' '))
    let hdKey = HDKey.fromMasterSeed(seed)
    return new Bytes32(hdKey.derive(VET_DERIVATION_PATH).privateKey)
}
