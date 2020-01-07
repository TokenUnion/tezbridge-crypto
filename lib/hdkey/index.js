//      

const ed25519 = require('./ed25519')
const p256 = require('./p256').HDKey
import secp256k1 from './secp256k1'


export function deriveKey(seed             , path         , scheme                                   ) {
  const mapping = {
    ed25519() {
      return ed25519.derivePath(path, seed).key
    },
    p256() {
      const node = p256.fromMasterSeed(seed)
      return node.derive(path)._privateKey
    },
    secp256k1() {
      const node = secp256k1.fromMasterSeed(seed)
      return node.derive(path)._privateKey
    }
  }
  return mapping[scheme]()
}
