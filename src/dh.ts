import MillerRabin from 'miller-rabin'
import randomBytes from '@bicycle-codes/randombytes'
import BN from 'bn.js'
import {
    concat,
    fromString,
    type SupportedEncodings,
    toString
} from 'uint8arrays'
import primes from './generate-prime.js'

const millerRabin = new MillerRabin()
const TWENTYFOUR = new BN(24)
const ELEVEN = new BN(11)
const TEN = new BN(10)
const THREE = new BN(3)
const SEVEN = new BN(7)

export class DH {
    _pub:BN
    _priv:BN
    _prime:BN
    __prime:BN
    _primeLen:BN
    _primeCode?:number
    _gen:BN
    __gen:Uint8Array|null = null
    _malleable:boolean

    static BN = BN

    constructor (prime, generator, malleable?:boolean) {
        this.setGenerator(generator)
        this._malleable = !!malleable
        this.__prime = new BN(prime)
        this._primeLen = prime.length
        this._pub = undefined
        this._priv = undefined
        this._primeCode = undefined
        if (malleable) {
            this._malleable = true
            // this.setPublicKey = setPublicKey
            // this.setPrivateKey = setPrivateKey
        } else {
            this._primeCode = 8
            this._malleable = false
        }
    }

    computeSecret (other:BN):Uint8Array {
        other = new BN(other)
        other = other.toRed(this._prime)
        const secret = other.redPow(this._priv).fromRed()
        // let out = new Buffer(secret.toArray())
        let out = new Uint8Array(secret.toArray())
        const prime = this.getPrime()
        if (out.length < prime.length) {
            // const front = new Buffer(prime.length - out.length)
            const front = new Uint8Array(prime.length - out.length)
            front.fill(0)
            // out = Buffer.concat([front, out])
            out = concat([front, out])
            // out = Buffer.concat([front, out])
        }

        return out
    }

    getPrime (enc?:SupportedEncodings) {
        return formatReturnValue(this.__prime, enc)
    }

    getPublicKey (enc?:SupportedEncodings) {
        return formatReturnValue(this._pub, enc)
    }

    getPrivateKey (enc?:SupportedEncodings) {
        return formatReturnValue(this._priv, enc)
    }

    generateKeys () {
        if (!this._priv) {
            this._priv = new BN(randomBytes(this._primeLen))
        }
        this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed()
        return this.getPublicKey()
    }

    setPublicKey (pub:Uint8Array|string, enc?:SupportedEncodings) {
        if (!this._malleable) throw new Error('not malleable')
        enc = enc || 'utf8'
        if (!(pub instanceof Uint8Array)) {
            pub = fromString(pub, enc)
        }
        this._pub = new BN(pub)

        return this
    }

    setPrivateKey (priv:string|Uint8Array, enc) {
        if (!this._malleable) throw new Error('not malleable')
        enc = enc || 'utf8'
        if (!(priv instanceof Uint8Array)) {
            priv = fromString(priv, enc)
        }
        this._priv = new BN(priv)

        return this
    }

    setGenerator (gen:Uint8Array|string, enc?:SupportedEncodings) {
        enc = enc || 'utf8'
        if (!(gen instanceof Uint8Array)) {
            gen = fromString(gen, enc)
        }
        this.__gen = gen
        this._gen = new BN(gen)
        return this
    }

    getGenerator (enc?:SupportedEncodings) {
        return formatReturnValue(this._gen, enc)
    }
}

Object.defineProperty(DH.prototype, 'verifyError', {
    enumerable: true,
    get: function () {
        if (typeof this._primeCode !== 'number') {
            this._primeCode = checkPrime(this.__prime, this.__gen)
        }
        return this._primeCode
    }
})

// export function oldDH (prime, generator, malleable) {
//     this.setGenerator(generator)
//     this.__prime = new BN(prime)
//     this._prime = BN.mont(this.__prime)
//     this._primeLen = prime.length
//     this._pub = undefined
//     this._priv = undefined
//     this._primeCode = undefined
//     if (malleable) {
//         this.setPublicKey = setPublicKey
//         this.setPrivateKey = setPrivateKey
//     } else {
//         this._primeCode = 8
//     }
// }

// DH.prototype.generateKeys = function () {
//     if (!this._priv) {
//         this._priv = new BN(randomBytes(this._primeLen))
//     }
//     this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed()
//     return this.getPublicKey()
// }

// DH.prototype.computeSecret = function (other) {
//     other = new BN(other)
//     other = other.toRed(this._prime)
//     const secret = other.redPow(this._priv).fromRed()
//     let out = new Buffer(secret.toArray())
//     const prime = this.getPrime()
//     if (out.length < prime.length) {
//         const front = new Buffer(prime.length - out.length)
//         front.fill(0)
//         out = Buffer.concat([front, out])
//     }
//     return out
// }

// DH.prototype.getPublicKey = function getPublicKey (enc) {
//     return formatReturnValue(this._pub, enc)
// }

// DH.prototype.getPrivateKey = function getPrivateKey (enc) {
//     return formatReturnValue(this._priv, enc)
// }

// DH.prototype.getPrime = function (enc) {
//     return formatReturnValue(this.__prime, enc)
// }

// DH.prototype.getGenerator = function (enc) {
//     return formatReturnValue(this._gen, enc)
// }

// DH.prototype.setGenerator = function (gen, enc) {
//     enc = enc || 'utf8'
//     if (!Buffer.isBuffer(gen)) {
//         gen = new Buffer(gen, enc)
//     }
//     this.__gen = gen
//     this._gen = new BN(gen)
//     return this
// }

function formatReturnValue (bn:BN, enc?:SupportedEncodings) {
    const buf = new Uint8Array(bn.toArray())
    if (!enc) {
        return buf
    } else {
        return toString(buf, enc)
    }
}

const primeCache = {}
function checkPrime (prime, generator) {
    const gen = generator.toString('hex')
    const hex = [gen, prime.toString(16)].join('_')
    if (hex in primeCache) {
        return primeCache[hex]
    }
    let error = 0

    if (prime.isEven() ||
    !primes.simpleSieve ||
    !primes.fermatTest(prime) ||
    !millerRabin.test(prime)) {
    // not a prime so +1
        error += 1

        if (gen === '02' || gen === '05') {
            // we'd be able to check the generator
            // it would fail so +8
            error += 8
        } else {
            // we wouldn't be able to test the generator
            // so +4
            error += 4
        }
        primeCache[hex] = error
        return error
    }
    if (!millerRabin.test(prime.shrn(1))) {
    // not a safe prime
        error += 2
    }
    let rem
    switch (gen) {
        case '02':
            if (prime.mod(TWENTYFOUR).cmp(ELEVEN)) {
                // unsuidable generator
                error += 8
            }
            break
        case '05':
            rem = prime.mod(TEN)
            if (rem.cmp(THREE) && rem.cmp(SEVEN)) {
                // prime mod 10 needs to equal 3 or 7
                error += 8
            }
            break
        default:
            error += 4
    }
    primeCache[hex] = error
    return error
}
