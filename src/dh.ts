import MillerRabin from 'miller-rabin'
import BN from './bn.js'
import primes from './generate-prime.js'

const millerRabin = new MillerRabin()
const TWENTYFOUR = new BN(24)
const ELEVEN = new BN(11)
const TEN = new BN(10)
const THREE = new BN(3)
const SEVEN = new BN(7)
module.exports = DH

function setPublicKey (pub, enc) {
    enc = enc || 'utf8'
    if (!Buffer.isBuffer(pub)) {
        pub = new Buffer(pub, enc)
    }
    this._pub = new BN(pub)
    return this
}

function setPrivateKey (priv, enc) {
    enc = enc || 'utf8'
    if (!Buffer.isBuffer(priv)) {
        priv = new Buffer(priv, enc)
    }
    this._priv = new BN(priv)
    return this
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

export function DH (prime, generator, malleable) {
    this.setGenerator(generator)
    this.__prime = new BN(prime)
    this._prime = BN.mont(this.__prime)
    this._primeLen = prime.length
    this._pub = undefined
    this._priv = undefined
    this._primeCode = undefined
    if (malleable) {
        this.setPublicKey = setPublicKey
        this.setPrivateKey = setPrivateKey
    } else {
        this._primeCode = 8
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
DH.prototype.generateKeys = function () {
    if (!this._priv) {
        this._priv = new BN(randomBytes(this._primeLen))
    }
    this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed()
    return this.getPublicKey()
}

DH.prototype.computeSecret = function (other) {
    other = new BN(other)
    other = other.toRed(this._prime)
    const secret = other.redPow(this._priv).fromRed()
    let out = new Buffer(secret.toArray())
    const prime = this.getPrime()
    if (out.length < prime.length) {
        const front = new Buffer(prime.length - out.length)
        front.fill(0)
        out = Buffer.concat([front, out])
    }
    return out
}

DH.prototype.getPublicKey = function getPublicKey (enc) {
    return formatReturnValue(this._pub, enc)
}

DH.prototype.getPrivateKey = function getPrivateKey (enc) {
    return formatReturnValue(this._priv, enc)
}

DH.prototype.getPrime = function (enc) {
    return formatReturnValue(this.__prime, enc)
}

DH.prototype.getGenerator = function (enc) {
    return formatReturnValue(this._gen, enc)
}

DH.prototype.setGenerator = function (gen, enc) {
    enc = enc || 'utf8'
    if (!Buffer.isBuffer(gen)) {
        gen = new Buffer(gen, enc)
    }
    this.__gen = gen
    this._gen = new BN(gen)
    return this
}

function formatReturnValue (bn, enc) {
    const buf = new Buffer(bn.toArray())
    if (!enc) {
        return buf
    } else {
        return buf.toString(enc)
    }
}
