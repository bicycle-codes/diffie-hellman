import { DH } from './dh.js'
const generatePrime = require('./lib/generatePrime')
const primes = require('./lib/primes.json')

export function DiffieHellmanGroup (mod) {
    const prime = new Buffer(primes[mod].prime, 'hex')
    const gen = new Buffer(primes[mod].gen, 'hex')

    return new DH(prime, gen)
}

const ENCODINGS = {
    binary: true, hex: true, base64: true
}

export function createDiffieHellman (prime, enc, generator, genc) {
    if (Buffer.isBuffer(enc) || ENCODINGS[enc] === undefined) {
        return createDiffieHellman(prime, 'binary', enc, generator)
    }

    enc = enc || 'binary'
    genc = genc || 'binary'
    generator = generator || new Buffer([2])

    if (!Buffer.isBuffer(generator)) {
        generator = new Buffer(generator, genc)
    }

    if (typeof prime === 'number') {
        return new DH(generatePrime(prime, generator), generator, true)
    }

    if (!Buffer.isBuffer(prime)) {
        prime = new Buffer(prime, enc)
    }

    return new DH(prime, generator, true)
}
