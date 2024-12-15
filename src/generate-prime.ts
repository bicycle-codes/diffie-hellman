import { randomBytes } from '@bicycle-codes/randombytes'
import BN from 'bn.js'
import MillerRabin from 'miller-rabin'
const TWENTYFOUR = new BN(24)
const millerRabin = new MillerRabin()
const ONE = new BN(1)
const TWO = new BN(2)
const FIVE = new BN(5)
const TEN = new BN(10)
const THREE = new BN(3)
const ELEVEN = new BN(11)
const FOUR = new BN(4)

let primes:number[]|null = null

findPrime.simpleSieve = simpleSieve
findPrime.fermatTest = fermatTest

function _getPrimes () {
    if (primes !== null) {
        return primes
    }

    const limit = 0x100000
    const res:number[] = []
    res[0] = 2
    for (let i = 1, k = 3; k < limit; k += 2) {
        const sqrt = Math.ceil(Math.sqrt(k))
        // eslint-disable-next-line no-var
        for (var j = 0; j < i && res[j] <= sqrt; j++) {
            if (k % res[j] === 0) { break }
        }

        if (i !== j && res[j] <= sqrt) { continue }

        res[i++] = k
    }

    primes = res
    return res
}

function simpleSieve (p) {
    const primes = _getPrimes()

    for (let i = 0; i < primes.length; i++) {
        if (p.modn(primes[i]) === 0) {
            if (p.cmpn(primes[i]) === 0) {
                return true
            } else {
                return false
            }
        }
    }

    return true
}

function fermatTest (p) {
    const red = BN.mont(p)
    return TWO.toRed(red).redPow(p.subn(1)).fromRed().cmpn(1) === 0
}

export function findPrime (bits, gen) {
    if (bits < 16) {
    // this is what openssl does
        if (gen === 2 || gen === 5) {
            return new BN([0x8c, 0x7b])
        } else {
            return new BN([0x8c, 0x27])
        }
    }
    gen = new BN(gen)

    let num, n2

    while (true) {
        num = new BN(randomBytes(Math.ceil(bits / 8)))
        while (num.bitLength() > bits) {
            num.ishrn(1)
        }
        if (num.isEven()) {
            num.iadd(ONE)
        }
        if (!num.testn(1)) {
            num.iadd(TWO)
        }
        if (!gen.cmp(TWO)) {
            while (num.mod(TWENTYFOUR).cmp(ELEVEN)) {
                num.iadd(FOUR)
            }
        } else if (!gen.cmp(FIVE)) {
            while (num.mod(TEN).cmp(THREE)) {
                num.iadd(FOUR)
            }
        }
        n2 = num.shrn(1)
        if (simpleSieve(n2) && simpleSieve(num) &&
      fermatTest(n2) && fermatTest(num) &&
      millerRabin.test(n2) && millerRabin.test(num)) {
            return num
        }
    }
}

export default findPrime
