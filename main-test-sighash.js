const fs = require('fs')
const bitcoin = require('bitcoinjs-lib');
const ordinalsBitcoinjs = require('./src/ordinals-bitcoinjs')

const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32')
const bip32 = BIP32Factory(ecc)
const bip39 = require('bip39');
bitcoin.initEccLib(ecc);

const indexSighashMap = {
    100: bitcoin.Transaction.SIGHASH_ALL,
    101: bitcoin.Transaction.SIGHASH_NONE,
    102: bitcoin.Transaction.SIGHASH_SINGLE,
    103: bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
    104: bitcoin.Transaction.SIGHASH_NONE | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
    105: bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
}

const {
    toXOnly,
} = ordinalsBitcoinjs

const mnemonic = `gauge hole clog property soccer idea cycle stadium utility slice hold chief`;
const seed = bip39.mnemonicToSeedSync(mnemonic);
const root = bip32.fromSeed(seed);

function p2pkh() {
    // log the function name
    console.log("==> ", arguments.callee.name);

    // 44'
    // raw have 6 outpus, use outputs as sighash test
    // m/44'/0'/0'/0/0 -> {
    //   m/44'/0'/0'/0/100 : 14000
    //   m/44'/0'/0'/0/101 : 14000
    //   m/44'/0'/0'/0/102 : 14000
    //   m/44'/0'/0'/0/103 : 14000
    //   m/44'/0'/0'/0/104 : 14000
    //   m/44'/0'/0'/0/105 : 14000
    // }
    const raw = "0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a47304402202f82a2c717c4990c0e43284011623043128418ff9f0737bed07fc0dbdb2f893602206d42cec375b3eedb5386c67417479280b1a37fa2a3c38ee64269123a3e4aefbc012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff06b0360000000000001976a9141fe50bd1fc738e82759b2b4cef9d8b97b205d9cd88acb0360000000000001976a914c5decc5a89320501ef0ccf149ac152269d98f0b488acb0360000000000001976a9144b146227dc09f72bdb8374d73c01180b2c949e6f88acb0360000000000001976a914312bb886c92daa0f6a632baa0b99ba72da1a433188acb0360000000000001976a91454a1df0b9e25dd8246a093f84173ed2353e5cc9d88acb0360000000000001976a914f4a68b936d7f5fb61be98b74643c007bad5664d188ac00000000"
    const tx = bitcoin.Transaction.fromHex(raw)
    const utxo = Buffer.from(raw, 'hex')
    const psbt = new bitcoin.Psbt();

    // for index 100..105 do add psbt.addInput
    for (let index = 0; index < 6; index++) {
        let path = `m/44'/0'/0'/0/${100 + index}`
        let pk = root.derivePath(path).publicKey
        psbt.addInput({
            hash: tx.getId(),
            index: index,
            nonWitnessUtxo: utxo,
            sighashType: indexSighashMap[100 + index],
            bip32Derivation: [
                {
                    masterFingerprint: Buffer.from('f1c149f5', 'hex'),
                    pubkey: pk,
                    path: path,
                },
            ],
        })
    }

    // add 6 outputs, each with 10000 satoshis, address is driven from xpub with index 200..205
    for (let index = 0; index < 6; index++) {
        let path = `m/44'/0'/0'/0/${200 + index}`
        let pk = root.derivePath(path).publicKey
        let address = bitcoin.payments.p2pkh({ pubkey: pk }).address
        psbt.addOutput({
            address: address,
            value: 10000
        })
    }

    // log the psbt as base64
    console.log(psbt.toBase64())

    // write the psbt to file
    fs.writeFileSync(`sighash-${arguments.callee.name}.psbt`, psbt.toBase64())
}

function p2wpkh() {
    // log the function name
    console.log("==> ", arguments.callee.name);

    // 84'
    // raw have 6 outpus, use outputs as sighash test
    // m/84'/0'/0'/0/0 -> {
    //   m/84'/0'/0'/0/100 : 14000
    //   m/84'/0'/0'/0/101 : 14000
    //   m/84'/0'/0'/0/102 : 14000
    //   m/84'/0'/0'/0/103 : 14000
    //   m/84'/0'/0'/0/104 : 14000
    //   m/84'/0'/0'/0/105 : 14000
    // }
    const raw = "020000000001011193147e0f5d3b0f76c2af5049adae7034bdf9761c302f8298f616a2d8dfe6200000000000fdffffff06b036000000000000160014cac7e65c4b3758b6107816a611ea0e726f9a9cb7b036000000000000160014a4f495943fbbc5e56ab1793750a9b8c99b4853d6b036000000000000160014b651e4a2f59e7888af78ad8a4924e2acb8527478b036000000000000160014d27cd953b386546ffc9c0e92c235072f4d0b56aab036000000000000160014880b51e0ec35e4b44c420b5ebc406def5819a849b036000000000000160014a1fde0c53f641f0be8845490c35f17ad1979d17e02483045022100e5681ddd79faa1ad3af4c9ea08587c5efd2c96064c23128018a27f6a8c7061a9022057c42cc435d96052e58fa412a20ac63b3f35d1cf1ace641c6ecd814dcb97fef20121021bacf967f39cce551b990e7e5c2beb9888e4df8dc086b476bc831fc57e69679700000000"
    const tx = bitcoin.Transaction.fromHex(raw)
    const utxo = Buffer.from(raw, 'hex')

    const psbt = new bitcoin.Psbt();

    // for index 100..105 do add psbt.addInput
    for (let index = 0; index < 6; index++) {
        let path = `m/84'/0'/0'/0/${100 + index}`
        let pk = root.derivePath(path).publicKey
        const script = bitcoin.payments.p2wpkh({ pubkey: pk }).output
        psbt.addInput({
            hash: tx.getId(),
            index: index,
            nonWitnessUtxo: utxo,
            witnessUtxo: {
                script: script,
                value: 14000,
            },
            sighashType: indexSighashMap[100 + index],
            bip32Derivation: [
                {
                    masterFingerprint: Buffer.from('f1c149f5', 'hex'),
                    pubkey: pk,
                    path: path,
                },
            ],
        })
    }

    // add 6 outputs, each with 10000 satoshis, address is driven from xpub with index 200..205
    for (let index = 0; index < 6; index++) {
        let path = `m/84'/0'/0'/0/${200 + index}`
        let pk = root.derivePath(path).publicKey
        let address = bitcoin.payments.p2wpkh({ pubkey: pk}).address
        psbt.addOutput({
            address: address,
            value: 10000
        })
    }

    // log the psbt as base64
    console.log(psbt.toBase64())

    // write the psbt to file
    fs.writeFileSync(`sighash-${arguments.callee.name}.psbt`, psbt.toBase64())
}

function p2tr() {
    // log the function name
    console.log("==> ", arguments.callee.name);

    // 86'
    // raw have 6 outpus, use outputs as sighash test
    // m/86'/0'/0'/0/0 -> {
    //   m/86'/0'/0'/0/100 : 14000
    //   m/86'/0'/0'/0/101 : 14000
    //   m/86'/0'/0'/0/102 : 14000
    //   m/86'/0'/0'/0/103 : 14000
    //   m/86'/0'/0'/0/104 : 14000
    //   m/86'/0'/0'/0/105 : 14000
    // }

    const raw = "020000000001018c852203ea78d270258f244638cad258cb37ffd1e6bb2c1fbe02565bccd089d20000000000fdffffff06b0360000000000002251203040a42417d449eb4d960907890f796e3b308943fb34fd74f5c5eb2f5145fdf4b0360000000000002251201d3d453b8e83b1dafff2d0ebf415c3e8201a98d5be129f5bc24fcbdada3f577ab03600000000000022512072075e0dfedb89c62fa006a57b802280c300da196ce60b03e7771790ee52fda6b0360000000000002251200e9c7a6c1e07ff21906d7f45cfc2981cc7f76d938cd0bb0e9ea0b9076fb65161b0360000000000002251209a27c6b4b3340ee3e1397198ac9569198270aa91c1fb087e3675ce9a8c016a1ab0360000000000002251200c18102da4bf9136e2d1749bf01810afecad7eb26816c97b635176ef661cce7b0140df3bce14335f33806ee3e27bba26ed2b741ceb16ebe367b50e7560c2fb7be6a26874cee482df216128c9eff6a5720b410cc32f95ba556692b795b170c7e4621400000000"
    const tx = bitcoin.Transaction.fromHex(raw)

    const psbt = new bitcoin.Psbt();
    const tweakHash = (pk, h) => bitcoin.crypto.taggedHash('TapTweak', Buffer.concat(h ? [pk, h] : [pk]))
    // for index 100..105 do add psbt.addInput
    for (let index = 0; index < 6; index++) {
        let path = `m/86'/0'/0'/0/${100 + index}`
        let internal = root.derivePath(path)
        let pk = internal.publicKey
        // tweak 
        out = internal.tweak(tweakHash(toXOnly(pk)))
        // const payment = bitcoin.payments.p2tr({ pubkey: toXOnly(out.publicKey) })
        // console.log(`address ${path} :`, payment.address)
        const script = bitcoin.payments.p2tr({ pubkey: toXOnly(out.publicKey) }).output
        console.log("script: ", script.toString('hex'))
        psbt.addInput({
            hash: tx.getId(),
            index: index,
            witnessUtxo: {
                script: script,
                value: 14000,
            },
            sighashType: indexSighashMap[100 + index],
            tapBip32Derivation: [
                {
                    masterFingerprint: Buffer.from('f1c149f5', 'hex'),
                    pubkey: toXOnly(pk),
                    path: path,
                    leafHashes: []
                },
            ],
            tapInternalKey: toXOnly(pk),
        })
    }

    // add 6 outputs, each with 10000 satoshis, address is driven from xpub with index 200..205
    for (let index = 0; index < 6; index++) {
        let path = `m/86'/0'/0'/0/${200 + index}`
        let internal = root.derivePath(path)
        let pk = internal.publicKey
        // tweak 
        out = internal.tweak(tweakHash(toXOnly(pk)))
        const payment = bitcoin.payments.p2tr({ pubkey: toXOnly(out.publicKey) })
        // console.log(`address ${path} :`, payment.address)
        let address = payment.address
    
        psbt.addOutput({
            address: address,
            value: 10000
        })
    }

    console.log(psbt.toBase64())

    fs.writeFileSync(`sighash-${arguments.callee.name}.psbt`, psbt.toBase64())
}

function p2wpkh_p2sh() {
    // log the function name
    console.log("==> ", arguments.callee.name);

    // 49'
    // raw have 6 outpus, use outputs as sighash test
    // m/49'/0'/0'/0/0 -> {
    //   m/49'/0'/0'/0/100 : 14000
    //   m/49'/0'/0'/0/101 : 14000
    //   m/49'/0'/0'/0/102 : 14000
    //   m/49'/0'/0'/0/103 : 14000
    //   m/49'/0'/0'/0/104 : 14000
    //   m/49'/0'/0'/0/105 : 14000
    // }

    const raw = "020000000001012d46dcc257124b566cb80d398dba5c6a226a80fbdb6de6b472a2b4fab48d37e50000000017160014f1520cdd5eea13ff0b22df67dbeae1f86b509a81fdffffff06b03600000000000017a9146bd4bf42904f33ae3aabb2204408e89cc253784c87b03600000000000017a9149b1b73c2b7050962fcb54999881ee1d8b6b2258c87b03600000000000017a914e0b6889347fea0034fe67dfd05091c082d4ac4cf87b03600000000000017a914bbb5d766765b799ca9736cba63dc549814cf20d987b03600000000000017a9149e40e5b99a7fde82ce6d21e4247aec55dd48c37a87b03600000000000017a9147dbe3048c24ba3094843757212a0192c8818403187024730440220609bc634bbc54e187bcff5c14002ac1d0f41d25e1af4483f6ca169ce7289eb61022001839101437a03ccaeff616e0534822fd6f87aadc9a77b6e9a6ee3e7f39d39080121027a28d603ddcbc769f96a1db223da0190c5808c7a1b74e67eeb44b463c33b71a200000000"
    const tx = bitcoin.Transaction.fromHex(raw)

    // log tx.getId()
    // console.log(tx.getId())
    const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

    // for index 100..105 do add psbt.addInput
    for (let index = 0; index < 6; index++) {
        let path = `m/49'/0'/0'/0/${100 + index}`
        let pk = root.derivePath(path).publicKey
        // get the redeem script
        const script = bitcoin.payments.p2sh({
            redeem: bitcoin.payments.p2wpkh({ pubkey: pk })
        }).redeem.output

        console.log("redeem script: ", script.toString('hex'))
        psbt.addInput({
            hash: tx.getId(),
            index: index,
            nonWitnessUtxo: Buffer.from(raw, 'hex'),
            redeemScript: script,
            sighashType: indexSighashMap[100 + index],
            bip32Derivation: [
                {
                    masterFingerprint: Buffer.from('f1c149f5', 'hex'),
                    pubkey: pk,
                    path: path,
                },
            ],
        })
    }

    // add 6 outputs, each with 10000 satoshis, address is driven from xpub with index 200..205
    for (let index = 0; index < 6; index++) {
        let path = `m/49'/0'/0'/0/${200 + index}`
        let address = bitcoin.payments.p2sh({
            redeem: bitcoin.payments.p2wpkh({ pubkey: root.derivePath(path).publicKey })
        }).address
        psbt.addOutput({
            address: address,
            value: 10000
        })
    }

    console.log(psbt.toBase64())

    fs.writeFileSync(`sighash-${arguments.callee.name}.psbt`, psbt.toBase64())
}

function xxxx() {
    const raw = "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"
    const psbt = bitcoin.Psbt.fromBase64(raw)
    const tx = psbt.extractTransaction()
    console.log(tx.toHex())
}

p2pkh()
p2wpkh()
p2tr()
p2wpkh_p2sh()
xxxx()