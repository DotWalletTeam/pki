const asn1js = require('asn1js')
const bsv = require('bsv')

function privkey2BER(privkey){
    var priv = new Uint8Array(bsv.PrivateKey(privkey).toBuffer()).buffer
    var pub = new Uint8Array(bsv.PrivateKey(privkey).publicKey.toBuffer()).buffer
    var ber = new asn1js.Sequence({
        value: [
            new asn1js.Integer({ value: 1}),
            new asn1js.OctetString({ valueHex: priv }),
            new asn1js.Constructed({
                optional: true,
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 0 // [0]
                },
                value: [
                    new asn1js.ObjectIdentifier({ value: "1.3.132.0.10"})
                ]
            }),
            new asn1js.Constructed({
                optional: true,
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 1 // [0]
                },
                value: [
                    new asn1js.BitString({ valueHex: pub })
                ]
            })
        ]
    })
    return Buffer.from(ber.toBER())
}
function BER2Privkey(berBuffer){
    var ber = asn1js.fromBER(new Uint8Array(berBuffer).buffer).result
    var keyInfo = {
        version: ber.valueBlock.value[0].valueBlock.valueDec,
        privkey: Buffer.from(ber.valueBlock.value[1].valueBlock.valueHex),
        curve: ber.valueBlock.value[2].valueBlock.value[0].valueBlock.value.map(sid=>sid.valueDec).join("."),
        pubkey: Buffer.from(ber.valueBlock.value[3].valueBlock.value[0].valueBlock.valueHex)
    }
    return keyInfo.privkey
}

module.exports = {
    privkey2BER: privkey2BER,
    BER2Privkey: BER2Privkey
}
