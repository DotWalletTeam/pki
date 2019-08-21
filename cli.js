const bsv = require('bsv')
const fs = require('fs')
const keyUtil = require('./keyUtil.js')

var program = require('commander')

program
    .command('key2pem')
    .description('warp bitcoin privkey into a pem file\r\n e.g: bitpki key2pem -key [privkey] -out keyfile.pem')
    .action(key2pem)

program
    .command('pem2key')
    .description('unwarp bitcoin privkey from pem file\r\n e.g: bitpki pem2key -in keyfile.pem')
    .action(pem2key)


program
    //.version(require('./package.json').version)
    .option('-i, --in [file]', 'file in')
    .option('-o, --out [file]', 'file out')
    .option('-k, --key [private key]', 'private key')

function key2pem(){
    var privkey = bsv.PrivateKey(program.key)
    var ber = keyUtil.privkey2BER(privkey)
    var base64 = ber.toString('base64')
    // 增加换行
    var base64n = []
    while(base64.length>0){
        base64n.push(base64.slice(0,64))
        base64 = base64.slice(64)
    }
    fs.writeFileSync(program.out,`-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\n${base64n.join("\n")}\n-----END EC PRIVATE KEY-----\n`)
}
function pem2key(){
    var file = fs.readFileSync(program.in).toString()
    var ber = file.split("-----BEGIN EC PRIVATE KEY-----")[1].split("-----END EC PRIVATE KEY-----")[0]
    var key = keyUtil.BER2Privkey(Buffer.from(ber, 'base64'))
    console.log(bsv.PrivateKey.fromBuffer(key).toString())
}

program.parse(process.argv)
