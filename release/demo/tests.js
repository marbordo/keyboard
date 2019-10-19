if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
    global.KeyouCryptography = require('../build/keyou-crypto-min.js');
    global.expect = require('./chai.js').expect;    
} else {
    window.expect = chai.expect
}

describe('校验接口测试', function () {
    var Checker = KeyouCryptography.util.Checker;

    it('#checkOnlyPrintChar 正常用例：校验字符串仅包含可打印字符', function () {
        var str = 'zxxxxAAAA456545678$%^&*(,./';
        var ret = Checker.checkOnlyPrintChar(str);
        expect(ret).to.be.true;
    })

    it('#checkOnlyPrintChar 异常用例：校验字符串包含中文', function () {
        var str = 'dasdasdas，。、、';
        var ret = Checker.checkOnlyPrintChar(str);
        expect(ret).to.be.false;
    })

    it('#checkHasChinese 正常用例：包含中文的字符串', function () {
        var str = 'dasda中dasdas';
        var ret = Checker.checkHasChinese(str);
        expect(ret).to.be.true;

        var str = 'sdasdas，。、、sdasd';
        var ret = Checker.checkHasChinese(str);
        expect(ret).to.be.true;
    })

    it('#checkHasChinese 异常用例：不包含中文的字符串', function () {
        var str = 'dasdasdasdas';
        var ret = Checker.checkHasChinese(str);
        expect(ret).to.be.false;
    })
});
describe('辅助接口测试', function () {
    var Helper = KeyouCryptography.util.Helper;

    it('ASC 字符串转字节数组：正常用例', function () {
        var ascstr = "0123456789";
        var arr = Helper.ascstr2array(ascstr);
        var test = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39];
        expect(arr.toString()).to.be.equal(test.toString());
    })

    it('ASC 字符串转字节数组：数据为空', function () {
        var ascstr = '';
        var arr = Helper.ascstr2array(ascstr);
        var test = [];
        expect(arr.toString()).to.be.equal(test.toString());
    })

    it('字节数组转 ASC 字符串：正常用例', function () {
        var arr = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39];
        var str = Helper.array2ascstr(arr);
        expect(str).to.be.equal('0123456789');
    })

    it('字节数组转 ASC 字符串：数据为空', function () {
        var arr = [];
        var str = Helper.array2ascstr(arr);
        expect(str).to.be.equal('');
    })

    it ('byte 数组和 int 数组转换接口测试', function () {
        var bytes = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        var integers = [0x31323334, 0x35363738];
        expect(Helper.bytes2integers(bytes).toString()).to.be.equal(integers.toString());
        expect(Helper.integers2bytes(integers).toString()).to.be.equal(bytes.toString());

        var bytes2 = [0x35, 0x36, 0x37, 0x38];
        var integers2 = [0x35363738];
        expect(Helper.bytes2integers(bytes, 4).toString()).to.be.equal(integers2.toString());
        expect(Helper.integers2bytes(integers, 1).toString()).to.be.equal(bytes2.toString());        
    })

    it ('Hex 和 Base64 相互转换', function () {
        var hex = '31323334353637383930414243444546';
        var base64 = 'MTIzNDU2Nzg5MEFCQ0RFRg==';

        expect(Helper.hex2b64(hex)).to.be.equal(base64);
        expect(Helper.b64tohex(base64)).to.be.equal(hex);
    })

    it ('asc 和 Base64 相互转换', function () {
        var asc = '1234567890123456';
        var base64 = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

        expect(Helper.asctob64(asc)).to.be.equal(base64);
        expect(Helper.b64toasc(base64)).to.be.equal(asc);
    })

});


    describe("数据填充接口测试", function () {
    var Hex = KeyouCryptography.util.Hex;
    var DataPadding = KeyouCryptography.util.DataPadding;
    var Helper = KeyouCryptography.util.Helper;

    it('PKCS#5（PKCS#7）填充和去填充数据：正常用例', function () {
        var data = Helper.ascstr2array('1234567890');
        var endata = DataPadding.encodeWithPKCS5(data, 16);
        var test = '31323334353637383930060606060606';
        expect(Hex.stringify(endata)).to.be.equal(test);
        var dedata = DataPadding.decodeWithPKCS5(endata);
        expect(data.toString()).to.be.equal(dedata.toString());
    })

    it('PKCS#5（PKCS#7）填充和去填充数据：数据为空', function () {
        var data = Helper.ascstr2array('');
        var endata = DataPadding.encodeWithPKCS5(data, 16);
        var test = '10101010101010101010101010101010';
        expect(Hex.stringify(endata)).to.be.equal(test);
        var dedata = DataPadding.decodeWithPKCS5(endata);
        expect(data.toString()).to.be.equal(dedata.toString());
    })

    it('PKCS#5（PKCS#7）填充和去填充数据：数据长度等于数据块大小', function () {
        var data = Helper.ascstr2array('1234567890ABCDEF');
        var endata = DataPadding.encodeWithPKCS5(data, 16);
        var test = '3132333435363738393041424344454610101010101010101010101010101010';
        expect(Hex.stringify(endata)).to.be.equal(test);
        var dedata = DataPadding.decodeWithPKCS5(endata);
        expect(data.toString()).to.be.equal(dedata.toString());
    })
});



    describe('密码填充接口测试', function () {
    var PinPadding = KeyouCryptography.util.PinPadding;
    var Helper = KeyouCryptography.util.Helper;

    it('国际算法交易密码固定填充', function () {
        var pin = '123456';
        var ppin = PinPadding.padWithMode1(pin);
        var test = [0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff, 0xff];
        expect(ppin.toString()).to.be.equal(test.toString());
    })

    it('国密算法交易密码和登录密码固定填充', function () {
        var pin = '1234567890ABCD';
        var ppin = PinPadding.padWithMode2(pin);
        var test = '0E1234567890ABCDFFFFFFFFFFFFFFFF';
        expect(Helper.array2ascstr(ppin)).to.be.equal(test);
    })

    it('国际算法登录密码固定填充', function () {
        var pin = '212121asda';
        var ppin = PinPadding.padWithMode3(pin);
        var test = '212121asdaFFFFFF';
        expect(Helper.array2ascstr(ppin)).to.be.equal(test);
    })

    it('国际算法交易密码异或填充', function () {
        var pin = '123456';
        var ppin = PinPadding.padWithXOR(pin);
        var test = '';
        for (var i = 0, len = pin.length; i < len; i++) {
            test += String.fromCharCode(ppin[i + 2 + len] ^ ppin[i + 2]);
        }
        expect(pin).to.be.equal(test);
    })
});     



    
describe('SM2 算法测试', function () {
    var SM2 = KeyouCryptography.algorithm.SM2;
    var Hex = KeyouCryptography.util.Hex;

    it('SM2 生成对称密钥', function () {
        var keypair = SM2.generate();
        expect(keypair.publicKey).to.be.exist;
        expect(keypair.publicKey.length).to.be.equal(64);
        expect(keypair.privateKey).to.be.exist;
        expect(keypair.privateKey.length).to.be.equal(32);
        // console.log('PK: ' + Hex.stringify(keypair.publicKey));
        // console.log('VK: ' + Hex.stringify(keypair.privateKey));
    })

    it('SM2 加解密正常用例', function () {
        var plaintext = Hex.parse("313233343536");
        var publicKey = Hex.parse(SM2.testKeypair.publicKey);
        var ciphertext = SM2.encrypt(plaintext, publicKey);
        expect(ciphertext.length).to.be.equal(96 + plaintext.length);
        var privateKey = Hex.parse(SM2.testKeypair.privateKey);
        var data = SM2.decrypt(ciphertext, privateKey).toString();
        expect(SM2.decrypt(ciphertext, privateKey).toString()).to.be.equal(plaintext.toString());
    });

    it('SM2 加密异常用例：数据为空，抛出 TypeError', function () {
        var publicKey = Hex.parse(SM2.testKeypair.publicKey);
        var error = function() {
            SM2.encrypt(new Array(0), publicKey)
        }
        expect(error).to.throw(TypeError, /empty/); 
    });

    it('SM2 加密异常用例：数据为 null，抛出 TypeError', function () {
        var publicKey = Hex.parse(SM2.testKeypair.publicKey);
        var error = function() {
            SM2.encrypt(null, publicKey)
        }
        expect(error).to.throw(TypeError, /empty/);       
    }); 

    it('SM2 加密异常用例：数据 undefined，抛出 Error', function () {
        var publicKey = Hex.parse(SM2.testKeypair.publicKey);
        var error = function() {
            SM2.encrypt(undefined, publicKey)
        }
        expect(error).to.throw(Error);       
    });     

});



    describe('SM3 算法测试', function () {
    var Hex = KeyouCryptography.util.Hex;
    var SM3 = KeyouCryptography.algorithm.SM3;
    var Helper = KeyouCryptography.util.Helper;

    it('SM3 计算数据摘要值：正常用例', function () {
        var data = "1234567890ABCDEF48DF4ED36CB9B740BBBA932935864C41DB16B08DB953AFBAAD110C2C4116DE8D";
        var hash = SM3.digest(Hex.parse(data));
        expect(Hex.stringify(hash)).to.be.equal('4A97150E5F3542B15CAB534100EE1047AF78C1F8A5881ED4EA7D95D72265A31E');
    })

   it('SM3 计算数据摘要值：数据为空', function () {
        var data = [];
        var hash = SM3.digest(data);
        expect(Hex.stringify(hash)).to.be.equal('1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B');
    })

    it('SM3 计算 HMAC：正常用例', function () {
        var data = Helper.ascstr2array("123456789012345648DF4ED36CB9B740BBBA932935864C41DB16B08DB953AFBAAD110C2C4116DE8D");
        var key = Helper.ascstr2array('48DF4ED36CB9B740BBBA932935864C41DB16B08DB953AFBAAD110C2C4116DE8D');
        var hmac = SM3.hmac(key, data);
        expect(Hex.stringify(hmac)).to.be.equal('8AFA88EF84392AC026FE7F739FD216B792EF73A2279F5DEB9686DBFA4E600434');
    })

    it('SM3 计算 HMAC：数据为空', function () {
        var data = [];
        var key = [];
        var hmac = SM3.hmac(key, data);
        expect(Hex.stringify(hmac)).to.be.equal('0D23F72BA15E9C189A879AEFC70996B06091DE6E64D31B7A84004356DD915261');
    })

    
});



    describe('SM4 算法测试', function () {
    var SM4 = KeyouCryptography.algorithm.SM4;
    var Hex = KeyouCryptography.util.Hex;
    var Helper = KeyouCryptography.util.Helper;
    var DataPadding = KeyouCryptography.util.DataPadding;

    it ('SM4 ECB 加解密测试', function (){
        var key = Hex.parse('9874561230ABCDEF3698521470BFEDCA');
        var data = Helper.ascstr2array('test SM4 encrypt and decrypt');

        var pdata = DataPadding.encodeWithPKCS5(data, SM4.KEY_SIZE);
        var ciphertext = SM4.encryptWithECB(pdata, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('94B1213F34F28D6ACA7119C8C0674987C58E174BF06D44DDC13DEFA53466013B');
        var plaintext = SM4.decryptWithECB(ciphertext, key);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWithPKCS5(pdata).toString());
    })

    it ('SM4 CBC 加解密测试', function () {
        var key = Hex.parse('9874561230ABCDEF3698521470BFEDCA');
        var iv = key;
        var data = Helper.ascstr2array('test SM4 encrypt and decrypt');

        var pdata = DataPadding.encodeWithPKCS5(data, SM4.KEY_SIZE);
        var ciphertext = SM4.encryptWithCBC(pdata, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('CD34D95C16AD40ABD6563A233FE25ECCF6D9658B17E8C55753A13DB263E2E536');
        var plaintext = SM4.decryptWithCBC(ciphertext, key, iv);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWithPKCS5(pdata).toString());
    })
});



    describe('RSA 算法测试', function () {
    var K = KeyouCryptography;
    var RSA = KeyouCryptography.algorithm.RSA;
    var Helper = KeyouCryptography.util.Helper;
    var Hex = KeyouCryptography.util.Hex;

    it ('生成 RSA 密钥对', function () { // 公钥包含 RSA oid 
        var bits = 1408;
        var exponent = "010001";
        var keypair = RSA.generate(bits, exponent);
        expect(keypair.publicKey.length > bits/8).to.be.true;
        expect(keypair.privateKey).to.be.exist;
        expect(keypair.privateKey.length > bits/8).to.be.true;        
    })

    it ('生成 RSA 密钥对', function () { // 公钥包含 RSA oid 
        var bits = 1408;
        var keypair = RSA.generate(bits);
        expect(keypair.publicKey.length > bits/8).to.be.true;
        expect(keypair.privateKey).to.be.exist;
        expect(keypair.privateKey.length > bits/8).to.be.true;        
    })

    it ('RSA 加解密自测', function () {
        var data = Hex.parse('00EB3AF903293C78EBE030EC2367DAEE');
        var publicKey = Hex.parse(RSA.testKeypair.publicKey);
        var ciphertext = RSA.encrypt(data, publicKey);

        // console.log(Hex.stringify(ciphertext));

        var privateKey = Hex.parse(RSA.testKeypair.privateKey);
        var plaintext = RSA.decrypt(ciphertext, privateKey);
        expect(data.toString()).to.be.equal(plaintext.toString());
    })

        it ('RSA 解密测试', function () {
        var data = Helper.ascstr2array('1234567890ABCDEF');
        var publicKey = Hex.parse("30818902818100BB541C8D09E5D116E2D98CAB9B630A4F711BE65081DD6C5E1C48442DBE83C3318999C0F670B774572BCF0CF37895EE828ED65894CFFDAE486ADB3B73CF6D5768CF41AA45DDE5A73D0BEC00BE4DAD7B213719AC557FF70CB6D87E5F4C3291D71DCFB306CC539C95017F0030E9072B1AE94CFDC0FA51FEE59826A2A6C08013D1CF0203010001");
        var ciphertext = RSA.encrypt(data, publicKey);

        console.log(Hex.stringify(ciphertext));

    })

    it('RSA 签名验签测试: 不做HASH', function () {
        var data = Helper.ascstr2array('1234567890ABCDEF');
        var privateKey = Hex.parse(RSA.testKeypair.privateKey);
        var sign = RSA._sign(data, privateKey);
        expect(RSA.sign(data, privateKey, K.Hasher.NONE).toString()).to.be.equal(sign.toString());

        // console.log(Hex.stringify(sign));

        var publicKey = Hex.parse(RSA.testKeypair.publicKey);
        var success = RSA._verify(sign, data, publicKey);
        expect(success).to.be.true;
        expect(RSA.verify(sign, data, publicKey, K.Hasher.NONE)).to.be.true;
    })

    it ('RSA 签名验签测试: 内部做HASH', function () {
        var data = Helper.ascstr2array('1234567890ABCDEF');
        var privateKey = Hex.parse(RSA.testKeypair.privateKey);
        var sign = RSA.sign(data, privateKey, K.Hasher.MD5);

        var publicKey = Hex.parse(RSA.testKeypair.publicKey);
        var success = RSA.verify(sign, data, publicKey, K.Hasher.MD5);
        expect(success).to.be.true;

        var data = Helper.ascstr2array('123456zhangmf');
        var sign = Hex.parse('008101463E725977623AA5EEDCE0C31CB3A60291C3157083DC839DB9CD4F967670850A44845888BA49D1573880D81A2F6E165DBABA89F55A7C46E7C51946BCCFD3C81B35EACDB4B81B79C1930A7AF6CFBA7457420F9BCE692D69C63A6276EC39B254FF0BAAF4F9E00D4BC5C952EBE19AC3D31EC1A875F0F871AE33C80895DFB93B');
        // var publicKey = Hex.parse('30818902818100B4A1DF5919561EC27EDEC78C7AB51903CAC6756B23EF0F5286E4DD44645B92C08A12BFCC47CF4D7AE251E9F5C56C6F3F2BF9C068808724F1367A2EC0BA22203B352C0976E5556E8F3A2F163ACE94AD0DC1FEF050A0D97676C24D72FA9E002E9AC291EA173F6D4DCF2E7ED8FD1147721231430C8F6E3D0A680227373EDAB286D10203010001');
        var publicKey = Hex.parse('B4A1DF5919561EC27EDEC78C7AB51903CAC6756B23EF0F5286E4DD44645B92C08A12BFCC47CF4D7AE251E9F5C56C6F3F2BF9C068808724F1367A2EC0BA22203B352C0976E5556E8F3A2F163ACE94AD0DC1FEF050A0D97676C24D72FA9E002E9AC291EA173F6D4DCF2E7ED8FD1147721231430C8F6E3D0A680227373EDAB286D1');
        var success = RSA.verify(sign, data, publicKey, K.Hasher.MD5);
        expect(success).to.be.true;        
    })
});



    describe('DES 算法测试', function () {
    var DES = KeyouCryptography.algorithm.DES;
    var Hex = KeyouCryptography.util.Hex;
    var Helper = KeyouCryptography.util.Helper;

    it('DES-64  ECB 加解密正常用例', function () {
        var plaintext = Hex.parse("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");  
        var key = Hex.parse("ABCDEF1234567890");
        var ciphertext = DES.encryptWithECB(plaintext, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('34D0C7352E63CC8634D0C7352E63CC8634D0C7352E63CC86');
        var data = DES.decryptWithECB(ciphertext, key);
        expect(Hex.stringify(data)).to.be.equal(Hex.stringify(plaintext));
    })

    it('DES-128 ECB 加解密正常用例', function () {
        var plaintext = Hex.parse("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");  
        var key = Hex.parse("ABCDEF1234567890ABCDEF1234567890");
        var ciphertext = DES.encryptWithECB(plaintext, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('34D0C7352E63CC8634D0C7352E63CC8634D0C7352E63CC8634D0C7352E63CC86');
        var data = DES.decryptWithECB(ciphertext, key);
        expect(data.toString()).to.be.equal(plaintext.toString());  


        var plaintext = Helper.ascstr2array("00321234567890ACE09535EA9432D12445320000");  
        var key = Hex.parse("CDDC4C7F388364CB45A11051C48A2597");
        var ciphertext = DES.encryptWithECB(plaintext, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('2F0F539A93273733C473CFDE9E17118B579B01536A30C4C17C45D9B9E5DAAAC141018A2B17C456DA');
        var data = DES.decryptWithECB(ciphertext, key);
        expect(data.toString()).to.be.equal(plaintext.toString());         


    })

    it('DES-192 ECB 加解密正常用例', function () {
        var plaintext = Hex.parse("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");  
        var key = Hex.parse("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");
        var ciphertext = DES.encryptWithECB(plaintext, key);
        expect(ciphertext.length).to.be.equal(plaintext.length);
        var data = DES.decryptWithECB(ciphertext, key);
        expect(data.toString()).to.be.equal(plaintext.toString());        
    })


    it ('DES-64 CBC 加解密', function () {
        var plaintext = Hex.parse('AFB8D2E9D0AB8826EDE9C0427DF530CB33212E25555EFBC11083F54EC2D72F9FEDEC06044B05BCBFC5EA04B5ADE78D688F7FCCE1488CFC9E8EFF82A77A0E0F55FA3F7900B80916C26ADBF2E3B8BDB100C7ACDD7C0D713FB41C5B98294F8C39C70F5695421374FD2A02EF21A0FE6F7F5619851EB29385E308E21F090924BF898FF1A9A941D464047C1CB999F66DE0B4A6BF1ADDFCD00ADE9C');
        var iv = Hex.parse('A278D91248B8B45C')
        var key = Hex.parse('CC3A14608DD54E2F')

        var ciphertext = DES.encryptWithCBC(plaintext, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('0B98215C0556B9EAFAD1CA9AABFD753809CE2B095A62537D239A94F662E227D7D7B23DC69E6FE6291BCDF19D7051F21CE615D04B57D4D6ED3181C4D0ED8D05F989F44C83137A75F58E37BB17EB6EA5FBFCBDF395450612F13E36F56294DDEEA62A698ED19D89AC14E97890FDB0241F8DF6AC9D163B344F21AC12082B9EB2CD9F696F1599BF25476B0858D97DC7DAD63F92E6E5358547FA93')
        var data = DES.decryptWithCBC(ciphertext, key, iv);
        expect(data.toString()).to.be.equal(plaintext.toString());
    })

    it ('DES-128 CBC 加解密', function () {
        var plaintext = Hex.parse('AFB8D2E9D0AB8826EDE9C0427DF530CB33212E25555EFBC11083F54EC2D72F9FEDEC06044B05BCBFC5EA04B5ADE78D688F7FCCE1488CFC9E8EFF82A77A0E0F55FA3F7900B80916C26ADBF2E3B8BDB100C7ACDD7C0D713FB41C5B98294F8C39C70F5695421374FD2A02EF21A0FE6F7F5619851EB29385E308E21F090924BF898FF1A9A941D464047C1CB999F66DE0B4A6BF1ADDFCD00ADE9C');
        var iv = Hex.parse('A278D91248B8B45C')
        var key = Hex.parse('C32C7F03FE9FB444E87F0136FDDAB1A9')

        var ciphertext = DES.encryptWithCBC(plaintext, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('ECD12F499B520D45A06014EAEB40C7975A0DF798FC59D26CEAAB43E3BD3E63B7F2B79E93CF3E30D26AA71F9B9E961DFF9A7FA290D2A9F99C839A3CE4652D77203DAB7C0CD72DC7CC0B277530142F55E27760704DBF2FD76DCECC226C3037840B03F7C7C420AE1595F038D3E90BA6A45791C7BF64B7F44AA877C4CCB35383E0216142CC3BA97C005E0AF775E241D686BE5ED003A135099D0F')
        var data = DES.decryptWithCBC(ciphertext, key, iv);
        expect(data.toString()).to.be.equal(plaintext.toString());        
    })    

    it ('DES-192 CBC 加解密', function () {
        var plaintext = Hex.parse('AFB8D2E9D0AB8826EDE9C0427DF530CB33212E25555EFBC11083F54EC2D72F9FEDEC06044B05BCBFC5EA04B5ADE78D688F7FCCE1488CFC9E8EFF82A77A0E0F55FA3F7900B80916C26ADBF2E3B8BDB100C7ACDD7C0D713FB41C5B98294F8C39C70F5695421374FD2A02EF21A0FE6F7F5619851EB29385E308E21F090924BF898FF1A9A941D464047C1CB999F66DE0B4A6BF1ADDFCD00ADE9C');
        var iv = Hex.parse('A278D91248B8B45C')
        var key = Hex.parse('7A85A7BF4DB59C551AA6654F1F0CF7B311B861A534C58BE2')

        var ciphertext = DES.encryptWithCBC(plaintext, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('61AA79FB77015081C0C01C51E14F76BC23EF572AFA0A362E2C8EC807246D1FC1A0B53ADCF56B67A7AC71D3971553BE72A700D6173F8297413053D8D58FD0377F0AE942989F742EA3A9EDD2AD51A0FCB092ABE68F07E7FC5A5B39A838FA6DAE5B6A4B01E54B356B29D9120685632D2257D891F22F6B42E60F0E358C6E0BAE1FBB6B12627FA32FC45155E9A8A486524FC90E0E41BF03CBB579')
        var data = DES.decryptWithCBC(ciphertext, key, iv);
        expect(data.toString()).to.be.equal(plaintext.toString());        
    })
});   




    describe('AES 算法测试', function () {
    var AES = KeyouCryptography.algorithm.AES;
    var Hex = KeyouCryptography.util.Hex;
    var Helper = KeyouCryptography.util.Helper;
    var DataPadding = KeyouCryptography.util.DataPadding;

    it ('AES-128 ECB 加解密测试', function (){
        var key = Hex.parse('43B20CAF5004561A0CD55AE042503E58');
        var data = Helper.ascstr2array('test AES ECB 128 encrypt and decrypt');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithECB(pdata, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('7E19CFD92216534D823D08169A490B1B7D6AB47FA377218EA2DA9C6DF6ADDB0F48A33049F975B2F55851C02B52CAD692');
        var plaintext = AES.decryptWithECB(ciphertext, key);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

    it ('AES-192 ECB 加解密测试', function () {
        var key = Hex.parse('6F5DE78D9DC2D560F7935F1FDDB8314D2693C77DE780B15A');
        var data = Helper.ascstr2array('test AES ECB 192 encrypt and decrypt');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithECB(pdata, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('42E2C7516421EEAF4663C2AB9F2579C63527D9E8149300F63319584027FBE644247E4E2079CAE3A650D92CCD1810BFCA');
        var plaintext = AES.decryptWithECB(ciphertext, key);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

    it ('AES-256 ECB 加解密测试', function () {
        var key = Hex.parse('0F2F8F7E8C994CA74F6175FC16B1A0228754CCD28795EFBDF461BA04DAABD3D1');
        var data = Helper.ascstr2array('test AES ECB 256 encrypt and decrypt');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithECB(pdata, key);
        expect(Hex.stringify(ciphertext)).to.be.equal('52DCE3A668B922DC2E03C273C8F1B8F1EE24BAC82A65AF171DB4D1A4543D90A3B184377985D164CDDFF06F43898BC797');
        var plaintext = AES.decryptWithECB(ciphertext, key);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

    it ('AES-128 CBC 加解密测试', function (){
        var key = Hex.parse('43B20CAF5004561A0CD55AE042503E58');
        var data = Helper.ascstr2array('test AES CBC 128 encrypt and decrypt');
        var iv = Helper.ascstr2array('1234567812345678');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithCBC(pdata, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('618B302E08BA95F817B19CA1C23DEB41C8BA00AD60628046883B85A865B6DC213D5E777493383CE1B499C6874736DF84');
        var plaintext = AES.decryptWithCBC(ciphertext, key, iv);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

    it ('AES-192 CBC 加解密测试', function () {
        var key = Hex.parse('6F5DE78D9DC2D560F7935F1FDDB8314D2693C77DE780B15A');
        var data = Helper.ascstr2array('test AES CBC 192 encrypt and decrypt');
        var iv = Helper.ascstr2array('1234567812345678');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithCBC(pdata, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('FECFC51DBFDFC37555EEE803287ACF88BAF527C5D2C8213C74F24D3F529222DBD721D4FA3AB7CEA8985FB6062923DFCB');
        var plaintext = AES.decryptWithCBC(ciphertext, key, iv);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

    it ('AES-256 CBC 加解密测试', function () {
        var key = Hex.parse('0F2F8F7E8C994CA74F6175FC16B1A0228754CCD28795EFBDF461BA04DAABD3D1');
        var data = Helper.ascstr2array('test AES CBC 256 encrypt and decrypt');
        var iv = Helper.ascstr2array('1234567812345678');

        var pdata = DataPadding.encodeWith0x00(data, AES.KEY_SIZE);
        var ciphertext = AES.encryptWithCBC(pdata, key, iv);
        expect(Hex.stringify(ciphertext)).to.be.equal('BAE5B1F3A828D974422A4F53540D93879CBE6D308B3718F7172BC0944C7CB5572222FEE54D0A190B19662448190F2F00');
        var plaintext = AES.decryptWithCBC(ciphertext, key, iv);
        expect(pdata.toString()).to.be.equal(plaintext.toString());
        expect(data.toString()).to.be.equal(DataPadding.decodeWith0x00(pdata).toString());
    })

});



    describe('MD5 算法测试', function () {

    var MD5 = KeyouCryptography.algorithm.MD5;
    var Helper = KeyouCryptography.util.Helper;
    var Hex = KeyouCryptography.util.Hex;

    it ('MD5 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(MD5.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('d41d8cd98f00b204e9800998ecf8427e'.toUpperCase());
        expect(HASH('a')).to.be.equal('0cc175b9c0f1b6a831c399e269772661'.toUpperCase());
        expect(HASH('abc')).to.be.equal('900150983cd24fb0d6963f7d28e17f72'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('f96b697d7cb7938d525a2f31aaf161d0'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('c3fcd3d76192e4007dfb496cca67e13b'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('d174ab98d277d9f5a5611c2c9f419d9f'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('57edf4a22be3c955ac49da2e2107b67a'.toUpperCase());
    })
});


    describe('SHA 算法测试', function () {

    var SHA1 = KeyouCryptography.algorithm.SHA1;
    var SHA224 = KeyouCryptography.algorithm.SHA224;
    var SHA256 = KeyouCryptography.algorithm.SHA256;
    var SHA384 = KeyouCryptography.algorithm.SHA384;
    var SHA512 = KeyouCryptography.algorithm.SHA512;
    var Helper = KeyouCryptography.util.Helper;
    var Hex = KeyouCryptography.util.Hex;

    it ('SHA1 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(SHA1.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709'.toUpperCase());
        expect(HASH('a')).to.be.equal('86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8'.toUpperCase());
        expect(HASH('abc')).to.be.equal('A9993E364706816ABA3E25717850C26C9CD0D89D'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('C12252CEDA8BE8994D5FA0290A47231C1D16AAE3'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('32D10C7B8CF96570CA04CE37F2A19D84240D3A89'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('761C457BF73B14D27E9E9265C46F4B4DDA11F940'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('50ABF5706A150990A08B2C5EA40FA0E585554732'.toUpperCase());
    })

    it ('SHA224 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(SHA224.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F'.toUpperCase());
        expect(HASH('a')).to.be.equal('ABD37534C7D9A2EFB9465DE931CD7055FFDB8879563AE98078D6D6D5'.toUpperCase());
        expect(HASH('abc')).to.be.equal('23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('2CB21C83AE2F004DE7E81C3C7019CBCB65B71AB656B22D6D0C39B8EB'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('45A5F72C39C5CFF2522EB3429799E49E5F44B356EF926BCF390DCCC2'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('BFF72B4FCB7D75E5632900AC5F90D219E05E97A7BDE72E740DB393D9'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('B50AECBE4E9BB0B57BC5F3AE760A8E01DB24F203FB3CDCD13148046E'.toUpperCase());
    })

    it ('SHA256 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(SHA256.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'.toUpperCase());
        expect(HASH('a')).to.be.equal('CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB'.toUpperCase());
        expect(HASH('abc')).to.be.equal('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E'.toUpperCase());
    })

    it ('SHA384 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(SHA384.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B'.toUpperCase());
        expect(HASH('a')).to.be.equal('54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31'.toUpperCase());
        expect(HASH('abc')).to.be.equal('CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('473ED35167EC1F5D8E550368A3DB39BE54639F828868E9454C239FC8B52E3C61DBD0D8B4DE1390C256DCBB5D5FD99CD5'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('FEB67349DF3DB6F5924815D6C3DC133F091809213731FE5C7B5F4999E463479FF2877F5F2936FA63BB43784B12F3EBB4'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('1761336E3F7CBFE51DEB137F026F89E01A448E3B1FAFA64039C1464EE8732F11A5341A6F41E0C202294736ED64DB1A84'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('B12932B0627D1C060942F5447764155655BD4DA0C9AFA6DD9B9EF53129AF1B8FB0195996D2DE9CA0DF9D821FFEE67026'.toUpperCase());
    })

    it ('SHA512 计算数据摘要值', function () {
        var HASH = function (data) {
            return Hex.stringify(SHA512.digest(Helper.ascstr2array(data)));
        }
        expect(HASH('')).to.be.equal('CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E'.toUpperCase());
        expect(HASH('a')).to.be.equal('1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75'.toUpperCase());
        expect(HASH('abc')).to.be.equal('DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F'.toUpperCase());
        expect(HASH('message digest')).to.be.equal('107DBF389D9E9F71A3A95F6C055B9251BC5268C2BE16D6C13492EA45B0199F3309E16455AB1E96118E8A905D5597B72038DDB372A89826046DE66687BB420E7C'.toUpperCase());
        expect(HASH('abcdefghijklmnopqrstuvwxyz')).to.be.equal('4DBFF86CC2CA1BAE1E16468A05CB9881C97F1753BCE3619034898FAA1AABE429955A1BF8EC483D7421FE3C1646613A59ED5441FB0F321389F77F48A879C7B1F1'.toUpperCase());
        expect(HASH('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).to.be.equal('1E07BE23C26A86EA37EA810C8EC7809352515A970E9253C26F536CFC7A9996C45C8370583E0A78FA4A90041D71A4CEAB7423F19C71B9D5A3E01249F0BEBD5894'.toUpperCase());
        expect(HASH('12345678901234567890123456789012345678901234567890123456789012345678901234567890')).to.be.equal('72EC1EF1124A45B047E8B7C75A932195135BB61DE24EC0D1914042246E0AEC3A2354E093D76F3048B456764346900CB130D2A4FD5DD16ABB5E30BCB850DEE843'.toUpperCase());
    })
});



    describe('数字信封测试', function () {
    var K = KeyouCryptography;
    var Helper = KeyouCryptography.util.Helper;
    var Hex = KeyouCryptography.util.Hex;
    var DigitalEnvelope = KeyouCryptography.DigitalEnvelope;

    it ('SM2WithSM4 加解密测试', function () {
        var pk = 'C5F171CC415C5C2759FE4668F51C0D7DA2CB85AE754F29135FED90D50C3B437D2EEA0F54163C3880C13618FF0F7CA67201DFF244016F09F19F7C1EC5D4033546';
        var data = Helper.ascstr2array(pk);


        var env = DigitalEnvelope.encrypt(data, pk, {
            asymmetricAlg: K.AsymmetricAlg.SM2,
            symmetricAlg: K.SymmetricAlg.SM4,
            pad: K.Pad.padPKCS5
        })

        var vk = '32803B68C49C9285F31577ACA17B7EE92E0828707F12FF8EE74442F75D68C5C8';
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.SM2,
            symmetricAlg: K.SymmetricAlg.SM4,
            pad: K.Pad.padPKCS5            
        })

        expect(Hex.stringify(data)).to.be.equal(plaintext);
    })

    it ('SM2WithAES 加解密测试', function () {
        var pk = 'C5F171CC415C5C2759FE4668F51C0D7DA2CB85AE754F29135FED90D50C3B437D2EEA0F54163C3880C13618FF0F7CA67201DFF244016F09F19F7C1EC5D4033546';
        var data = Helper.ascstr2array(pk);


        var env = DigitalEnvelope.encrypt(data, pk, {
            asymmetricAlg: K.AsymmetricAlg.SM2,
            symmetricAlg: K.SymmetricAlg.AES128,
            pad: K.Pad.padPKCS5
        })

        var vk = '32803B68C49C9285F31577ACA17B7EE92E0828707F12FF8EE74442F75D68C5C8';
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.SM2,
            symmetricAlg: K.SymmetricAlg.AES128,
            pad: K.Pad.padPKCS5            
        })

        expect(Hex.stringify(data)).to.be.equal(plaintext);
    })

    it ('RSAWithDESede 加解密测试', function () {
        var pk = '308189028181009F43B5203FB2A2E20E97D1A985AA3D86F66274922304E9ED6698BA94B7903AD7F3741EDE9078DF3EBA27FCD1A38F9B608499A7E5CD3EF6FC658BAA231028B40033F3A11AB0B286541CA385B758D4C87D052216B14547B28265AC3243549378ECAAA5CEEAA7CB38DA2F78C3D6634A3BEA1745923E452E3C4ABA0D967D67DCABD50203010001';
        var data = Helper.ascstr2array(pk);

        var env = DigitalEnvelope.encrypt(data, pk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.DES128,
            pad: K.Pad.pad0x00
        })        

        var vk = '3082025D020100028181009F43B5203FB2A2E20E97D1A985AA3D86F66274922304E9ED6698BA94B7903AD7F3741EDE9078DF3EBA27FCD1A38F9B608499A7E5CD3EF6FC658BAA231028B40033F3A11AB0B286541CA385B758D4C87D052216B14547B28265AC3243549378ECAAA5CEEAA7CB38DA2F78C3D6634A3BEA1745923E452E3C4ABA0D967D67DCABD502030100010281806B37D1C01C21CEB610CCF44103D3500883E65443ED7F695C812D60AEADC55357FE75B6326F60702A7278692358D15CF0E553EC4C3098AAFDCFFEEE531C95CA5728B4CA81F25CF1B88E476F246882BD311DAD00463DEBAE2F0275F1C4538E9216DB70A19DC78DFE875E7EFE35EBFCFB459DFF9EA821A20178C5FE3EC53571BA21024100CE0D43DDE1383EA9827EF3A5F684573F58FAAE294693A48DC56B77489E0A3E86DE74BDE3D43A684C6F15AB21E5ED2B781CBD880246EA99F2A960079AA715AD13024100C5DF02E9ECAE7A3B268377372BC6EAA67838DFAB6C497FDA1216EDCB7962B6D0AB0D33AA13233B19ACDAB0CA86A165A7B96BF9D995643FA431F74A423650E87702410092D2FAF820E2FE2BB57416D3BCCC628B1E314A66D9069DABF3EFF6C884ECD1CF32B6C7149006AA89446291560F4BA7BCE7E5DA039D5AD0260CB103DA1C932287024100BD0E14019F6321644CAB0587D02AF15DF6B61876F832CD9674FC355DD8EFC94E5C7073B187317D314DE7714D400F0B4A92AE28FD8C7049223F9F4FF32D646687024003D59FD40D99C7A67E33836DB66A933432CBBC34D958BA7E233672EBA6174E7AAEC3AF2821A899A667CBBD48283C7BB59BBF77C8A8232CD9F0F17DBDC2629118';
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.DES128,
            pad: K.Pad.pad0x00           
        })

        expect(Hex.stringify(data)).to.be.equal(plaintext); 

        var env = {
            KeyCipher: '002605F0764F0E3925B7EC5862247F7751620AC8E286E766533AAC38F209CA8A300157DDBBCE13BF9AD2D1F4E39FF94A549E0CDB5AF6531A925D7A4EF6837B6B5F0E5DFB14D8FD34BDC9DDE0E642D784266F8683E86ABE8CE4E962ED6C0F27DDFE1D41FB01E481F3F2C40D9C5048D33BA83A0AF7BDFB7F84D067E3E5D515FEAB',
            MessageCipher: '6FA9ED8BAA403E5156FFAC50303A6D87737AFEC1C6BAC8E94FD78CB3FCBFC45B'
        }
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.DES128,
            pad: K.Pad.pad0x00      
        })

        expect(Helper.array2ascstr(Hex.parse(plaintext))).to.be.equal('1234567890ACE09535EA9432D1244532');

    })

    it ('RSAWithAES 加解密测试', function () {
        var pk = '308189028181009F43B5203FB2A2E20E97D1A985AA3D86F66274922304E9ED6698BA94B7903AD7F3741EDE9078DF3EBA27FCD1A38F9B608499A7E5CD3EF6FC658BAA231028B40033F3A11AB0B286541CA385B758D4C87D052216B14547B28265AC3243549378ECAAA5CEEAA7CB38DA2F78C3D6634A3BEA1745923E452E3C4ABA0D967D67DCABD50203010001';
        var data = Helper.ascstr2array(pk);

        var env = DigitalEnvelope.encrypt(data, pk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.AES128,
            pad: K.Pad.pad0x00
        })        

        var vk = '3082025D020100028181009F43B5203FB2A2E20E97D1A985AA3D86F66274922304E9ED6698BA94B7903AD7F3741EDE9078DF3EBA27FCD1A38F9B608499A7E5CD3EF6FC658BAA231028B40033F3A11AB0B286541CA385B758D4C87D052216B14547B28265AC3243549378ECAAA5CEEAA7CB38DA2F78C3D6634A3BEA1745923E452E3C4ABA0D967D67DCABD502030100010281806B37D1C01C21CEB610CCF44103D3500883E65443ED7F695C812D60AEADC55357FE75B6326F60702A7278692358D15CF0E553EC4C3098AAFDCFFEEE531C95CA5728B4CA81F25CF1B88E476F246882BD311DAD00463DEBAE2F0275F1C4538E9216DB70A19DC78DFE875E7EFE35EBFCFB459DFF9EA821A20178C5FE3EC53571BA21024100CE0D43DDE1383EA9827EF3A5F684573F58FAAE294693A48DC56B77489E0A3E86DE74BDE3D43A684C6F15AB21E5ED2B781CBD880246EA99F2A960079AA715AD13024100C5DF02E9ECAE7A3B268377372BC6EAA67838DFAB6C497FDA1216EDCB7962B6D0AB0D33AA13233B19ACDAB0CA86A165A7B96BF9D995643FA431F74A423650E87702410092D2FAF820E2FE2BB57416D3BCCC628B1E314A66D9069DABF3EFF6C884ECD1CF32B6C7149006AA89446291560F4BA7BCE7E5DA039D5AD0260CB103DA1C932287024100BD0E14019F6321644CAB0587D02AF15DF6B61876F832CD9674FC355DD8EFC94E5C7073B187317D314DE7714D400F0B4A92AE28FD8C7049223F9F4FF32D646687024003D59FD40D99C7A67E33836DB66A933432CBBC34D958BA7E233672EBA6174E7AAEC3AF2821A899A667CBBD48283C7BB59BBF77C8A8232CD9F0F17DBDC2629118';
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.AES128,
            pad: K.Pad.pad0x00           
        })

        expect(Hex.stringify(data)).to.be.equal(plaintext); 

        var env = {
            KeyCipher: '002605F0764F0E3925B7EC5862247F7751620AC8E286E766533AAC38F209CA8A300157DDBBCE13BF9AD2D1F4E39FF94A549E0CDB5AF6531A925D7A4EF6837B6B5F0E5DFB14D8FD34BDC9DDE0E642D784266F8683E86ABE8CE4E962ED6C0F27DDFE1D41FB01E481F3F2C40D9C5048D33BA83A0AF7BDFB7F84D067E3E5D515FEAB',
            MessageCipher: '66381D497E7B80BBAEE96BD796A0E1B2F38BFFD9F4C2340AAF2A48A31130EAB1'
        }
        var plaintext = DigitalEnvelope.decrypt(env, vk, {
            asymmetricAlg: K.AsymmetricAlg.RSA,
            symmetricAlg: K.SymmetricAlg.AES128,
            pad: K.Pad.pad0x00      
        })

        expect(Helper.array2ascstr(Hex.parse(plaintext))).to.be.equal('1234567890ACE09535EA9432D1244532');

    })

})

