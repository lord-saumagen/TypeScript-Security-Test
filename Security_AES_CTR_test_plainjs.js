﻿var TS_Security_test;
(function (TS_Security_test)
{
  let AES_CTR_TestVector128;
  let AES_CTR_TestVector192;
  let AES_CTR_TestVector256;
  let numberArray16;
  let unsignedByteValueArray16;
  let unsignedByteValueArray33;

  QUnit.module("TS.Security.AES_CTR (plain js)", {
    before: function ()
    {
      AES_CTR_TestVector128 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        nonce: [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff],
        cipherText: [0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee]
      };
      AES_CTR_TestVector192 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
        nonce: [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff],
        cipherText: [0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b, 0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94, 0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7, 0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50]
      };
      AES_CTR_TestVector256 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        nonce: [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff],
        cipherText: [0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6]
      };
      numberArray16 = [0, -1, 1, -125, 125, -250, 250, -500, 500, -1000, 1000, -0xFFFF, 0xFFFF, -0xFFFFFFFF, 0xFFFFFFFF, 16];
      unsignedByteValueArray33 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33];
      unsignedByteValueArray16 = unsignedByteValueArray33.slice(0, 16);
    },
    beforeEach: function ()
    {
      // prepare something for all following tests
    },
    afterEach: function ()
    {
      // clean up after each test
    },
    after: function ()
    {
      // runs once after all unit tests finished (including teardown)
    }
  });

  QUnit.test("AES_CTR constructor (plain js)", function (assert)
  {
    let aes_CTR;

    assert.throws(function ()
    {
      TS.Security.AES_CTR();
    }, TypeError, "Shoud throw a 'TypeError' for a call without the new operator.");
    // TypeError: Class constructor AES_CTR cannot be invoked without 'new'

    assert.throws(function ()
    {
      aes_CTR = new TS.Security.AES_CTR({}, unsignedByteValueArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'keyByteArray' argument.");

    assert.throws(function ()
    {
      aes_CTR = new TS.Security.AES_CTR(unsignedByteValueArray16, {});
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'nonce / counterValue' argument.");

  });


  QUnit.test("AES_CTR_Stream constructor (plain js)", function (assert)
  {
    let aes_CTR_Stream;
    let onNextData = function (bitString) { };
    let onClosed = function () { };
    let onError = function (exception) { };

    assert.throws(function ()
    {
      TS.Security.AES_CTR_Stream();
    }, TypeError, "Should throw a 'TypeError' for a call without the new operator.");
    // TypeError: Class constructor AES_CTR_Stream cannot be invoked without 'new'

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream({}, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'keyByteArray' argument.");

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream(unsignedByteValueArray16, {}, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'nonce / counterValue' argument.");

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream(unsignedByteValueArray16,  0, {}, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream(unsignedByteValueArray16, 0, TS.Security.CipherOperationEnum.ENCRYPT, "test", onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'onNextData' argument.");

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream(unsignedByteValueArray16, 0, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, "test", onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'onClosed' argument.");

    assert.throws(function ()
    {
      aes_CTR_Stream = new TS.Security.AES_CTR_Stream(unsignedByteValueArray16, 0, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, "test");
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'onError' argument.");
  });

})(TS_Security_test || (TS_Security_test = {}));