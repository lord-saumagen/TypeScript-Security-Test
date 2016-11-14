/// <reference path="_references.ts" />

namespace TS_Security_test
{
  var AES_CBC_TestVector128: DATA.IIVTestVector;
  var AES_CBC_TestVector192: DATA.IIVTestVector;
  var AES_CBC_TestVector256: DATA.IIVTestVector;

  var numberArray16: Array<number>;
  var unsignedByteValueArray16: Array<number>;
  var unsignedByteValueArray33: Array<number>;

  QUnit.module("TS.Security.AES_CBC",
  {
    before: function ()
    {
      AES_CBC_TestVector128 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        cipherText: [0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7]
      };

      AES_CBC_TestVector192 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
        IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        cipherText: [0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0, 0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd]
      };

      AES_CBC_TestVector256 = {
        plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        key: [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        cipherText: [0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b]
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


  QUnit.test("AES_CBC constructor", (assert) =>
  {
    let aes_cbc: TS.Security.AES_CBC;

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(null, []);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(undefined, []);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC([], []);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33.slice(0,15), []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33.slice(0, 17), []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33.slice(0, 23), []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33.slice(0, 25), []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33.slice(0, 31), []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray33, []);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, []);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, unsignedByteValueArray33.slice(0, 15));
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'initialisationVector' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, numberArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'initialisationVector' which is not an unsigned byte value array.");

    aes_cbc = new TS.Security.AES_CBC(unsignedByteValueArray16, unsignedByteValueArray16);
    assert.ok(TS.Utils.Assert.isObject(aes_cbc), "Should pass for a call with valid arguments.");
  });


  QUnit.test("AES_CBC encrypt", (assert) =>
  {
    let aes_cbc: TS.Security.AES_CBC;
    let cipherText: Array<number>;

    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector128.key, AES_CBC_TestVector128.IV);
    cipherText = aes_cbc.encrypt((AES_CBC_TestVector128.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CBC_TestVector128.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");

    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector192.key, AES_CBC_TestVector192.IV);
    cipherText = aes_cbc.encrypt((AES_CBC_TestVector192.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CBC_TestVector192.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");


    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV);
    cipherText = aes_cbc.encrypt((AES_CBC_TestVector256.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CBC_TestVector256.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");

    assert.throws(() =>
    {
      aes_cbc.encrypt((AES_CBC_TestVector256.plainText as Array<number>).concat([1, 2, 3]));
    }, TS.ArgumentException, "Should throw a 'TS.ArgumentException' for a call to enrypt with an inappropriate length.");

  });


  QUnit.test("AES_CBC decrypt", (assert) =>
  {
    let aes_cbc: TS.Security.AES_CBC;
    let plainText: Array<number>

    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector128.key, AES_CBC_TestVector128.IV);
    plainText = aes_cbc.decrypt((AES_CBC_TestVector128.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CBC_TestVector128.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");

    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector192.key, AES_CBC_TestVector192.IV);
    plainText = aes_cbc.decrypt((AES_CBC_TestVector192.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CBC_TestVector192.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");


    aes_cbc = new TS.Security.AES_CBC(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV);
    plainText = aes_cbc.decrypt((AES_CBC_TestVector256.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CBC_TestVector256.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");

    assert.throws(() =>
    {
      aes_cbc.decrypt((AES_CBC_TestVector256.cipherText as Array<number>).concat([1, 2, 3]));
    }, TS.ArgumentException, "Should throw a 'TS.ArgumentException' for a call to enrypt with an inappropriate length.");

  });


  QUnit.test("AES_CBC_Stream constructor", (assert) =>
  {
    let onNextData: (bitString: string) => void;
    let onClosed: () => void;
    let onError: (exception: TS.Exception) => void;
    let aes_cbc_Stream: TS.Security.AES_CBC_Stream;

    onNextData = (bitString : string) => { };
    onClosed = () => { };
    onError = (exception: TS.Exception) => { };

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(null, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(undefined, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream([], unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33.slice(0, 15), unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33.slice(0, 17), unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33.slice(0, 23), unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33.slice(0, 25), unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33.slice(0, 31), unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray33, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, null, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, undefined, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, [], TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16.slice(0, 15), TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with an 'initialisationVector' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, numberArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an 'initialisationVector' which is not an unsigned byte value array.");
    
    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, null, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, undefined, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, -1, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 2, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 0.75, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, null, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, undefined, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, null, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onClosed' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, undefined, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onClosed' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onError' argument.");

    assert.throws(() =>
    {
      aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onError' argument.");

    aes_cbc_Stream = new TS.Security.AES_CBC_Stream(unsignedByteValueArray16, unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    assert.ok(TS.Utils.Assert.isObject(aes_cbc_Stream), "Should pass for a call with valid arguments.");

  });


  QUnit.test("AES_CBC_Stream write (async stream encrypt)", (assert) =>
  {
    let aes_cbc_Stream128: TS.Security.AES_CBC_Stream;
    let aes_cbc_Stream192: TS.Security.AES_CBC_Stream;
    let aes_cbc_Stream256: TS.Security.AES_CBC_Stream;
    let aes_cbc_StreamFail: TS.Security.AES_CBC_Stream;
    let cipherText128: Array<number>;
    let cipherText192: Array<number>;
    let cipherText256: Array<number>;
    let cipherTextFail: Array<number>;
    let asyncDone128: () => void;
    let asyncDone192: () => void;
    let asyncDone256: () => void;
    let asyncDoneFail: () => void;

    //****************//
    // 128 Bit Key    //
    //****************//
    cipherText128 = new Array<number>();
    asyncDone128 = assert.async();

    aes_cbc_Stream128 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector128.key, AES_CBC_TestVector128.IV, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText128 = cipherText128.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText128, AES_CBC_TestVector128.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream128.writeByteArray((AES_CBC_TestVector128.plainText as Array<number>));
    aes_cbc_Stream128.close();

    //****************//
    // 192 Bit Key    //
    //****************//
    cipherText192 = new Array<number>();
    asyncDone192 = assert.async();

    aes_cbc_Stream192 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector192.key, AES_CBC_TestVector192.IV, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText192 = cipherText192.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText192, AES_CBC_TestVector192.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream192.writeByteArray((AES_CBC_TestVector192.plainText as Array<number>));
    aes_cbc_Stream192.close();

    //****************//
    // 256 Bit Key    //
    //****************//
    cipherText256 = new Array<number>();
    asyncDone256 = assert.async();

    aes_cbc_Stream256 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText256 = cipherText256.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText256, AES_CBC_TestVector256.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream256.writeByteArray((AES_CBC_TestVector256.plainText as Array<number>));
    aes_cbc_Stream256.close();

    //****************//
    // Fail           //
    //****************//
    cipherTextFail = new Array<number>();
    asyncDoneFail = assert.async();

    aes_cbc_StreamFail = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherTextFail = cipherTextFail.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        throw new TS.Exception("Unexpected result. Stream cipher should fail because of a data feed which doesn't match the block length requirement of the underlying block cipher operation.");
      },
      //onError
      (exception: TS.Exception) =>
      {
        assert.ok(exception.type == "TS.InvalidOperationException", "Should fail because of an unappropriate data length for the underlying cipher object.");
        asyncDoneFail();
      });

    aes_cbc_StreamFail.writeByteArray((AES_CBC_TestVector256.plainText as Array<number>));
    //Make sure that the stream data doesn't fit into a 128 bit block.
    aes_cbc_StreamFail.writeByteArray([0, 0, 0]);
    aes_cbc_StreamFail.close();

  });


  QUnit.test("AES_CBC_Stream write (async stream decrypt)", (assert) =>
  {
    let aes_cbc_Stream128: TS.Security.AES_CBC_Stream;
    let aes_cbc_Stream192: TS.Security.AES_CBC_Stream;
    let aes_cbc_Stream256: TS.Security.AES_CBC_Stream;
    let aes_cbc_StreamFail: TS.Security.AES_CBC_Stream;
    let plainText128: Array<number>;
    let plainText192: Array<number>;
    let plainText256: Array<number>;
    let plainTextFail: Array<number>;
    let asyncDone128: () => void;
    let asyncDone192: () => void;
    let asyncDone256: () => void;
    let asyncDoneFail: () => void;

    //****************//
    // 128 Bit Key    //
    //****************//
    plainText128 = new Array<number>();
    asyncDone128 = assert.async();

    aes_cbc_Stream128 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector128.key, AES_CBC_TestVector128.IV, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText128 = plainText128.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText128, AES_CBC_TestVector128.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream128.writeByteArray((AES_CBC_TestVector128.cipherText as Array<number>));
    aes_cbc_Stream128.close();

    //****************//
    // 192 Bit Key    //
    //****************//
    plainText192 = new Array<number>();
    asyncDone192 = assert.async();

    aes_cbc_Stream192 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector192.key, AES_CBC_TestVector192.IV, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText192 = plainText192.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText192, AES_CBC_TestVector192.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream192.writeByteArray((AES_CBC_TestVector192.cipherText as Array<number>));
    aes_cbc_Stream192.close();

    //****************//
    // 256 Bit Key    //
    //****************//
    plainText256 = new Array<number>();
    asyncDone256 = assert.async();

    aes_cbc_Stream256 = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText256 = plainText256.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText256, AES_CBC_TestVector256.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_cbc_Stream256.writeByteArray((AES_CBC_TestVector256.cipherText as Array<number>));
    aes_cbc_Stream256.close();

    //****************//
    // Fail           //
    //****************//
    plainTextFail = new Array<number>();
    asyncDoneFail = assert.async();

    aes_cbc_StreamFail = new TS.Security.AES_CBC_Stream(AES_CBC_TestVector256.key, AES_CBC_TestVector256.IV, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainTextFail = plainTextFail.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        throw new TS.Exception("Unexpected result. Stream cipher should fail because of a data feed which doesn't match the block length requirement of the underlying cipher object.");
      },
      //onError
      (exception: TS.Exception) =>
      {
        assert.ok(exception.type == "TS.InvalidOperationException", "Should fail because of an unappropriate data length for the underlying cipher object.");
        asyncDoneFail();
      });

    aes_cbc_StreamFail.writeByteArray((AES_CBC_TestVector256.cipherText as Array<number>));
    //Make sure that the stream data doesn't fit into a 128 bit block.
    aes_cbc_StreamFail.writeByteArray([0, 0, 0]);
    aes_cbc_StreamFail.close();

  });

}//END namespace 