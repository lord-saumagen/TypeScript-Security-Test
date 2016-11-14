/// <reference path="_references.ts" />

namespace TS_Security_test
{
  let AES_CFB_TestVector128_1BIT: DATA.IIVTestVector;
  let AES_CFB_TestVector192_1BIT: DATA.IIVTestVector;
  let AES_CFB_TestVector256_1BIT: DATA.IIVTestVector;
  let AES_CFB_TestVector128_8BIT: DATA.IIVTestVector;
  let AES_CFB_TestVector192_8BIT: DATA.IIVTestVector;
  let AES_CFB_TestVector256_8BIT: DATA.IIVTestVector;
  let numberArray16: Array<number>;
  let unsignedByteValueArray16: Array<number>;
  let unsignedByteValueArray33: Array<number>;

  QUnit.module("TS.Security.AES_CFB",
    {
      before: function ()
      {

        AES_CFB_TestVector128_8BIT = {
          plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d],
          key: [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: [0x3b, 0x79, 0x42, 0x4c, 0x9c, 0x0d, 0xd4, 0x36, 0xba, 0xce, 0x9e, 0x0e, 0xd4, 0x58, 0x6a, 0x4f, 0x32, 0xb9]
        };

        AES_CFB_TestVector192_8BIT = {
          plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d],
          key: [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: [0xcd, 0xa2, 0x52, 0x1e, 0xf0, 0xa9, 0x05, 0xca, 0x44, 0xcd, 0x05, 0x7c, 0xbf, 0x0d, 0x47, 0xa0, 0x67, 0x8a]
        };

        AES_CFB_TestVector256_8BIT = {
          plainText: [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d],
          key: [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: [0xdc, 0x1f, 0x1a, 0x85, 0x20, 0xa6, 0x4d, 0xb5, 0x5f, 0xcc, 0x8a, 0xc5, 0x54, 0x84, 0x4e, 0x88, 0x97, 0x00]
        };

        AES_CFB_TestVector128_1BIT = {
          plainText: "0110101111000001",
          key: [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: "0110100010110011"
        };

        AES_CFB_TestVector192_1BIT = {
          plainText: "0110101111000001",
          key: [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: "1001001101011001"
        };

        AES_CFB_TestVector256_1BIT = {
          plainText: "0110101111000001",
          key: [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
          IV: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: "1001000000101001"
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


  QUnit.test("AES_CFB constructor", (assert) =>
  {
    let aes_CFB: TS.Security.AES_CFB;

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(null, [], 8);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(undefined, [], 8);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB([], [], 8);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33.slice(0, 15), [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33.slice(0, 17), [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33.slice(0, 23), [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33.slice(0, 25), [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33.slice(0, 31), [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray33, [], 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, null, 8);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, undefined, 8);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, [], 8);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray33.slice(0, 15), 8);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'initialisationVector' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, numberArray16, 8);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'initialisationVector' which is not an unsigned byte value array.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, -1);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a invalid 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, 0);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'segmentSizeInBit' value which is outside the allowed range as argument.");

    assert.throws(() =>
    {
      aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, 129);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'segmentSizeInBit' value which is outside the allowed range as argument.");

    aes_CFB = new TS.Security.AES_CFB(unsignedByteValueArray16, unsignedByteValueArray16, 8);
    assert.ok(TS.Utils.Assert.isObject(aes_CFB), "Should pass for a call with valid arguments.");
  });


  QUnit.test("AES_CFB encrypt", (assert) =>
  {
    let aes_CFB: TS.Security.AES_CFB;
    let index: number;
    let cipherText: Array<number> | string;

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector128_8BIT.key, AES_CFB_TestVector128_8BIT.IV, 8);
    cipherText = aes_CFB.encrypt((AES_CFB_TestVector128_8BIT.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CFB_TestVector128_8BIT.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector192_8BIT.key, AES_CFB_TestVector192_8BIT.IV, 8);
    cipherText = aes_CFB.encrypt((AES_CFB_TestVector192_8BIT.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CFB_TestVector192_8BIT.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector256_8BIT.key, AES_CFB_TestVector256_8BIT.IV, 8);
    cipherText = aes_CFB.encrypt((AES_CFB_TestVector256_8BIT.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_CFB_TestVector256_8BIT.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector128_1BIT.key, AES_CFB_TestVector128_1BIT.IV, 1);
    cipherText = aes_CFB.encryptBitString((AES_CFB_TestVector128_1BIT.plainText as string));
    assert.equal(cipherText, AES_CFB_TestVector128_1BIT.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector192_1BIT.key, AES_CFB_TestVector192_1BIT.IV, 1);
    cipherText = aes_CFB.encryptBitString((AES_CFB_TestVector192_1BIT.plainText as string));
    assert.equal(cipherText, AES_CFB_TestVector192_1BIT.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector256_1BIT.key, AES_CFB_TestVector256_1BIT.IV, 1);
    cipherText = aes_CFB.encryptBitString((AES_CFB_TestVector256_1BIT.plainText as string));
    assert.equal(cipherText, AES_CFB_TestVector256_1BIT.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");

  });


  QUnit.test("AES_CFB decrypt", (assert) =>
  {
    var aes_CFB: TS.Security.AES_CFB;
    var plainText: Array<number> | string;

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector128_8BIT.key, AES_CFB_TestVector128_8BIT.IV, 8);
    plainText = aes_CFB.decrypt((AES_CFB_TestVector128_8BIT.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CFB_TestVector128_8BIT.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector192_8BIT.key, AES_CFB_TestVector192_8BIT.IV, 8);
    plainText = aes_CFB.decrypt((AES_CFB_TestVector192_8BIT.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CFB_TestVector192_8BIT.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector256_8BIT.key, AES_CFB_TestVector256_8BIT.IV, 8);
    plainText = aes_CFB.decrypt((AES_CFB_TestVector256_8BIT.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_CFB_TestVector256_8BIT.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector128_1BIT.key, AES_CFB_TestVector128_1BIT.IV, 1);
    plainText = aes_CFB.decryptBitString((AES_CFB_TestVector128_1BIT.cipherText as string));
    assert.equal(plainText, AES_CFB_TestVector128_1BIT.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector192_1BIT.key, AES_CFB_TestVector192_1BIT.IV, 1);
    plainText = aes_CFB.decryptBitString((AES_CFB_TestVector192_1BIT.cipherText as string));
    assert.equal(plainText, AES_CFB_TestVector192_1BIT.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");

    aes_CFB = new TS.Security.AES_CFB(AES_CFB_TestVector256_1BIT.key, AES_CFB_TestVector256_1BIT.IV, 1);
    plainText = aes_CFB.decryptBitString((AES_CFB_TestVector256_1BIT.cipherText as string));
    assert.equal(plainText, AES_CFB_TestVector256_1BIT.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");

  });


  QUnit.test("AES_CFB_Stream constructor", (assert) =>
  {
    var onNextData: (bitString: string) => void;
    var onClosed: () => void;
    var onError: (exception: TS.Exception) => void;
    var aes_CFB_Stream: TS.Security.AES_CFB_Stream;

    onNextData = (bitString: string) => { };
    onClosed = () => { };
    onError = (exception: TS.Exception) => { };

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(null, [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(undefined, [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream([], [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33.slice(0, 15), [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33.slice(0, 17), [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33.slice(0, 23), [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33.slice(0, 25), [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33.slice(0, 31), [], 8, TS.Security.CipherOperationEnum.ENCRYPT,  onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray33, [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, null, 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, undefined, 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, [], 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'initialisationVector' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray33.slice(0, 15), 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'initialisationVector' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, numberArray16, 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'initialisationVector' which is not an unsigned byte value array.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, null, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, undefined, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, -1, TS.Security.CipherOperationEnum.ENCRYPT,  onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a invalid 'segmentSizeInBit' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 0, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'segmentSizeInBit' value which is outside the allowed range as argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 129, TS.Security.CipherOperationEnum.ENCRYPT,  onNextData, onClosed, onError);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'segmentSizeInBit' value which is outside the allowed range as argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, null, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, undefined, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, -1, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, 2, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, 0.75, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with an invalid value for the 'cipherOperation' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, null, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, undefined, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, null, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onClosed' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, undefined, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onClosed' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onError' argument.");

    assert.throws(() =>
    {
      aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 128, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'onError' argument.");

    aes_CFB_Stream = new TS.Security.AES_CFB_Stream(unsignedByteValueArray16, unsignedByteValueArray16, 8, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    assert.ok(TS.Utils.Assert.isObject(aes_CFB_Stream), "Should pass for a call with valid arguments.");

  });


  QUnit.test("AES_CFB_Stream write (async stream encrypt)", (assert) =>
  {
    let oneBit = 1;
    let eightBit = 8;

    let aes_CFB_Stream128_1BIT: TS.Security.AES_CFB_Stream;
    let aes_CFB_Stream192_1BIT: TS.Security.AES_CFB_Stream;
    let aes_CFB_Stream256_1BIT: TS.Security.AES_CFB_Stream;
    let aes_CFB_Stream128_8BIT: TS.Security.AES_CFB_Stream;
    let aes_CFB_Stream192_8BIT: TS.Security.AES_CFB_Stream;
    let aes_CFB_Stream256_8BIT: TS.Security.AES_CFB_Stream;
    let cipherText128_1BIT: string;
    let cipherText192_1BIT: string;
    let cipherText256_1BIT: string;
    let cipherText128_8BIT: string;
    let cipherText192_8BIT: string;
    let cipherText256_8BIT: string;
    let asyncDone128_1BIT: () => void;
    let asyncDone192_1BIT: () => void;
    let asyncDone256_1BIT: () => void;
    let asyncDone128_8BIT: () => void;
    let asyncDone192_8BIT: () => void;
    let asyncDone256_8BIT: () => void;


    //****************//
    // 128 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone128_1BIT = assert.async();
    cipherText128_1BIT = "";

    aes_CFB_Stream128_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector128_1BIT.key, AES_CFB_TestVector128_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.ENCRYPT,
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText128_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText128_1BIT, AES_CFB_TestVector128_1BIT.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
    );

    aes_CFB_Stream128_1BIT.writeBitString((AES_CFB_TestVector128_1BIT.plainText as string));
    aes_CFB_Stream128_1BIT.close();


    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone128_8BIT = assert.async();
    cipherText128_8BIT = "";

    aes_CFB_Stream128_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector128_8BIT.key, AES_CFB_TestVector128_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.ENCRYPT,
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText128_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText128_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector128_8BIT.cipherText as Array<number>)), "The encrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    aes_CFB_Stream128_8BIT.writeByteArray((AES_CFB_TestVector128_8BIT.plainText as Array<number>));
    aes_CFB_Stream128_8BIT.close();

    //****************//
    // 192 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone192_1BIT = assert.async();
    cipherText192_1BIT = "";

    aes_CFB_Stream192_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector192_1BIT.key, AES_CFB_TestVector192_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.ENCRYPT,
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText192_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText192_1BIT, AES_CFB_TestVector192_1BIT.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    aes_CFB_Stream192_1BIT.writeBitString((AES_CFB_TestVector192_1BIT.plainText as string));
    aes_CFB_Stream192_1BIT.close();

    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone192_8BIT = assert.async();
    cipherText192_8BIT = "";

    aes_CFB_Stream192_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector192_8BIT.key, AES_CFB_TestVector192_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.ENCRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText192_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText192_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector192_8BIT.cipherText as Array<number>)), "The encrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    aes_CFB_Stream192_8BIT.writeByteArray((AES_CFB_TestVector192_8BIT.plainText as Array<number>));
    aes_CFB_Stream192_8BIT.close();

    //****************//
    // 256 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone256_1BIT = assert.async();
    cipherText256_1BIT = "";

    aes_CFB_Stream256_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector256_1BIT.key, AES_CFB_TestVector256_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.ENCRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText256_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText256_1BIT, AES_CFB_TestVector256_1BIT.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    aes_CFB_Stream256_1BIT.writeBitString((AES_CFB_TestVector256_1BIT.plainText as string));
    aes_CFB_Stream256_1BIT.close();

    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone256_8BIT = assert.async();
    cipherText256_8BIT = "";

    aes_CFB_Stream256_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector256_8BIT.key, AES_CFB_TestVector256_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.ENCRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        cipherText256_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(cipherText256_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector256_8BIT.cipherText as Array<number>)), "The encrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    aes_CFB_Stream256_8BIT.writeByteArray((AES_CFB_TestVector256_8BIT.plainText as Array<number>));
    aes_CFB_Stream256_8BIT.close();

  });


  QUnit.test("AES_CFB_Stream write (async stream decrypt)", (assert) =>
  {
    let oneBit = 1;
    let eightBit = 8;

    let AES_CFB_Stream128_1BIT: TS.Security.AES_CFB_Stream;
    let AES_CFB_Stream192_1BIT: TS.Security.AES_CFB_Stream;
    let AES_CFB_Stream256_1BIT: TS.Security.AES_CFB_Stream;
    let AES_CFB_Stream128_8BIT: TS.Security.AES_CFB_Stream;
    let AES_CFB_Stream192_8BIT: TS.Security.AES_CFB_Stream;
    let AES_CFB_Stream256_8BIT: TS.Security.AES_CFB_Stream;
    let plainText128_1BIT: string;
    let plainText192_1BIT: string;
    let plainText256_1BIT: string;
    let plainText128_8BIT: string;
    let plainText192_8BIT: string;
    let plainText256_8BIT: string;
    let asyncDone128_1BIT: () => void;
    let asyncDone192_1BIT: () => void;
    let asyncDone256_1BIT: () => void;
    let asyncDone128_8BIT: () => void;
    let asyncDone192_8BIT: () => void;
    let asyncDone256_8BIT: () => void;

    //****************//
    // 128 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone128_1BIT = assert.async();
    plainText128_1BIT = "";

    AES_CFB_Stream128_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector128_1BIT.key, AES_CFB_TestVector128_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText128_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText128_1BIT, AES_CFB_TestVector128_1BIT.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream128_1BIT.writeBitString((AES_CFB_TestVector128_1BIT.cipherText as string));
    AES_CFB_Stream128_1BIT.close();


    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone128_8BIT = assert.async();
    plainText128_8BIT = "";

    AES_CFB_Stream128_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector128_8BIT.key, AES_CFB_TestVector128_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText128_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText128_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector128_8BIT.plainText as Array<number>)), "The decrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream128_8BIT.writeByteArray((AES_CFB_TestVector128_8BIT.cipherText as Array<number>));
    AES_CFB_Stream128_8BIT.close();

    //****************//
    // 192 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone192_1BIT = assert.async();
    plainText192_1BIT = "";

    AES_CFB_Stream192_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector192_1BIT.key, AES_CFB_TestVector192_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText192_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText192_1BIT, AES_CFB_TestVector192_1BIT.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream192_1BIT.writeBitString((AES_CFB_TestVector192_1BIT.cipherText as string));
    AES_CFB_Stream192_1BIT.close();

    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone192_8BIT = assert.async();
    plainText192_8BIT = "";

    AES_CFB_Stream192_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector192_8BIT.key, AES_CFB_TestVector192_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText192_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText192_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector192_8BIT.plainText as Array<number>)), "The decrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream192_8BIT.writeByteArray((AES_CFB_TestVector192_8BIT.cipherText as Array<number>));
    AES_CFB_Stream192_8BIT.close();

    //****************//
    // 256 Bit Key    //
    //****************//

    //**********************//
    // 1 Bit segment length //
    //**********************//
    asyncDone256_1BIT = assert.async();
    plainText256_1BIT = "";

    AES_CFB_Stream256_1BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector256_1BIT.key, AES_CFB_TestVector256_1BIT.IV, oneBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText256_1BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText256_1BIT, AES_CFB_TestVector256_1BIT.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256_1BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream256_1BIT.writeBitString((AES_CFB_TestVector256_1BIT.cipherText as string));
    AES_CFB_Stream256_1BIT.close();

    //**********************//
    // 8 Bit segment length //
    //**********************//
    asyncDone256_8BIT = assert.async();
    plainText256_8BIT = "";

    AES_CFB_Stream256_8BIT = new TS.Security.AES_CFB_Stream(AES_CFB_TestVector256_8BIT.key, AES_CFB_TestVector256_8BIT.IV, eightBit, TS.Security.CipherOperationEnum.DECRYPT, 
      //onSegmentComplete
      (binaryString: string) =>
      {
        plainText256_8BIT += binaryString;
      },
      //onClosed
      () =>
      {
        assert.equal(plainText256_8BIT, TS.Utils.byteArrayToBitString((AES_CFB_TestVector256_8BIT.plainText as Array<number>)), "The decrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256_8BIT();
      },
      //onError
      (exception: TS.Exception) =>
      {
        throw exception;
      }
      );
    AES_CFB_Stream256_8BIT.writeByteArray((AES_CFB_TestVector256_8BIT.cipherText as Array<number>));
    AES_CFB_Stream256_8BIT.close();
  });


}//END namespace 