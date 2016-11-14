/// <reference path="_references.ts" />

namespace TS_Security_test
{
  let AES_TestVector128: DATA.TestVector;
  let AES_TestVector192: DATA.TestVector;
  let AES_TestVector256: DATA.TestVector;
  let numberArray16: Array<number>;
  let unsignedByteValueArray16: Array<number>;
  let unsignedByteValueArray33: Array<number>;

  QUnit.module("TS.Security.AES",
    {
      before: function ()
      {
        AES_TestVector128 = {
          plainText: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
          key: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
          cipherText: [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
        };

        AES_TestVector192 = {
          plainText: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
          key: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
          cipherText: [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91]
        };

        AES_TestVector256 = {
          plainText: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
          key: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
          cipherText: [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89]
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


  QUnit.test("AES constructor", (assert) =>
  {
    let aes: TS.Security.AES

    assert.throws(() =>
    {
      aes = new TS.Security.AES(null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES(undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for an undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([]);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES(numberArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'keyByteArray' which is not an unsigned byte value array.");
    
    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    assert.throws(() =>
    {
      aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a call with a 'keyByteArray' with an invalid number of arguments.");

    aes = new TS.Security.AES([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert.ok(TS.Utils.Assert.isObject(aes), "Should pass for a call with valid arguments.");

  });


  QUnit.test("AES encrypte", (assert) =>
  {
    let aes: TS.Security.AES;
    let cipherText: Array<number>;
    let plainText: Array<number>;


    aes = new TS.Security.AES(AES_TestVector128.key);
    cipherText = aes.encrypt((AES_TestVector128.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_TestVector128.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");

    aes = new TS.Security.AES(AES_TestVector192.key);
    cipherText = aes.encrypt((AES_TestVector192.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_TestVector192.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");

    aes = new TS.Security.AES(AES_TestVector256.key);
    cipherText = aes.encrypt((AES_TestVector256.plainText as Array<number>));
    assert.deepEqual(cipherText, AES_TestVector256.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");

    assert.throws(() => 
    {
      aes = new TS.Security.AES(AES_TestVector128.key);
      plainText = (AES_TestVector128.plainText as Array<number>).slice();
      plainText.push(1);
      cipherText = aes.encrypt(plainText);
    }, TS.ArgumentException, "The call should fail with a \"TS.ArgumentException\" for a 'data' array with an invalid number of bytes.");

    assert.throws(() => 
    {
      aes = new TS.Security.AES(AES_TestVector128.key);
      cipherText = aes.encrypt([]);
    }, TS.InvalidTypeException, "The call should fail with a \"TS.InvalidTypeException\" for a 'data' argument which is an empty array.");

    assert.throws(() => 
    {
      aes = new TS.Security.AES(AES_TestVector128.key);
      cipherText = aes.encrypt(null);
    }, TS.ArgumentNullOrUndefinedException, "The call should fail with a \"TS.ArgumentNullOrUndefinedException\" for a 'data' argument with a null value.");

    assert.throws(() => 
    {
      aes = new TS.Security.AES(AES_TestVector128.key);
      cipherText = aes.encrypt(undefined);
    }, TS.ArgumentNullOrUndefinedException, "The call should fail with a \"TS.ArgumentNullOrUndefinedException\" for a 'data' argument with an undefined value.");

  });


  QUnit.test("AES decrypt", (assert) =>
  {
    let aes: TS.Security.AES;
    let plainText: Array<number>;

    aes = new TS.Security.AES(AES_TestVector128.key);
    plainText = aes.decrypt((AES_TestVector128.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_TestVector128.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");

    aes = new TS.Security.AES(AES_TestVector192.key);
    plainText = aes.decrypt((AES_TestVector192.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_TestVector192.plainText, "The encrypted text schould match with the test vector for a 192 bit key.");

    aes = new TS.Security.AES(AES_TestVector256.key);
    plainText = aes.decrypt((AES_TestVector256.cipherText as Array<number>));
    assert.deepEqual(plainText, AES_TestVector256.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");

  });


  QUnit.test("AES_Stream constructor", (assert) =>
  {
    let aes_Stream: TS.Security.AES_Stream;
    let onNextData: (bitString: string) => void;
    let onClosed: () => void;
    let onError: (exception: TS.Exception) => void;

    onNextData = (bitString: string) => { };
    onClosed = () => { };
    onError = (exception: TS.Exception) => { };


    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(null, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(undefined, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream([], TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(numberArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'keyByteArray' which is not an unsigned byte value array.");
    
    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, 4, onNextData, onClosed, onError);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an invalid 'cipherOperation' argument.");
    
    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, null, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, undefined, onClosed, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'onNextData' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, null, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onClose' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, undefined, onError);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'onClose' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'onError' argument.");

    assert.throws(() =>
    {
      aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'onError' argument.");

    aes_Stream = new TS.Security.AES_Stream(unsignedByteValueArray16, TS.Security.CipherOperationEnum.ENCRYPT, onNextData, onClosed, onError);
    assert.ok(TS.Utils.Assert.isObject(aes_Stream), "Should pass for a call with valid arguments.");

  });


  QUnit.test("AES_Stream write (async stream encrypt)", (assert) =>
  {
    let aes_Stream128: TS.Security.AES_Stream;
    let aes_Stream192: TS.Security.AES_Stream;
    let aes_Stream256: TS.Security.AES_Stream;
    let aes_StreamFail: TS.Security.AES_Stream;
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

    aes_Stream128 = new TS.Security.AES_Stream(AES_TestVector128.key, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText128 = cipherText128.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText128, AES_TestVector128.cipherText, "The encrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream128.writeByteArray((AES_TestVector128.plainText as Array<number>));
    aes_Stream128.close();

    //****************//
    // 192 Bit Key    //
    //****************//
    cipherText192 = new Array<number>();
    asyncDone192 = assert.async();

    aes_Stream192 = new TS.Security.AES_Stream(AES_TestVector192.key, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText192 = cipherText192.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText192, AES_TestVector192.cipherText, "The encrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream192.writeByteArray((AES_TestVector192.plainText as Array<number>));
    aes_Stream192.close();

    //****************//
    // 256 Bit Key    //
    //****************//
    cipherText256 = new Array<number>();
    asyncDone256 = assert.async();

    aes_Stream256 = new TS.Security.AES_Stream(AES_TestVector256.key, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherText256 = cipherText256.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(cipherText256, AES_TestVector256.cipherText, "The encrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream256.writeByteArray((AES_TestVector256.plainText as Array<number>));
    aes_Stream256.close();

    //****************//
    // Fail           //
    //****************//
    cipherTextFail = new Array<number>();
    asyncDoneFail = assert.async();

    aes_StreamFail = new TS.Security.AES_Stream(AES_TestVector256.key, TS.Security.CipherOperationEnum.ENCRYPT,
      //onData
      (data) =>
      {
        cipherTextFail = cipherTextFail.concat(TS.Utils.bitStringToByteArray(data));
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

    aes_StreamFail.writeByteArray((AES_TestVector256.plainText as Array<number>));
    //Make sure that the stream data doesn't fit into a 128 bit block.
    aes_StreamFail.writeByteArray([0, 0, 0]);
    aes_StreamFail.close();

  });


  QUnit.test("AES_Stream write (async stream decrypt)", (assert) =>
  {
    let aes_Stream128: TS.Security.AES_Stream;
    let aes_Stream192: TS.Security.AES_Stream;
    let aes_Stream256: TS.Security.AES_Stream;
    let aes_StreamFail: TS.Security.AES_Stream;
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

    aes_Stream128 = new TS.Security.AES_Stream(AES_TestVector128.key, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText128 = plainText128.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText128, AES_TestVector128.plainText, "The decrypted text schould match with the test vector for a 128 bit key.");
        asyncDone128();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream128.writeByteArray((AES_TestVector128.cipherText as Array<number>));
    aes_Stream128.close();

    //****************//
    // 192 Bit Key    //
    //****************//
    plainText192 = new Array<number>();
    asyncDone192 = assert.async();

    aes_Stream192 = new TS.Security.AES_Stream(AES_TestVector192.key, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText192 = plainText192.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText192, AES_TestVector192.plainText, "The decrypted text schould match with the test vector for a 192 bit key.");
        asyncDone192();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream192.writeByteArray((AES_TestVector192.cipherText as Array<number>));
    aes_Stream192.close();

    //****************//
    // 256 Bit Key    //
    //****************//
    plainText256 = new Array<number>();
    asyncDone256 = assert.async();

    aes_Stream256 = new TS.Security.AES_Stream(AES_TestVector256.key, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainText256 = plainText256.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        assert.deepEqual(plainText256, AES_TestVector256.plainText, "The decrypted text schould match with the test vector for a 256 bit key.");
        asyncDone256();
      },
      //onError
      (exception) =>
      {
        throw exception;
      });

    aes_Stream256.writeByteArray((AES_TestVector256.cipherText as Array<number>));
    aes_Stream256.close();

    //****************//
    // Fail           //
    //****************//
    plainTextFail = new Array<number>();
    asyncDoneFail = assert.async();

    aes_StreamFail = new TS.Security.AES_Stream(AES_TestVector256.key, TS.Security.CipherOperationEnum.DECRYPT,
      //onData
      (data) =>
      {
        plainTextFail = plainTextFail.concat(TS.Utils.bitStringToByteArray(data));
      },
      //onClose
      () =>
      {
        throw new TS.Exception("Unexpected result. Stream cipher should fail because of a data feed which doesn't match the block length required of the underlying cipher object.");
      },
      //onError
      (exception: TS.Exception) =>
      {
        assert.ok(exception.type == "TS.InvalidOperationException", "Should fail because of an unappropriate data length for the underlying cipher object.");
        asyncDoneFail();
      });

    aes_StreamFail.writeByteArray((AES_TestVector256.cipherText as Array<number>));
    //Make sure that the stream data doesn't fit into a 128 bit block.
    aes_StreamFail.writeByteArray([0, 0, 0]);
    aes_StreamFail.close();

  });

}//END namespace 