/// <reference path="_references.ts" />

namespace TS_Security_test
{
  let PBKDF2_ITER1_LEN20: DATA.IPBKDFTestVector;
  let PBKDF2_ITER2_LEN20: DATA.IPBKDFTestVector;
  let PBKDF2_ITER4096_LEN20: DATA.IPBKDFTestVector;
  let PBKDF2_ITER16777216_LEN20: DATA.IPBKDFTestVector;
  let PBKDF2_ITER4096_LEN25: DATA.IPBKDFTestVector;
  let PBKDF2_ITER4096_LEN16: DATA.IPBKDFTestVector;

  4096 
  QUnit.module("TS.Security.PBKDF2",
    {
      before: function ()
      {
        //
        // Test vectors as described in RFC 6070, https://www.ietf.org/rfc/rfc6070.txt
        // 

        PBKDF2_ITER1_LEN20 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("password"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("salt"),
          iterations: 1,
          derivedKeyLength: 20,
          cipherText: [0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]
        };

        PBKDF2_ITER2_LEN20 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("password"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("salt"),
          iterations: 2,
          derivedKeyLength: 20,
          cipherText: [0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57]
        };

        PBKDF2_ITER4096_LEN20 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("password"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("salt"),
          iterations: 4096,
          derivedKeyLength: 20,
          cipherText: [0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1]
        };

        PBKDF2_ITER4096_LEN25 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("passwordPASSWORDpassword"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
          iterations: 4096,
          derivedKeyLength: 25,
          cipherText: [0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38]
        };

        PBKDF2_ITER4096_LEN16 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("pass" + String.fromCharCode(0) + "word"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("sa" + String.fromCharCode(0) + "lt"),
          iterations: 4096,
          derivedKeyLength: 16,
          cipherText: [0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3]
        };

        PBKDF2_ITER16777216_LEN20 = {
          key: TS.Encoding.UTF.UTF16StringToUTF8Array("password"),
          plainText: TS.Encoding.UTF.UTF16StringToUTF8Array("salt"),
          iterations: 16777216,
          derivedKeyLength: 20,
          cipherText: [0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84]
        };

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

  QUnit.test("PBKDF2_HMAC_SHA1", (assert) =>
  {
    let resultArr: Array<number>;

    resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER1_LEN20.key, (PBKDF2_ITER1_LEN20.plainText as Array<number>), PBKDF2_ITER1_LEN20.iterations, PBKDF2_ITER1_LEN20.derivedKeyLength);
    assert.deepEqual(resultArr, PBKDF2_ITER1_LEN20.cipherText, "Should return the expected espanded key.");

    resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER2_LEN20.key, (PBKDF2_ITER2_LEN20.plainText as Array<number>), PBKDF2_ITER2_LEN20.iterations, PBKDF2_ITER2_LEN20.derivedKeyLength);
    assert.deepEqual(resultArr, PBKDF2_ITER2_LEN20.cipherText, "Should return the expected espanded key.");

    resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER4096_LEN20.key, (PBKDF2_ITER4096_LEN20.plainText as Array<number>), PBKDF2_ITER4096_LEN20.iterations, PBKDF2_ITER4096_LEN20.derivedKeyLength);
    assert.deepEqual(resultArr, PBKDF2_ITER4096_LEN20.cipherText, "Should return the expected espanded key.");

    resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER4096_LEN25.key, (PBKDF2_ITER4096_LEN25.plainText as Array<number>), PBKDF2_ITER4096_LEN25.iterations, PBKDF2_ITER4096_LEN25.derivedKeyLength);
    assert.deepEqual(resultArr, PBKDF2_ITER4096_LEN25.cipherText, "Should return the expected espanded key.");

    resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER4096_LEN16.key, (PBKDF2_ITER4096_LEN16.plainText as Array<number>), PBKDF2_ITER4096_LEN16.iterations, PBKDF2_ITER4096_LEN16.derivedKeyLength);
    assert.deepEqual(resultArr, PBKDF2_ITER4096_LEN16.cipherText, "Should return the expected espanded key.");

    //
    //Kills your browser. 
    //
    //resultArr = TS.Security.PBKDF2_HMAC_SHA1(PBKDF2_ITER16777216_LEN20.key, (PBKDF2_ITER16777216_LEN20.plainText as Array<number>), PBKDF2_ITER16777216_LEN20.iterations, PBKDF2_ITER16777216_LEN20.derivedKeyLength);
    //assert.deepEqual(resultArr, PBKDF2_ITER16777216_LEN20.cipherText, "Should return the expected espanded key.");
  });
}
