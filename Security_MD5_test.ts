/// <reference path="_references.ts" />

namespace TS_Security_test
{
  let MD5_TestVector1: DATA.TestVector;
  let MD5_TestVector2: DATA.TestVector;
  let MD5_TestVector3: DATA.TestVector;
  let MD5_TestVector4: DATA.TestVector;
  let MD5_TestVector5: DATA.TestVector;
  let MD5_TestVector6: DATA.TestVector;
  let MD5_TestVector7: DATA.TestVector;

  QUnit.module("TS.Security.MD5",
    {
      //
      // Test vectors as described in IETF PUB RFC 1321, https://www.ietf.org/rfc/rfc1321.txt
      // 

      before: function ()
      {
        MD5_TestVector1 =
          {
            plainText: "",
            key: [],
            cipherText: "d41d8cd98f00b204e9800998ecf8427e"
          };

        MD5_TestVector2 =
          {
            plainText: "a",
            key: [],
            cipherText: "0cc175b9c0f1b6a831c399e269772661"
          };

        MD5_TestVector3 =
          {
          plainText: "abc",
            key: [],
            cipherText: "900150983cd24fb0d6963f7d28e17f72"
          };

        MD5_TestVector4 =
          {
          plainText: "message digest",
            key: [],
            cipherText: "f96b697d7cb7938d525a2f31aaf161d0"
          };

        MD5_TestVector5 =
          {
          plainText: "abcdefghijklmnopqrstuvwxyz",
            key: [],
            cipherText: "c3fcd3d76192e4007dfb496cca67e13b"
          };

        MD5_TestVector6 =
          {
          plainText: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            key: [],
            cipherText: "d174ab98d277d9f5a5611c2c9f419d9f"
          };

        MD5_TestVector7 =
          {
          plainText: "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            key: [],
            cipherText: "57edf4a22be3c955ac49da2e2107b67a"
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

  QUnit.test("MD5", (assert) =>
  {
    let result: string;

    result = TS.Security.MD5.encrypt(MD5_TestVector1.plainText);
    assert.equal(result, MD5_TestVector1.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector2.plainText);
    assert.equal(result, MD5_TestVector2.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector3.plainText);
    assert.equal(result, MD5_TestVector3.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector4.plainText);
    assert.equal(result, MD5_TestVector4.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector5.plainText);
    assert.equal(result, MD5_TestVector5.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector6.plainText);
    assert.equal(result, MD5_TestVector6.cipherText, "Should return the expected result.");

    result = TS.Security.MD5.encrypt(MD5_TestVector7.plainText);
    assert.equal(result, MD5_TestVector7.cipherText, "Should return the expected result.");
  });
}
