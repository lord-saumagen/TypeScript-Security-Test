/// <reference path="_references.ts" />

namespace TS_Security_test
{
  let numberArray16: Array<number>;
  let unsignedByteValueArray16: Array<number>;
  let unsignedByteValueArray33: Array<number>;


  QUnit.module("TS.Security.RandomNumberGenerator",
    {
      before: function ()
      {
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


  QUnit.test("RandomNumberGenerator constructor", (assert) =>
  {
    let rng: TS.Security.RandomNumberGenerator;

    rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, unsignedByteValueArray16);
    assert.ok(TS.Utils.Assert.isObject(rng), "Should pass for a call with valid arguments.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(null, unsignedByteValueArray16);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'keyByteArray' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(undefined, unsignedByteValueArray16);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'keyByteArray' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator([], unsignedByteValueArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'keyByteArray' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(numberArray16, unsignedByteValueArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'keyByteArray' which is not an unsigned byte value array.");
    

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16.slice(2), unsignedByteValueArray16);
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'keyByteArray' with a invalid number of elements as argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, null);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a null 'initialisationVector' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, undefined);
    }, TS.ArgumentNullOrUndefinedException, "Should throw a 'TS.ArgumentNullOrUndefinedException' for a undefined 'initialisationVector' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, []);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for an empty 'initialisationVector' argument.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, numberArray16);
    }, TS.InvalidTypeException, "Should throw a 'TS.InvalidTypeException' for a call with a 'initialisationVector' which is not an unsigned byte value array.");

    assert.throws(() =>
    {
      rng = new TS.Security.RandomNumberGenerator(unsignedByteValueArray16, unsignedByteValueArray16.slice(2));
    }, TS.ArgumentOutOfRangeException, "Should throw a 'TS.ArgumentOutOfRangeException' for a 'initialisationVector' with a invalid number of elements as argument.");

  });


  QUnit.test("RandomNumberGenerator next", (assert) =>
  {
    let rng: TS.Security.RandomNumberGenerator;
    let key: Array<number>;
    let next: Array<number>;
    let resultArray: Array<Array<number>>;
    let index: number;

    key = TS.Encoding.UTF.UTF16StringToUTF8Array("abcdefghijklmnop");

    rng = new TS.Security.RandomNumberGenerator(key, unsignedByteValueArray16);
    resultArray = new Array<Array<number>>();

    for (index = 0; index < 200; index++)
    {
      next = rng.next;

      if (resultArray.filter((value) =>
      {
        return value.every((_value, index) =>
        {
          return _value == next[index];
        });
      }).length == 0)
      {
        assert.ok(true, "Unique random number: '" + next.join("|") + "'");
      }//END if
      else
      {
        assert.ok(false, "Random number collision: '" + next.join("|") + "'");
      }//END else

      resultArray.push(next);

    }//END for

  });

}//END namespace 