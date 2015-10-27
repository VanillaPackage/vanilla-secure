<?php

namespace Rentalhost\VanillaSecure;

use PHPUnit_Framework_TestCase;
use Rentalhost\VanillaResult\Result;

/**
 * Class SecureTest
 * @package Rentalhost\VanillaSecure
 */
class SecureTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test success.
     * @covers Rentalhost\VanillaSecure\Secure::__construct
     * @covers Rentalhost\VanillaSecure\Secure::generateFromTimestamp
     * @covers Rentalhost\VanillaSecure\Secure::validate
     * @covers Rentalhost\VanillaSecure\Secure::internalGenerator
     * @covers Rentalhost\VanillaSecure\Secure::internalHash
     */
    public function testSuccess()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd');

        $publicKeyTimestamp = gmdate('U');
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp);

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp);

        static::assertInstanceOf(Result::class, $validationResult);
        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());
    }

    /**
     * Test with additional data.
     */
    public function testAdditionalData()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd');

        $publicKeyTimestamp = gmdate('U');
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp, [ 'userId' => 1 ]);

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp, [ 'userId' => 1 ]);

        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp, [ 'userId' => 2 ]);

        static::assertFalse($validationResult->isSuccess());
        static::assertSame('fail:key.invalid', $validationResult->getMessage());
    }

    /**
     * Test fails.
     * @covers Rentalhost\VanillaSecure\Secure::generate
     * @covers Rentalhost\VanillaSecure\Secure::validate
     */
    public function testFails()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd');

        // Timestamp invalid.
        $publicKey = $secure->generate();
        $validationResult = $secure->validate($publicKey, 'fail:timestamp.invalid');

        static::assertFalse($validationResult->isSuccess());
        static::assertSame('fail:timestamp.invalid', $validationResult->getMessage());

        // Timestamp invalid.
        $validationResult = $secure->validate('invalid', gmdate('U'));

        static::assertFalse($validationResult->isSuccess());
        static::assertSame('fail:key.invalid', $validationResult->getMessage());
    }

    /**
     * Test private key.
     * @covers Rentalhost\VanillaSecure\Secure::setPrivateKey
     * @covers Rentalhost\VanillaSecure\Secure::getPrivateKey
     */
    public function testPrivateKey()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd');
        static::assertSame('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd', $secure->getPrivateKey());

        $secure->setPrivateKey('ddddddddddccccccccccbbbbbbbbbbaaaaaaaaaa');
        static::assertSame('ddddddddddccccccccccbbbbbbbbbbaaaaaaaaaa', $secure->getPrivateKey());
    }

    /**
     * Test delay.
     * @covers Rentalhost\VanillaSecure\Secure::validate
     * @covers Rentalhost\VanillaSecure\Secure::setDelay
     * @covers Rentalhost\VanillaSecure\Secure::getDelay
     */
    public function testDelay()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd', 5);

        static::assertSame(5, $secure->getDelay());

        $publicKeyTimestamp = (int) gmdate('U');
        $publicKeyTimestampDelayedDown = $publicKeyTimestamp - 10;
        $publicKeyTimestampDelayedUp = $publicKeyTimestamp + 10;

        // Delayed down.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedDown);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedDown);

        static::assertFalse($validationResult->isSuccess());
        static::assertSame('fail:timestamp.delayed', $validationResult->getMessage());
        static::assertSame([ 'delay' => -10 ], $validationResult->getData());

        // Delayed up.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedUp);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedUp);

        static::assertFalse($validationResult->isSuccess());
        static::assertSame('fail:timestamp.delayed', $validationResult->getMessage());
        static::assertSame([ 'delay' => 10 ], $validationResult->getData());

        // Acceptable delay.
        $secure->setDelay(15);

        // Delayed down.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedDown);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedDown);

        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());

        // Delayed up.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedUp);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedUp);

        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());

        // Unlimited delay.
        $secure->setDelay(null);

        // Delayed down.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedDown);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedDown);

        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());

        // Delayed up.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedUp);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedUp);

        static::assertTrue($validationResult->isSuccess());
        static::assertSame('success', $validationResult->getMessage());
    }

    /**
     * Test string x integer private key.
     * @covers Rentalhost\VanillaSecure\Secure::validate
     */
    public function testStringCrossIntegerPrivateKey()
    {
        $secure = new Secure(12345, null);

        // Generate based on integer private key.
        $publicKeyTimestamp = time();
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp);

        // Test based on string private key.
        $secure = new Secure('12345', null);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp);

        static::assertTrue($validationResult->isSuccess());
    }

    /**
     * Test string x integer timestamp.
     * @covers Rentalhost\VanillaSecure\Secure::validate
     */
    public function testStringCrossIntegerTimestamp()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd', null);

        // Generate based on string time.
        $publicKeyTimestamp = (string) time();
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp);

        // Test based on integer time.
        $validationResult = $secure->validate($publicKey, (int) $publicKeyTimestamp);

        static::assertTrue($validationResult->isSuccess());
    }

    /**
     * Test falsy vs empty data array.
     * @covers Rentalhost\VanillaSecure\Secure::validate
     */
    public function testFalsyCrossEmptyDataArray()
    {
        $secure = new Secure('aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd', null);

        // Generate based on falsy data.
        $publicKeyTimestamp = time();
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp, null);

        // Test based on empty data array.
        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp, [ ]);

        static::assertTrue($validationResult->isSuccess());
    }
}
