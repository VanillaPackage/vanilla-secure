<?php

namespace Rentalhost\VanillaSecure;

use Rentalhost\VanillaResult\Result;
use PHPUnit_Framework_TestCase;

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
        $secure = new Secure("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd");

        $publicKeyTimestamp = time();
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp);

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp);

        $this->assertInstanceOf(Result::class, $validationResult);
        $this->assertTrue($validationResult->isSuccess());
        $this->assertSame("success", $validationResult->getMessage());
    }

    /**
     * Test with additional data.
     */
    public function testAdditionalData()
    {
        $secure = new Secure("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd");

        $publicKeyTimestamp = time();
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestamp, [ "userId" => 1 ]);

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp, [ "userId" => 1 ]);

        $this->assertTrue($validationResult->isSuccess());
        $this->assertSame("success", $validationResult->getMessage());

        $validationResult = $secure->validate($publicKey, $publicKeyTimestamp, [ "userId" => 2 ]);

        $this->assertFalse($validationResult->isSuccess());
        $this->assertSame("fail:key.invalid", $validationResult->getMessage());
    }

    /**
     * Test fails.
     * @covers Rentalhost\VanillaSecure\Secure::generate
     * @covers Rentalhost\VanillaSecure\Secure::validate
     */
    public function testFails()
    {
        $secure = new Secure("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd");

        // Timestamp invalid.
        $publicKey = $secure->generate();
        $validationResult = $secure->validate($publicKey, "fail:timestamp.invalid");

        $this->assertFalse($validationResult->isSuccess());
        $this->assertSame("fail:timestamp.invalid", $validationResult->getMessage());

        // Timestamp invalid.
        $validationResult = $secure->validate("invalid", time());

        $this->assertFalse($validationResult->isSuccess());
        $this->assertSame("fail:key.invalid", $validationResult->getMessage());
    }

    /**
     * Test private key.
     * @covers Rentalhost\VanillaSecure\Secure::setPrivateKey
     * @covers Rentalhost\VanillaSecure\Secure::getPrivateKey
     */
    public function testPrivateKey()
    {
        $secure = new Secure("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd");
        $this->assertSame("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd", $secure->getPrivateKey());

        $secure->setPrivateKey("ddddddddddccccccccccbbbbbbbbbbaaaaaaaaaa");
        $this->assertSame("ddddddddddccccccccccbbbbbbbbbbaaaaaaaaaa", $secure->getPrivateKey());
    }

    /**
     * Test delay.
     * @covers Rentalhost\VanillaSecure\Secure::setDelay
     * @covers Rentalhost\VanillaSecure\Secure::getDelay
     */
    public function testDelay()
    {
        $secure = new Secure("aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd", 5);

        $this->assertSame(5, $secure->getDelay());

        $publicKeyTimestamp = time();
        $publicKeyTimestampDelayedDown = $publicKeyTimestamp - 10;
        $publicKeyTimestampDelayedUp = $publicKeyTimestamp + 10;

        // Delayed down.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedDown);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedDown);

        $this->assertFalse($validationResult->isSuccess());
        $this->assertSame("fail:timestamp.delayed", $validationResult->getMessage());
        $this->assertSame([ "delay" => -10 ], $validationResult->getData());

        // Delayed up.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedUp);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedUp);

        $this->assertFalse($validationResult->isSuccess());
        $this->assertSame("fail:timestamp.delayed", $validationResult->getMessage());
        $this->assertSame([ "delay" => 10 ], $validationResult->getData());

        // Acceptable delay.
        $secure->setDelay(15);

        // Delayed down.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedDown);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedDown);

        $this->assertTrue($validationResult->isSuccess());
        $this->assertSame("success", $validationResult->getMessage());

        // Delayed up.
        $publicKey = $secure->generateFromTimestamp($publicKeyTimestampDelayedUp);
        $validationResult = $secure->validate($publicKey, $publicKeyTimestampDelayedUp);

        $this->assertTrue($validationResult->isSuccess());
        $this->assertSame("success", $validationResult->getMessage());
    }
}
