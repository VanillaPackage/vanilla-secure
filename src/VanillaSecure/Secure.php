<?php

namespace Rentalhost\VanillaSecure;

use Rentalhost\VanillaResult\Result;

class Secure
{
    /**
     * Stores the private key.
     * @var string
     */
    private $privateKey;

    /**
     * Construct a new Secure instance.
     * @param string  $privateKey      Private key.
     */
    public function __construct($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Set a new one private key.
     * @param string $privateKey Private key.
     */
    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Get current private key.
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * Generate a new public key.
     * @param  mixed $data Additional key data.
     * @return Key
     */
    public function generate($data = null)
    {
        return $this->generateFromTimestamp(time(), $data);
    }

    /**
     * Generate a new public key, by passing a own timestamp.
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data Additional key data.
     * @return Key
     */
    public function generateFromTimestamp($timestamp, $data = null)
    {
        return $this->internalGenerator($timestamp, $data);
    }

    /**
     * Validate if public key is valid.
     * @param  string  $key       Key phrase.
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Additional key data.
     * @return Result
     */
    public function validate($key, $timestamp, $data = null)
    {
        // Timestamp is bad-formatted.
        if (!ctype_digit($timestamp) && !is_int($timestamp)) {
            return new Result(false, "fail:timestamp.invalid");
        }

        // Expected key is invalid.
        if (!password_verify($this->internalSerialize($timestamp, $data), $key)) {
            return new Result(false, "fail:key.invalid");
        }

        return new Result(true, "success");
    }

    /**
     * Generate a public key, based on private key.
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Key data.
     * @return string
     */
    private function internalGenerator($timestamp, $data)
    {
        return password_hash($this->internalSerialize($timestamp, $data), PASSWORD_BCRYPT);
    }

    /**
     * Serializes data.
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Key data.
     * @return string
     */
    private function internalSerialize($timestamp, $data)
    {
        return serialize([ $this->privateKey, $timestamp, $data ]);
    }
}
