<?php

namespace Rentalhost\VanillaSecure;

use Rentalhost\VanillaResult\Result;

/**
 * Class Secure
 * @package Rentalhost\VanillaSecure
 */
class Secure
{
    /**
     * Stores the private key.
     * @var string
     */
    private $privateKey;

    /**
     * Stores the limit delay of timestamp.
     * @var integer
     */
    private $delay;

    /**
     * Construct a new Secure instance.
     *
     * @param string  $privateKey Private key.
     * @param integer $delay      Limit delay to timestamp (up or down) in seconds.
     */
    public function __construct($privateKey, $delay = 30)
    {
        $this->privateKey = $privateKey;
        $this->delay = $delay;
    }

    /**
     * Set a new one private key.
     *
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
     * Redefine delay.
     *
     * @param integer $delay Delay.
     */
    public function setDelay($delay)
    {
        $this->delay = $delay;
    }

    /**
     * Get current delay.
     * @return integer
     */
    public function getDelay()
    {
        return $this->delay;
    }

    /**
     * Generate a new public key.
     *
     * @param  mixed $data Additional key data.
     *
     * @return string
     */
    public function generate($data = null)
    {
        return $this->generateFromTimestamp(gmdate('U'), $data);
    }

    /**
     * Generate a new public key, by passing a own timestamp.
     *
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Additional key data.
     *
     * @return string
     */
    public function generateFromTimestamp($timestamp, $data = null)
    {
        return $this->internalGenerator($timestamp, $data);
    }

    /**
     * Validate if public key is valid.
     *
     * @param  string  $key       Key phrase.
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Additional key data.
     *
     * @return Result
     */
    public function validate($key, $timestamp, $data = null)
    {
        // Timestamp is bad-formatted.
        if (!is_int($timestamp) &&
            !ctype_digit($timestamp)
        ) {
            return new Result(false, 'fail:timestamp.invalid');
        }

        // Timestamp was delayed.
        if ($this->delay !== null) {
            $timestampDelay = $timestamp - gmdate('U');
            if (abs($timestampDelay) > $this->delay) {
                return new Result(false, 'fail:timestamp.delayed', [ 'delay' => $timestampDelay ]);
            }
        }

        // Expected key is invalid.
        if (!password_verify($this->internalHash($timestamp, $data), $key)) {
            return new Result(false, 'fail:key.invalid');
        }

        return new Result(true, 'success');
    }

    /**
     * Generate a public key, based on private key.
     *
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Key data.
     *
     * @return string
     */
    private function internalGenerator($timestamp, $data)
    {
        return password_hash($this->internalHash($timestamp, $data), PASSWORD_BCRYPT, [ 'cost' => 4 ]);
    }

    /**
     * Hash data using raw SHA512.
     *
     * @param  integer $timestamp Key timestamp.
     * @param  mixed   $data      Key data.
     *
     * @return string
     */
    private function internalHash($timestamp, $data)
    {
        return hash('SHA512', serialize([ $this->privateKey, $timestamp, $data ]), true);
    }
}
