<?php

/**
 * Class LSSodium
 */
class LSSodium
{
    public $bLibraryExists = false;
    protected $key = null;
    // static nonce, only used for fallback decryption
    protected $nonce = null;

    public function init()
    {
        require_once Yii::app()->basePath . '/../vendor/paragonie/sodium_compat/src/Compat.php';
        require_once Yii::app()->basePath . '/../vendor/paragonie/sodium_compat/src/Core/Util.php';
        require_once Yii::app()->basePath . '/../vendor/paragonie/sodium_compat/autoload.php';

        // set availability of sodium library
        // this is a public property and referenced elsewhere
        $this->bLibraryExists = function_exists('sodium_crypto_sign_open') === true;

        if ($this->bLibraryExists === false) {
            /*throw new SodiumException(sprintf(gT("This operation uses data encryption functions which require Sodium library to be installed, but library was not found. If you don't want to use data encryption, you have to disable encryption in attribute settings. Here is a link to the manual page:
            %s", 'unescaped'), 'https://manual.limesurvey.org/Data_encryption#Errors'));*/
        } else {
            // get existing key from config, default is empty string
            $key = Yii::app()->getConfig('encryptionsecretboxkey');
            // if the key is empty, generate a new one
            if (empty($key)) {
                $this->generateEncryptionKeys();
            }
            // use existing key
            else {
                $this->key = ParagonIE_Sodium_Compat::hex2bin((string) $key);

                // load static nonce if exists in config in order to use for fallback decryption, otherwise null
                $nonce = Yii::app()->getConfig('encryptionnonce');
                $this->nonce = empty($nonce) ? null : ParagonIE_Sodium_Compat::hex2bin((string) $nonce);
            }
        }
    }

    /**
     * Encrypt input data using AES256 CBC encryption
     * @param string $plaintext Data to encrypt. Could be a string or a serializable PHP object
     * @return string Return concatenated hex representation of random nonce and ciphertext
     * @throws SodiumException
     */
    public function encrypt($plaintext): string
    {
        if ($this->bLibraryExists === true) {
            if (isset($plaintext) && $plaintext !== "") {

                // old encryption method retained for testing
                // return base64_encode(
                //     ParagonIE_Sodium_Compat::crypto_secretbox(
                //         (string) $plaintext,
                //         $this->nonce,
                //         $this->key
                //     )
                // );

                // generate a random nonce
                $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);
                // encrypt plaintext with key and nonce
                $ciphertext = ParagonIE_Sodium_Compat::crypto_secretbox(
                    (string) $plaintext,
                    $nonce,
                    $this->key
                );
                // concatenate random nonce and cipher text as hex
                return ParagonIE_Sodium_Compat::bin2hex($nonce) . ParagonIE_Sodium_Compat::bin2hex($ciphertext);
            }
            return '';
        }
        return $plaintext;
    }

    /**
     *
     * Decrypt encrypted string.
     * @param string $sEncryptedString Encrypted string to decrypt, if it string 'null', didn't try to decode
     * @param bool $bReturnFalseIfError false by default. If TRUE, return false in case of error (bad decryption). Else, return given $encryptedInput value
     * @return string Return decrypted value (string or unsezialized object) if suceeded. Return FALSE if an error occurs (bad password/salt given) or inpyt encryptedString
     * @throws SodiumException
     */
    public function decrypt($sEncryptedString, $bReturnFalseIfError = false): string
    {
        if ($this->bLibraryExists === true) {
            if (!empty($sEncryptedString) && $sEncryptedString !== 'null') {
                // assume decryption is not possible
                $plaintext = false;
                // minimum length (assuming empty message) is size of nonce
                // plus the size of the authentication tag
                $minLength = (
                    ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES +
                    ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_MACBYTES
                );
                // attempt to decrypt string with the old method of using
                // a static nonce and base 64 encoding
                if ($this->nonce !== null) {
                    $plaintext = ParagonIE_Sodium_Compat::crypto_secretbox_open(
                        base64_decode($sEncryptedString),
                        $this->nonce,
                        $this->key
                    );
                }
                // fall through to new method
                // if plaintext is still false, static nonce decryption failed
                // also check that encrypted string is of sufficient length to
                // contain at minimum the random nonce and authentication tag
                // split the string into nonce and cipher text then decrypt
                if ($plaintext === false && strlen($sEncryptedString) >= $minLength) {
                    $nonceAndCipherText = ParagonIE_Sodium_Compat::hex2bin($sEncryptedString);
                    $nonce = substr($nonceAndCipherText, 0, ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);
                    $ciphertext = substr($nonceAndCipherText, ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);
                    $plaintext = ParagonIE_Sodium_Compat::crypto_secretbox_open(
                        $ciphertext,
                        $nonce,
                        $this->key
                    );
                }
                // neither method worked, error
                if ($plaintext === false) {
                    throw new SodiumException(sprintf(gT("Wrong decryption key! Decryption key has changed since this data were last saved, so data can't be decrypted. Please consult our manual at %s.", 'unescaped'), 'https://manual.limesurvey.org/Data_encryption#Errors'));
                } else {
                    return $plaintext;
                }
            }
            return '';
        }
        return $sEncryptedString;
    }

    /**
     *
     * Write encryption key to version.php config file
     * @throws Exception
     * @return void
     */
    protected function generateEncryptionKeys()
    {
        // generate new key
        $newKeyBin = ParagonIE_Sodium_Compat::crypto_secretbox_keygen();
        $newKeyHex = ParagonIE_Sodium_Compat::bin2hex($newKeyBin);
        // update app config
        Yii::app()->setConfig("encryptionsecretboxkey", $newKeyHex);
        // set class property
        $this->key = $newKeyBin;
        // generate config for security.php
        $sConfig = "<?php if (!defined('BASEPATH')) exit('No direct script access allowed');" . "\n"
            . "/*" . "\n"
            . " * LimeSurvey" . "\n"
            . " * Copyright (C) 2007-2019 The LimeSurvey Project Team / Carsten Schmitz" . "\n"
            . " * All rights reserved." . "\n"
            . " * License: GNU/GPL License v3 or later, see LICENSE.php" . "\n"
            . " * LimeSurvey is free software. This version may have been modified pursuant" . "\n"
            . " * to the GNU General Public License, and as distributed it includes or" . "\n"
            . " * is derivative of works licensed under the GNU General Public License or" . "\n"
            . " * other free or open source software licenses." . "\n"
            . " * See COPYRIGHT.php for copyright notices and details." . "\n"
            . " */" . "\n"
            . "\n"
            . "/*" . "\n"
            . "WARNING!!!" . "\n"
            . "ONCE SET, ENCRYPTION KEYS SHOULD NEVER BE CHANGED, OTHERWISE ALL ENCRYPTED DATA COULD BE LOST !!!" . "\n"
            . "\n"
            . "*/" . "\n"
            . "\n"
            . "\$config = array();" . "\n";
        // persist new secret to security.php
        $sConfig .= "\$config['encryptionsecretboxkey'] = '" . $newKeyHex. "';" . "\n";
        $sConfig .= "return \$config;\n";
        // write out security.php file
        $configdir = \Yii::app()->getConfig('configdir');
        if (is_writable($configdir)) {
            file_put_contents($configdir . '/security.php', $sConfig);
        } else {
            throw new CHttpException(500, gT("Configuration directory is not writable"));
        }
    }
}
