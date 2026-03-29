<?php

namespace NeoSmart\SecureStore;

use Exception;

/**
 * An abstraction over SecureStore password- or key-based decryption
 */
class KeySource
{
    private const MASTER_KEY_LEN = 16 * 2;

    public const TYPE_PASSWORD = 'password';
    public const TYPE_KEY = 'key';

    public string $type;
    public string $value;

    private function __construct(string $type, string $value)
    {
        $this->type = $type;
        $this->value = $value;
    }

    /**
     * Derive decryption keys from the provided password
     */
    public static function fromPassword(string $password): self
    {
        return new self(self::TYPE_PASSWORD, $password);
    }

    /**
     * Load decryption key from a key file.
     * Handles both raw binary and ASCII-armored keys.
     */
    public static function fromFile(string $path): self
    {
        if (!file_exists($path)) {
            throw new Exception("SecureStore encryption key not found: $path");
        }

        $content = file_get_contents($path);
        return KeySource::fromKey($content);
    }

    /**
     * Load decryption key from a raw key.
     * Handles both raw binary and ASCII-armored keys.
     */
    public static function fromKey(array|string $key): self
    {
        // Convert arrays to binary strings
        if (is_array($key)) {
            $key = pack('C*', ...$key);
        }

        if (strlen($key) === self::MASTER_KEY_LEN) {
            // Assume we were provided the raw key
            return new self(self::TYPE_KEY, $key);
        }

        // Check for ASCII-armored (PEM-style) format
        if (strpos($key, '--BEGIN') !== false) {
            if (preg_match('/--+BEGIN.*?KEY--+(.*?)--+END.*?KEY--+/s', $key, $matches)) {
                return new self(self::TYPE_KEY, base64_decode(trim($matches[1])));
            }
        }

        throw new Exception("Invalid SecureStore decryption key provided");
    }
}

/**
 * SecretsManager instances can be used to load and decrypt secrets from SecureStore vaults.
 */
class SecretsManager
{
    private const PBKDF2_ROUNDS = 256000;
    private const AES_ALGO = 'aes-128-cbc';
    private const HMAC_ALGO = 'sha1';
    private const MASTER_KEY_LEN = 16 * 2;

    private array $secrets = [];
    private string $aesKey;
    private string $hmacKey;

    private function __construct(string $aesKey, string $hmacKey, array $secrets)
    {
        $this->aesKey = $aesKey;
        $this->hmacKey = $hmacKey;
        $this->secrets = $secrets;
    }

    /**
     * Load a SecureStore vault, decrypting with the provided password.
     */
    public static function loadWithPassword(string $path, string $password): self
    {
        return self::load($path, KeySource::fromPassword($password));
    }

    /**
     * Load a SecureStore vault, decrypting with a key loaded from the provided path.
     */
    public static function loadWithKeyFile(string $path, string $keyPath): self
    {
        return self::load($path, KeySource::fromFile($keyPath));
    }

    /**
     * Load a SecureStore vault, decrypting with a key loaded from the provided KeySource.
     */
    public static function load(string $path, KeySource $keySource): self
    {
        if (!file_exists($path)) {
            throw new Exception("SecureStore vault not found: $path");
        }

        $data = json_decode(file_get_contents($path), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to parse SecureStore vault JSON.");
        }

        if (($data['version'] ?? 0) !== 3) {
            throw new Exception("Unsupported SecureStore version. This library supports v3.");
        }

        // Derive or load the 36-byte master key
        $masterKey = self::resolveMasterKey($keySource, $data['iv'] ?? null);
        if (strlen($masterKey) != self::MASTER_KEY_LEN) {
            throw new Exception("Invalid key length. Expected " . self::MASTER_KEY_LEN . " bytes.");
        }

        // Split master key (16-byte AES-128 key, 16-byte HMAC-SHA1 key)
        $aesKey = substr($masterKey, 0, 16);
        $hmacKey = substr($masterKey, 16, 16);

        // Verify the correct password was provided via the (optional) sentinel
        if (isset($data['sentinel'])) {
            try {
                self::decryptEntry($data['sentinel'], $aesKey, $hmacKey);
            } catch (Exception $e) {
                throw new Exception("SecureStore load failure: invalid key or password.");
            }
        }

        return new self($aesKey, $hmacKey, $data['secrets'] ?? []);
    }

    /**
     * Retrieve and decrypt a single named secret from the vault.
     * Returns `null` if no such secret exists in the vault.
     */
    public function get(string $name): ?string
    {
        if (!isset($this->secrets[$name])) {
            return null;
        }

        return self::decryptEntry($this->secrets[$name], $this->aesKey, $this->hmacKey);
    }

    /**
     * Retrieve a list of all keys in the vault.
     */
    public function keys(): array
    {
        return array_keys($this->secrets);
    }

    private static function decryptEntry(array $entry, string $aesKey, string $hmacKey): string
    {
        $iv = base64_decode($entry['iv']);
        $mac = base64_decode($entry['hmac']);
        $ciphertext = base64_decode($entry['payload']);

        // Authenticate: HMAC(IV + Ciphertext)
        $computedMac = hash_hmac(self::HMAC_ALGO, $iv . $ciphertext, $hmacKey, true);

        if (!hash_equals($mac, $computedMac)) {
            throw new Exception("Integrity check failed (HMAC mismatch).");
        }

        // Decrypt: AES-128-CBC with PKCS#7 padding (per SecureStore v3 spec)
        $plaintext = openssl_decrypt($ciphertext, self::AES_ALGO, $aesKey, OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            throw new Exception("Secret decryption failed.");
        }

        return $plaintext;
    }

    private static function resolveMasterKey(KeySource $source, ?string $base64Salt): string
    {
        if ($source->type === KeySource::TYPE_KEY) {
            // Keys already provided
            return $source->value;
        }

        // Password-based derivation
        if ($base64Salt === null) {
            throw new Exception("Vault missing root 'iv' (salt) required for password decryption.");
        }

        return hash_pbkdf2(
            self::HMAC_ALGO,
            $source->value,
            base64_decode($base64Salt),
            self::PBKDF2_ROUNDS,
            self::MASTER_KEY_LEN,
            true
        );
    }
}
