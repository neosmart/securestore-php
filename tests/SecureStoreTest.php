<?php

declare(strict_types=1);

namespace NeoSmart\SecureStore\Tests;

use PHPUnit\Framework\TestCase;
use NeoSmart\SecureStore\SecretsManager;
use RuntimeException;
use Exception;

class SecureStoreTest extends TestCase
{
    private const TEST_PASSWORD = 'correct-horse-battery-staple';
    private const TEST_KEY = 'test-label';
    private const TEST_SECRET = 'this-is-a-very-secure-payload';
    private const NEW_LABEL = 'app-api-key';
    private const NEW_SECRET = 'sk_live_51Mabc123';

    private string $tempDir;
    private string $storePath;
    private string $keyPath;

    /**
     * Helper to run ssclient CLI commands using an array of arguments.
     *
     * @param array<string> $args
     * @throws RuntimeException
     */
    private function runCli(array $args): string
    {
        // Prepend the binary name to the arguments array
        $command = array_merge(['ssclient'], $args);

        // Determine the null device based on OS
        $nullDevice = (DIRECTORY_SEPARATOR === '\\') ? 'NUL' : '/dev/null';
        $descriptors = [
            0 => ['file', $nullDevice, 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptors, $pipes);

        if (!is_resource($process)) {
            throw new \RuntimeException("Failed to execute ssclient.");
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);

        // Close pipes to avoid deadlocks
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($exitCode !== 0) {
            throw new \RuntimeException(
                sprintf(
                    "ssclient failed with exit code %d.\nCommand: %s\nError: %s\nOutput: %s",
                    $exitCode,
                    implode(' ', $args),
                    trim($stderr),
                    trim($stdout)
                )
            );
        }

        return trim($stdout);
    }

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ss_test_' . bin2hex(random_bytes(8));

        if (!mkdir($this->tempDir, 0700, true)) {
            throw new RuntimeException("Could not create temp directory: {$this->tempDir}");
        }

        $this->storePath = $this->tempDir . DIRECTORY_SEPARATOR . 'test.ss';
        $this->keyPath = $this->tempDir . DIRECTORY_SEPARATOR . 'test.key';
    }

    protected function tearDown(): void
    {
        if (!is_dir($this->tempDir)) {
            return;
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->tempDir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($files as $fileinfo) {
            $path = $fileinfo->getRealPath();
            $fileinfo->isDir() ? rmdir($path) : unlink($path);
        }

        rmdir($this->tempDir);
    }

    public function testCompatibilityReadStoreCreatedByCliWithPassword(): void
    {
        $this->runCli(['create', '-s', $this->storePath, '-p', self::TEST_PASSWORD, '--no-vcs']);
        $this->runCli(['set', '-s', $this->storePath, '-p', self::TEST_PASSWORD, self::TEST_KEY, self::TEST_SECRET]);

        $store = SecretsManager::loadWithPassword($this->storePath, self::TEST_PASSWORD);

        $this->assertEquals(self::TEST_SECRET, $store->get(self::TEST_KEY));
    }

    public function testCompatibilityReadStoreCreatedByCliWithKeyFile(): void
    {
        $this->runCli([
            'create',
            '-s', $this->storePath,
            '-p', self::TEST_PASSWORD,
            '--export-key', $this->keyPath,
            '--no-vcs'
        ]);

        $this->runCli(['set', '-s', $this->storePath, '-p', self::TEST_PASSWORD, self::TEST_KEY, self::TEST_SECRET]);

        $store = SecretsManager::loadWithKeyFile($this->storePath, $this->keyPath);

        $this->assertEquals(self::TEST_SECRET, $store->get(self::TEST_KEY));
    }

    public function testSecurityIncorrectPasswordThrowsException(): void
    {
        $this->runCli(['create', '-s', $this->storePath, '-p', self::TEST_PASSWORD, '--no-vcs']);

        $this->expectException(Exception::class);
        SecretsManager::loadWithPassword($this->storePath, 'wrong-password');
    }

    public function testFunctionalityMultipleKeysRetrieval(): void
    {
        $this->runCli(['create', '-s', $this->storePath, '-p', self::TEST_PASSWORD, '--no-vcs']);

        $this->runCli(['set', '-s', $this->storePath, '-p', self::TEST_PASSWORD, self::TEST_KEY, self::TEST_SECRET]);
        $this->runCli(['set', '-s', $this->storePath, '-p', self::TEST_PASSWORD, self::NEW_LABEL, self::NEW_SECRET]);

        $store = SecretsManager::loadWithPassword($this->storePath, self::TEST_PASSWORD);
        $keys = $store->keys();

        $this->assertIsArray($keys);
        $this->assertContains(self::TEST_KEY, $keys);
        $this->assertContains(self::NEW_LABEL, $keys);
        $this->assertEquals(self::TEST_SECRET, $store->get(self::TEST_KEY));
        $this->assertEquals(self::NEW_SECRET, $store->get(self::NEW_LABEL));
    }
}
