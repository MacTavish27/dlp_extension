<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\DlpPolicy;

class DlpMaskingService
{
    /**
     * Common credential / API key regex patterns (defense-in-depth).
     *
     * @var array<string, string>
     */
    protected static array $commonSecretPatterns = [
        // AWS Access Key ID (e.g., AKIA...)
        'aws_access_key' => '/\b(AKIA[0-9A-Z]{16})\b/',
        // AWS Secret Access Key (40 chars base64)
        'aws_secret_key' => '/(?i)\b(?:aws_secret_access_key|aws_secret|secret_key)[\s:=]+([0-9a-zA-Z\/+]{40})\b/',
        // OpenAI / Anthropic API Keys (e.g., sk-...)
        'ai_api_key' => '/\b(sk-[a-zA-Z0-9_-]{20,})\b/',
        // GitHub Personal Access Token / Fine-grained Token
        'github_token' => '/\b(gh[pousr]_[0-9a-zA-Z]{36,255})\b/',
        // Slack API Token
        'slack_token' => '/\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/',
        // Generic Bearer Token
        'bearer_token' => '/(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{24,})\b/',
        // Private Keys
        'private_key' => '/-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----/',
    ];

    /**
     * Mask a secret token string, preserving non-sensitive prefix and suffix.
     */
    public static function maskSecret(string $secret): string
    {
        $secret = trim($secret);
        $length = strlen($secret);

        if ($length === 0) {
            return '';
        }

        // If already heavily masked, don't re-mask
        if (static::isAlreadyMasked($secret)) {
            return $secret;
        }

        // Very short strings (<= 4 chars)
        if ($length <= 4) {
            return str_repeat('*', $length);
        }

        // Short strings (5 - 8 chars): keep first 1 and last 1
        if ($length <= 8) {
            return substr($secret, 0, 1).str_repeat('*', $length - 2).substr($secret, -1);
        }

        // Determine prefix to keep for well-known key formats
        $keepStart = 2;
        if (str_starts_with($secret, 'AKIA') || str_starts_with($secret, 'ghp_') || str_starts_with($secret, 'sk-')) {
            $keepStart = 4;
        }

        $keepEnd = min(2, $length - $keepStart - 1);
        $maskLength = max(4, $length - ($keepStart + $keepEnd));

        return substr($secret, 0, $keepStart).str_repeat('*', $maskLength).substr($secret, -$keepEnd);
    }

    /**
     * Check if a sample or string is already masked.
     */
    public static function isAlreadyMasked(?string $value): bool
    {
        if (empty($value)) {
            return false;
        }

        // Contains at least 3 asterisks
        return substr_count($value, '*') >= 3 || str_contains($value, '[REDACTED');
    }

    /**
     * Mask sensitive sample before storing in database.
     */
    public static function maskSample(?string $sample, ?DlpPolicy $policy = null): ?string
    {
        if ($sample === null || $sample === '') {
            return null;
        }

        if (static::isAlreadyMasked($sample)) {
            return $sample;
        }

        return static::maskSecret($sample);
    }

    /**
     * Mask secret keys inside full prompt content before storing in database.
     */
    public static function maskPromptContent(?string $prompt, ?DlpPolicy $policy = null, ?string $sample = null): ?string
    {
        if ($prompt === null || $prompt === '') {
            return $prompt;
        }

        $masked = $prompt;

        // 1. If a specific unmasked sample was supplied, mask that exact string in the prompt
        if (! empty($sample) && ! static::isAlreadyMasked($sample)) {
            $maskedSecret = static::maskSecret($sample);
            $masked = str_replace($sample, $maskedSecret, $masked);
        }

        // 2. If a masked sample was supplied (e.g. AK****************LE), find its unmasked counterpart in prompt
        if (! empty($sample) && static::isAlreadyMasked($sample)) {
            $masked = static::replaceMaskedSampleInPrompt($masked, $sample);
        }

        // 3. Mask matches based on the violated policy
        if ($policy !== null) {
            $masked = static::maskUsingPolicy($masked, $policy);
        }

        // 4. Defense-in-depth: Mask common known secret patterns (AWS, OpenAI, GitHub, etc.)
        foreach (static::$commonSecretPatterns as $patternName => $pattern) {
            try {
                if ($patternName === 'private_key') {
                    $masked = preg_replace(
                        $pattern,
                        '-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----',
                        $masked
                    );
                } elseif ($patternName === 'bearer_token') {
                    $masked = preg_replace_callback($pattern, function ($matches) {
                        return 'Bearer '.static::maskSecret($matches[1]);
                    }, $masked);
                } elseif ($patternName === 'aws_secret_key') {
                    $masked = preg_replace_callback($pattern, function ($matches) {
                        return str_replace($matches[1], static::maskSecret($matches[1]), $matches[0]);
                    }, $masked);
                } else {
                    $masked = preg_replace_callback($pattern, function ($matches) {
                        return static::maskSecret($matches[1]);
                    }, $masked);
                }
            } catch (\Throwable) {
                // Ignore regex errors
            }
        }

        return $masked;
    }

    /**
     * Mask prompt content based on the violated policy detection type and pattern.
     */
    protected static function maskUsingPolicy(string $prompt, DlpPolicy $policy): string
    {
        $pattern = trim($policy->pattern ?? '');
        if ($pattern === '') {
            return $prompt;
        }

        $type = strtolower($policy->detection_type ?? '');

        if ($type === 'regex') {
            $regex = $pattern;
            if (! str_starts_with($regex, '/') || ! preg_match('/\/[a-z]*$/i', $regex)) {
                $regex = '/'.str_replace('/', '\/', $regex).'/i';
            }

            try {
                return (string) preg_replace_callback($regex, function ($matches) {
                    return static::maskSecret($matches[0]);
                }, $prompt);
            } catch (\Throwable) {
                return $prompt;
            }
        }

        if ($type === 'keyword') {
            // Split comma or newline delimited keywords
            $keywords = preg_split('/[,;\r\n]+/', $pattern);
            if (is_array($keywords)) {
                foreach ($keywords as $keyword) {
                    $keyword = trim($keyword);
                    if ($keyword !== '' && strlen($keyword) >= 3) {
                        try {
                            $prompt = (string) preg_replace_callback(
                                '/\b'.preg_quote($keyword, '/').'\b/i',
                                fn ($matches) => static::maskSecret($matches[0]),
                                $prompt
                            );
                        } catch (\Throwable) {
                            // Fallback
                        }
                    }
                }
            }
        }

        return $prompt;
    }

    /**
     * When client sends an already-masked sample (e.g. AK****************LE),
     * locate the corresponding cleartext secret in the prompt and replace it.
     */
    protected static function replaceMaskedSampleInPrompt(string $prompt, string $maskedSample): string
    {
        // Example masked sample: AK****************LE
        if (! preg_match('/^([^*]+)(\*+)([^*]+)$/', $maskedSample, $matches)) {
            return $prompt;
        }

        $prefix = $matches[1];
        $asterisks = $matches[2];
        $suffix = $matches[3];
        $asteriskCount = strlen($asterisks);

        // Regex looking for prefix + exact count of non-space chars + suffix
        $regex = '/\b'.preg_quote($prefix, '/').'[A-Za-z0-9_\-\.\/\+]{'.$asteriskCount.'}'.preg_quote($suffix, '/').'\b/';

        try {
            return (string) preg_replace($regex, $maskedSample, $prompt);
        } catch (\Throwable) {
            return $prompt;
        }
    }
}
