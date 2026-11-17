<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\DlpPolicy;

class DlpMaskingService
{
    /**
     * @var array<string, string>
     */
    protected static array $commonSecretPatterns = [
        'aws_access_key' => '/\b(AKIA[0-9A-Z]{16})\b/',
        'aws_secret_key' => '/(?i)\b(?:aws_secret_access_key|aws_secret|secret_key)[\s:=]+([0-9a-zA-Z\/+]{40})\b/',
        'ai_api_key' => '/\b(sk-[a-zA-Z0-9_-]{20,})\b/',
        'github_token' => '/\b(gh[pousr]_[0-9a-zA-Z]{36,255})\b/',
        'slack_token' => '/\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/',
        'bearer_token' => '/(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{24,})\b/',
        'private_key' => '/-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----/',
    ];

    public static function maskSecret(string $secret): string
    {
        $secret = trim($secret);
        $length = strlen($secret);

        if ($length === 0) {
            return '';
        }

        if (static::isAlreadyMasked($secret)) {
            return $secret;
        }

        if ($length <= 4) {
            return str_repeat('*', $length);
        }

        if ($length <= 8) {
            return substr($secret, 0, 1).str_repeat('*', $length - 2).substr($secret, -1);
        }

        $keepStart = 2;
        if (str_starts_with($secret, 'AKIA') || str_starts_with($secret, 'ghp_') || str_starts_with($secret, 'sk-')) {
            $keepStart = 4;
        }

        $keepEnd = min(2, $length - $keepStart - 1);
        $maskLength = max(4, $length - ($keepStart + $keepEnd));

        return substr($secret, 0, $keepStart).str_repeat('*', $maskLength).substr($secret, -$keepEnd);
    }

    public static function isAlreadyMasked(?string $value): bool
    {
        if (empty($value)) {
            return false;
        }

        return substr_count($value, '*') >= 3 || str_contains($value, '[REDACTED');
    }

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

    public static function maskPromptContent(?string $prompt, ?DlpPolicy $policy = null, ?string $sample = null): ?string
    {
        if ($prompt === null || $prompt === '') {
            return $prompt;
        }

        $masked = $prompt;

        if (! empty($sample) && ! static::isAlreadyMasked($sample)) {
            $maskedSecret = static::maskSecret($sample);
            $masked = str_replace($sample, $maskedSecret, $masked);
        }

        if (! empty($sample) && static::isAlreadyMasked($sample)) {
            $masked = static::replaceMaskedSampleInPrompt($masked, $sample);
        }

        if ($policy !== null) {
            $masked = static::maskUsingPolicy($masked, $policy);
        }

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
            }
        }

        return $masked;
    }

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
                        }
                    }
                }
            }
        }

        return $prompt;
    }

    protected static function replaceMaskedSampleInPrompt(string $prompt, string $maskedSample): string
    {
        if (! preg_match('/^([^*]+)(\*+)([^*]+)$/', $maskedSample, $matches)) {
            return $prompt;
        }

        $prefix = $matches[1];
        $asterisks = $matches[2];
        $suffix = $matches[3];
        $asteriskCount = strlen($asterisks);

        $regex = '/\b'.preg_quote($prefix, '/').'[A-Za-z0-9_\-\.\/\+]{'.$asteriskCount.'}'.preg_quote($suffix, '/').'\b/';

        try {
            return (string) preg_replace($regex, $maskedSample, $prompt);
        } catch (\Throwable) {
            return $prompt;
        }
    }
}
