<?php

declare(strict_types=1);

namespace App\Support;

class BrowserDetector
{
    /**
     * Format a user-agent string into a friendly browser and platform description.
     */
    public static function format(?string $userAgent): string
    {
        if (empty($userAgent)) {
            return '-';
        }

        $browser = static::browser($userAgent);
        $platform = static::platform($userAgent);

        if ($platform) {
            return "{$browser} on {$platform}";
        }

        return $browser;
    }

    /**
     * Detect the browser name and major version.
     */
    public static function browser(?string $userAgent): string
    {
        if (empty($userAgent)) {
            return '-';
        }

        if (preg_match('/Edg(?:e|A|iOS)?\/([0-9.]+)/i', $userAgent, $matches)) {
            return 'Edge '.explode('.', $matches[1])[0];
        }

        if (preg_match('/OPR\/([0-9.]+)/i', $userAgent, $matches) || preg_match('/Opera\/([0-9.]+)/i', $userAgent, $matches)) {
            return 'Opera '.explode('.', $matches[1])[0];
        }

        if (preg_match('/Chrome\/([0-9.]+)/i', $userAgent, $matches) && ! preg_match('/Edg/i', $userAgent)) {
            return 'Chrome '.explode('.', $matches[1])[0];
        }

        if (preg_match('/Firefox\/([0-9.]+)/i', $userAgent, $matches)) {
            return 'Firefox '.explode('.', $matches[1])[0];
        }

        if (preg_match('/Version\/([0-9.]+).*Safari/i', $userAgent, $matches)) {
            return 'Safari '.explode('.', $matches[1])[0];
        }

        if (preg_match('/PostmanRuntime\/([0-9.]+)/i', $userAgent)) {
            return 'Postman';
        }

        if (preg_match('/curl\/([0-9.]+)/i', $userAgent)) {
            return 'cURL';
        }

        if (preg_match('/Symfony/i', $userAgent)) {
            return 'Symfony BrowserKit';
        }

        return 'Other Browser';
    }

    /**
     * Detect the operating system / platform.
     */
    public static function platform(?string $userAgent): ?string
    {
        if (empty($userAgent)) {
            return null;
        }

        if (preg_match('/Windows NT 10.0/i', $userAgent)) {
            return 'Windows 10/11';
        }

        if (preg_match('/Windows NT/i', $userAgent)) {
            return 'Windows';
        }

        if (preg_match('/Macintosh|Mac OS X/i', $userAgent)) {
            return 'macOS';
        }

        if (preg_match('/Android/i', $userAgent)) {
            return 'Android';
        }

        if (preg_match('/iPhone|iPad|iPod/i', $userAgent)) {
            return 'iOS';
        }

        if (preg_match('/Linux/i', $userAgent)) {
            return 'Linux';
        }

        return null;
    }
}
