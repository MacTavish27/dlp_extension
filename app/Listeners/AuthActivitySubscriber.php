<?php

declare(strict_types=1);

namespace App\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Events\Dispatcher;

class AuthActivitySubscriber
{
    public function handleLogin(Login $event): void
    {
        $log = activity('auth')
            ->event('login')
            ->performedOn($event->user)
            ->causedBy($event->user)
            ->withProperties([
                'guard' => $event->guard,
                'remember' => $event->remember,
            ]);

        $log->log('Logged in to admin panel');
    }

    public function handleLogout(Logout $event): void
    {
        if (! $event->user) {
            return;
        }

        activity('auth')
            ->event('logout')
            ->performedOn($event->user)
            ->causedBy($event->user)
            ->withProperties([
                'guard' => $event->guard,
            ])
            ->log('Logged out of admin panel');
    }

    public function handleFailed(Failed $event): void
    {
        $email = $event->credentials['email'] ?? 'unknown';

        $activity = activity('auth')
            ->event('failed')
            ->withProperties([
                'guard' => $event->guard,
                'email' => $email,
            ]);

        if ($event->user) {
            $activity->performedOn($event->user);
        }

        $activity->log("Failed login attempt for {$email}");
    }

    public function handleLockout(Lockout $event): void
    {
        activity('auth')
            ->event('lockout')
            ->withProperties([
                'ip' => request()->ip(),
            ])
            ->log('User account locked out due to excessive failed attempts');
    }

    public function handlePasswordReset(PasswordReset $event): void
    {
        activity('auth')
            ->event('password_reset')
            ->performedOn($event->user)
            ->causedBy($event->user)
            ->log('Password reset successfully');
    }

    public function subscribe(Dispatcher $events): array
    {
        return [
            Login::class => 'handleLogin',
            Logout::class => 'handleLogout',
            Failed::class => 'handleFailed',
            Lockout::class => 'handleLockout',
            PasswordReset::class => 'handlePasswordReset',
        ];
    }
}
