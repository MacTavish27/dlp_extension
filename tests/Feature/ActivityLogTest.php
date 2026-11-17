<?php

use App\Models\DlpPolicy;
use App\Models\User;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Spatie\Activitylog\Models\Activity;

uses(RefreshDatabase::class);

beforeEach(function () {
    Activity::query()->delete();
});

test('login event logs action as login with IP address and browser context', function () {
    $user = User::factory()->create([
        'name' => 'Test Admin',
        'email' => 'admin_test@example.com',
    ]);

    // Clear user creation activity so we test login specifically
    Activity::query()->delete();

    // Simulate login event
    event(new Login('web', $user, false));

    $log = Activity::where('event', 'login')->first();

    expect($log)->not->toBeNull()
        ->and($log->event)->toBe('login')
        ->and($log->description)->toBe('Logged in to admin panel')
        ->and($log->subject_type)->toBe(User::class)
        ->and($log->subject_id)->toBe($user->id)
        ->and($log->causer_id)->toBe($user->id)
        ->and($log->ip_address)->not->toBeNull()
        ->and(data_get($log->properties, 'user_agent'))->not->toBeNull();
});

test('updating remember token does not trigger a false updated activity log', function () {
    $user = User::factory()->create();
    $countBefore = Activity::count();

    $user->setRememberToken(Str::random(60));
    $user->save();

    expect(Activity::count())->toBe($countBefore);
});

test('logout event logs action as logout', function () {
    $user = User::factory()->create();

    // Clear user creation activity
    Activity::query()->delete();

    event(new Logout('web', $user));

    $log = Activity::where('event', 'logout')->first();

    expect($log)->not->toBeNull()
        ->and($log->event)->toBe('logout')
        ->and($log->description)->toBe('Logged out of admin panel')
        ->and($log->subject_id)->toBe($user->id);
});

test('failed login attempt logs failed event with email and client IP', function () {
    event(new Failed('web', null, ['email' => 'hacker@example.com', 'password' => 'secret']));

    $log = Activity::where('event', 'failed')->first();

    expect($log)->not->toBeNull()
        ->and($log->event)->toBe('failed')
        ->and($log->description)->toBe('Failed login attempt for hacker@example.com')
        ->and(data_get($log->properties, 'email'))->toBe('hacker@example.com')
        ->and($log->ip_address)->not->toBeNull();
});

test('dlp policy crud actions log specific descriptions and capture IP and browser', function () {
    $policy = DlpPolicy::create([
        'name' => 'Confidential Data',
        'detection_type' => 'keyword',
        'pattern' => 'confidential',
        'action' => 'block',
        'severity' => 'high',
        'target_domains' => ['example.com'],
        'is_active' => true,
    ]);

    $createdLog = Activity::where('event', 'created')->latest()->first();
    expect($createdLog)->not->toBeNull()
        ->and($createdLog->description)->toBe("Created DLP policy 'Confidential Data'")
        ->and($createdLog->ip_address)->not->toBeNull()
        ->and(data_get($createdLog->properties, 'user_agent'))->not->toBeNull();

    $policy->update(['severity' => 'critical']);

    $updatedLog = Activity::where('event', 'updated')->latest()->first();
    expect($updatedLog)->not->toBeNull()
        ->and($updatedLog->description)->toBe("Updated DLP policy 'Confidential Data'");

    $policy->delete();

    $deletedLog = Activity::where('event', 'deleted')->latest()->first();
    expect($deletedLog)->not->toBeNull()
        ->and($deletedLog->description)->toBe("Deleted DLP policy 'Confidential Data'");
});
