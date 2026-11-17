<?php

namespace App\Providers;

use AlizHarb\ActivityLog\Taps\SetActivityContextTap;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Spatie\Activitylog\Actions\LogActivityAction;
use Spatie\Activitylog\Contracts\Activity as ActivityContract;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void {}

    public function boot(): void
    {
        LogActivityAction::beforeLogging(function (ActivityContract $activity): void {
            if (! $activity instanceof Model) {
                return;
            }

            try {
                $tap = app(SetActivityContextTap::class);
                $tap(
                    $activity,
                    (string) ($activity->getAttribute('event') ?? ''),
                    $activity->getAttribute('subject'),
                    $activity->getAttribute('causer')
                );
            } catch (\Throwable) {
            }

            $ipAddress = data_get($activity->properties, 'ip_address') ?? request()?->ip();
            if ($ipAddress && empty($activity->getAttribute('ip_address'))) {
                $activity->setAttribute('ip_address', $ipAddress);
            }

            $requestId = data_get($activity->properties, 'request_id');
            if ($requestId && empty($activity->getAttribute('request_id'))) {
                $activity->setAttribute('request_id', $requestId);
            }
        });
    }
}
