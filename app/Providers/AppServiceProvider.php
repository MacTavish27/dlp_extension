<?php

namespace App\Providers;

use AlizHarb\ActivityLog\Taps\SetActivityContextTap;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Spatie\Activitylog\Actions\LogActivityAction;
use Spatie\Activitylog\Contracts\Activity as ActivityContract;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Automatically attach request context (IP address, user agent, request ID, risk score) to every logged activity
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
                // Fallback in case of missing context collectors or exceptions
            }

            // Ensure IP address and request ID are directly populated on the model table columns
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
