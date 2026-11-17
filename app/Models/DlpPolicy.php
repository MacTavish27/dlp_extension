<?php

namespace App\Models;

use AlizHarb\ActivityLog\Contracts\HasActivityLogTitle;
use App\Observers\DlpPolicyObserver;
use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Model;
use Spatie\Activitylog\Models\Concerns\LogsActivity;
use Spatie\Activitylog\Support\LogOptions;

#[ObservedBy([DlpPolicyObserver::class])]
class DlpPolicy extends Model implements HasActivityLogTitle
{
    use LogsActivity;

    protected $fillable = [
        'name',
        'detection_type',
        'pattern',
        'action',
        'severity',
        'target_domains',
        'is_active',
    ];

    protected $casts = [
        'target_domains' => 'array',
        'is_active' => 'boolean',
    ];

    public function getActivitylogOptions(): LogOptions
    {
        return LogOptions::defaults()
            ->logAll()
            ->logOnlyDirty()
            ->dontLogEmptyChanges()
            ->setDescriptionForEvent(fn (string $eventName) => match ($eventName) {
                'created' => "Created DLP policy ':subject.name'",
                'updated' => "Updated DLP policy ':subject.name'",
                'deleted' => "Deleted DLP policy ':subject.name'",
                default => "DLP policy ':subject.name' was {$eventName}",
            });
    }

    public function getActivityLogTitle(): string
    {
        return $this->name;
    }
}
