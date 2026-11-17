<?php

namespace App\Models;

use AlizHarb\ActivityLog\Contracts\HasActivityLogTitle;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Activitylog\Models\Concerns\LogsActivity;
use Spatie\Activitylog\Support\LogOptions;

#[Fillable(['name', 'email', 'password'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable implements HasActivityLogTitle
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, LogsActivity, Notifiable;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function getActivitylogOptions(): LogOptions
    {
        return LogOptions::defaults()
            ->logOnly(['name', 'email'])
            ->logOnlyDirty()
            ->dontLogEmptyChanges()
            ->dontLogIfAttributesChangedOnly(['remember_token'])
            ->setDescriptionForEvent(fn (string $eventName) => match ($eventName) {
                'created' => "Created user ':subject.name'",
                'updated' => "Updated user ':subject.name'",
                'deleted' => "Deleted user ':subject.name'",
                default => "User ':subject.name' was {$eventName}",
            });
    }

    public function getActivityLogTitle(): string
    {
        return "{$this->name} ({$this->email})";
    }
}
