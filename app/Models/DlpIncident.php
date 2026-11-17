<?php

namespace App\Models;

use AlizHarb\ActivityLog\Contracts\HasActivityLogTitle;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DlpIncident extends Model implements HasActivityLogTitle
{
    protected $fillable = [
        'dlp_policy_id',
        'user_identifier',
        'domain',
        'action_taken',
        'masked_sample',
        'prompt_content',
        'client_ip',
        'user_agent',
        'occurred_at',
    ];

    protected $casts = [
        'occurred_at' => 'datetime',
    ];

    public function policy(): BelongsTo
    {
        return $this->belongsTo(DlpPolicy::class, 'dlp_policy_id');
    }

    public function getActivityLogTitle(): string
    {
        return "Incident #{$this->id} ({$this->domain})";
    }
}
