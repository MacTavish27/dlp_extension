<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DlpIncident extends Model
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
}
