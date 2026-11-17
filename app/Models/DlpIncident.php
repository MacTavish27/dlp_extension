<?php

namespace App\Models;

use AlizHarb\ActivityLog\Contracts\HasActivityLogTitle;
use App\Services\DlpMaskingService;
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

    protected static function booted(): void
    {
        static::saving(function (DlpIncident $incident): void {
            $policy = $incident->policy ?? DlpPolicy::find($incident->dlp_policy_id);

            // Ensure masked_sample is stored in masked form
            if (! empty($incident->masked_sample)) {
                $incident->masked_sample = DlpMaskingService::maskSample($incident->masked_sample, $policy);
            }

            // Ensure full prompt content never contains raw unmasked secret keys
            if (! empty($incident->prompt_content)) {
                $incident->prompt_content = DlpMaskingService::maskPromptContent(
                    $incident->prompt_content,
                    $policy,
                    $incident->masked_sample
                );
            }
        });
    }

    public function policy(): BelongsTo
    {
        return $this->belongsTo(DlpPolicy::class, 'dlp_policy_id');
    }

    public function getActivityLogTitle(): string
    {
        return "Incident #{$this->id} ({$this->domain})";
    }
}
