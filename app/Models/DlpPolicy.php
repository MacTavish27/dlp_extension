<?php

namespace App\Models;

use App\Observers\DlpPolicyObserver;
use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Model;

#[ObservedBy([DlpPolicyObserver::class])]
class DlpPolicy extends Model
{
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
}
