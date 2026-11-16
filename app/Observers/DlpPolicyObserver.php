<?php

namespace App\Observers;

use App\Models\DlpPolicy;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class DlpPolicyObserver
{
    /**
     * Invalidate active DLP policy cache and bump version.
     */
    private function invalidatePolicyCache(string $event, DlpPolicy $dlpPolicy): void
    {
        Cache::forget('active_dlp_policies');
        $newVersion = md5(now()->toIso8601String() . '_' . $dlpPolicy->id);
        Cache::forever('dlp_policies_cache_bust', $newVersion);

        Log::info("[DLP Observer] Policy {$event} (ID: {$dlpPolicy->id}, Name: '{$dlpPolicy->name}'). Cache cleared.");
    }

    /**
     * Handle the DlpPolicy "saved" event (covers created and updated).
     */
    public function saved(DlpPolicy $dlpPolicy): void
    {
        $this->invalidatePolicyCache('saved', $dlpPolicy);
    }

    /**
     * Handle the DlpPolicy "deleted" event.
     */
    public function deleted(DlpPolicy $dlpPolicy): void
    {
        $this->invalidatePolicyCache('deleted', $dlpPolicy);
    }

    /**
     * Handle the DlpPolicy "restored" event.
     */
    public function restored(DlpPolicy $dlpPolicy): void
    {
        $this->invalidatePolicyCache('restored', $dlpPolicy);
    }

    /**
     * Handle the DlpPolicy "force deleted" event.
     */
    public function forceDeleted(DlpPolicy $dlpPolicy): void
    {
        $this->invalidatePolicyCache('forceDeleted', $dlpPolicy);
    }
}
