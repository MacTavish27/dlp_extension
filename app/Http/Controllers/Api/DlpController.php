<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\DlpIncident;
use App\Models\DlpPolicy;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class DlpController extends Controller
{
    public function policies()
    {
        $policies = Cache::remember('active_dlp_policies', 900, function () {
            return DlpPolicy::where('is_active', true)
                ->select(['id', 'name', 'detection_type', 'pattern', 'action', 'severity', 'target_domains'])
                ->get()
                ->toArray();
        });

        return response()->json([
            'version' => md5(json_encode($policies)),
            'policies' => $policies,
        ]);
    }

    public function logIncident(Request $request)
    {
        $validated = $request->validate([
            'dlp_policy_id' => 'required|exists:dlp_policies,id',
            'user_identifier' => 'nullable|string|max:255',
            'domain' => 'required|string|max:255',
            'action_taken' => 'required|string|max:50',
            'masked_sample' => 'nullable|string|max:255',
            'prompt_content' => 'nullable|string',
        ]);

        $incident = DlpIncident::create([
            ...$validated,
            'client_ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'occurred_at' => now(),
        ]);

        return response()->json([
            'status' => 'recorded',
            'incident_id' => $incident->id,
        ], 201);
    }
}
