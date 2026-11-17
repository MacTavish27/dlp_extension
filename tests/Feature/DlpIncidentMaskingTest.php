<?php

use App\Models\DlpIncident;
use App\Models\DlpPolicy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

test('dlp incident api masks raw secret keys in both masked_sample and prompt_content', function () {
    $policy = DlpPolicy::create([
        'name' => 'AWS Key Detector',
        'detection_type' => 'regex',
        'pattern' => 'AKIA[0-9A-Z]{16}',
        'action' => 'block',
        'severity' => 'critical',
        'target_domains' => ['chatgpt.com'],
        'is_active' => true,
    ]);

    $rawSecret = 'AKIAIOSFODNN7EXAMPLE';
    $rawPrompt = "Check this AWS secret key: {$rawSecret} and let me know if valid";

    $response = $this->postJson('/api/v1/dlp/incidents', [
        'dlp_policy_id' => $policy->id,
        'user_identifier' => 'developer_1',
        'domain' => 'chatgpt.com',
        'action_taken' => 'block',
        'masked_sample' => $rawSecret, // Raw key passed as sample
        'prompt_content' => $rawPrompt, // Raw prompt containing key
    ]);

    $response->assertStatus(201);

    $incident = DlpIncident::latest()->first();

    // The raw secret should NOT exist anywhere in the database record
    expect($incident->masked_sample)->not->toContain($rawSecret)
        ->and($incident->prompt_content)->not->toContain($rawSecret)
        ->and($incident->masked_sample)->toBe('AKIA**************LE')
        ->and($incident->prompt_content)->toBe('Check this AWS secret key: AKIA**************LE and let me know if valid');
});

test('dlp incident api preserves prompt when client passes pre-masked sample', function () {
    $policy = DlpPolicy::create([
        'name' => 'AWS Key Detector',
        'detection_type' => 'regex',
        'pattern' => 'AKIA[0-9A-Z]{16}',
        'action' => 'block',
        'severity' => 'critical',
        'target_domains' => ['gemini.google.com'],
        'is_active' => true,
    ]);

    $rawSecret = 'AKIAIOSFODNN7EXAMPLE';
    $maskedSample = 'AK****************LE';

    $response = $this->postJson('/api/v1/dlp/incidents', [
        'dlp_policy_id' => $policy->id,
        'user_identifier' => 'user_dev_01',
        'domain' => 'gemini.google.com',
        'action_taken' => 'block',
        'masked_sample' => $maskedSample,
        'prompt_content' => "My access key is {$rawSecret} for testing.",
    ]);

    $response->assertStatus(201);

    $incident = DlpIncident::latest()->first();

    expect($incident->prompt_content)->not->toContain($rawSecret)
        ->and($incident->prompt_content)->toContain($maskedSample)
        ->and($incident->masked_sample)->toBe($maskedSample);
});

test('dlp incident model automatically masks secrets even when created directly', function () {
    $policy = DlpPolicy::create([
        'name' => 'OpenAI Key Detector',
        'detection_type' => 'regex',
        'pattern' => 'sk-[a-zA-Z0-9_\-]{20,}',
        'action' => 'block',
        'severity' => 'critical',
        'target_domains' => ['claude.ai'],
        'is_active' => true,
    ]);

    $rawSecret = 'sk-proj-9876543210abcdef9876543210';
    $incident = DlpIncident::create([
        'dlp_policy_id' => $policy->id,
        'domain' => 'claude.ai',
        'action_taken' => 'block',
        'masked_sample' => $rawSecret,
        'prompt_content' => "Here is my secret token: {$rawSecret}",
        'occurred_at' => now(),
    ]);

    $incident->refresh();

    expect($incident->masked_sample)->not->toContain($rawSecret)
        ->and($incident->prompt_content)->not->toContain($rawSecret)
        ->and($incident->masked_sample)->toContain('****')
        ->and($incident->prompt_content)->toContain('****');
});
