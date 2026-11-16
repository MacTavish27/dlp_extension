<?php

namespace App\Filament\Resources\DlpIncidents\Schemas;

use App\Models\DlpIncident;
use Filament\Infolists\Components\TextEntry;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontFamily;

class DlpIncidentInfolist
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->components([
                Section::make('Event Summary & Enforcement')
                    ->description('Details of the DLP policy match and enforcement action.')
                    ->schema([
                        TextEntry::make('occurred_at')
                            ->label('Timestamp')
                            ->dateTime('M d, Y H:i:s')
                            ->helperText(fn (DlpIncident $record) => $record->occurred_at?->diffForHumans()),

                        TextEntry::make('domain')
                            ->label('AI Platform / Domain')
                            ->badge()
                            ->color(fn (string $state): string => match (true) {
                                str_contains($state, 'gemini') => 'info',
                                str_contains($state, 'chatgpt') || str_contains($state, 'openai') => 'success',
                                str_contains($state, 'claude') => 'warning',
                                default => 'gray',
                            }),

                        TextEntry::make('action_taken')
                            ->label('Enforcement Action')
                            ->badge()
                            ->formatStateUsing(fn (string $state): string => match ($state) {
                                'block' => 'HARD BLOCKED',
                                'warn_blocked' => 'WARN - CANCELLED BY USER',
                                'warn_bypassed' => 'WARN - OVERRIDDEN BY USER',
                                'redact' => 'AUTO-REDACTED',
                                'log' => 'AUDIT LOG ONLY',
                                default => strtoupper($state),
                            })
                            ->color(fn (string $state): string => match ($state) {
                                'block', 'warn_blocked' => 'danger',
                                'warn_bypassed' => 'warning',
                                'redact' => 'info',
                                'log' => 'gray',
                                default => 'gray',
                            }),

                        TextEntry::make('policy.name')
                            ->label('Triggered Policy')
                            ->placeholder('Policy Deleted'),

                        TextEntry::make('policy.severity')
                            ->label('Policy Severity')
                            ->badge()
                            ->color(fn (?string $state): string => match (strtolower($state ?? '')) {
                                'critical' => 'danger',
                                'high' => 'danger',
                                'medium' => 'warning',
                                'low' => 'info',
                                default => 'gray',
                            }),

                        TextEntry::make('policy.detection_type')
                            ->label('Detection Method')
                            ->badge()
                            ->color('gray')
                            ->formatStateUsing(fn (?string $state) => strtoupper($state ?? 'N/A')),
                    ])
                    ->columns(3),

                Section::make('User & Origin Information ("Who")')
                    ->description('Identity and device details of the user who entered the prompt.')
                    ->schema([
                        TextEntry::make('user_identifier')
                            ->label('User Identifier')
                            ->icon('heroicon-m-user')
                            ->copyable()
                            ->badge()
                            ->color('gray'),

                        TextEntry::make('client_ip')
                            ->label('Client IP Address')
                            ->icon('heroicon-m-globe-alt')
                            ->copyable()
                            ->placeholder('Localhost / Direct'),

                        TextEntry::make('user_agent')
                            ->label('Browser & System (User Agent)')
                            ->placeholder('-')
                            ->columnSpanFull(),
                    ])
                    ->columns(2),

                Section::make('What Was Entered ("The Prompt & Sensitive Content")')
                    ->description('Complete user input and detected confidential tokens.')
                    ->schema([
                        TextEntry::make('masked_sample')
                            ->label('Detected Sensitive Data (Masked)')
                            ->fontFamily(FontFamily::Mono)
                            ->copyable()
                            ->badge()
                            ->color('danger')
                            ->placeholder('-'),

                        TextEntry::make('prompt_content')
                            ->label('Full User Prompt (What Was Typed)')
                            ->fontFamily(FontFamily::Mono)
                            ->copyable()
                            ->columnSpanFull()
                            ->placeholder('Full prompt content not captured (sent via raw network payload).')
                            ->extraAttributes([
                                'class' => 'bg-gray-950 p-4 rounded-lg border border-gray-800 text-sm whitespace-pre-wrap leading-relaxed text-gray-200',
                            ]),
                    ]),
            ]);
    }
}
