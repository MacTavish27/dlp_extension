<?php

namespace App\Filament\Resources\DlpIncidents\Tables;

use App\Models\DlpIncident;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\ViewAction;
use Filament\Support\Enums\FontFamily;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class DlpIncidentsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->defaultSort('occurred_at', 'desc')
            ->columns([
                TextColumn::make('occurred_at')
                    ->label('Timestamp')
                    ->dateTime('M d, Y H:i:s')
                    ->description(fn (DlpIncident $record) => $record->occurred_at?->diffForHumans())
                    ->sortable(),

                TextColumn::make('user_identifier')
                    ->label('Who (User)')
                    ->searchable()
                    ->copyable()
                    ->badge()
                    ->color('gray')
                    ->icon('heroicon-m-user'),

                TextColumn::make('domain')
                    ->label('AI Domain')
                    ->searchable()
                    ->badge()
                    ->color(fn (string $state): string => match (true) {
                        str_contains($state, 'gemini') => 'info',
                        str_contains($state, 'chatgpt') || str_contains($state, 'openai') => 'success',
                        str_contains($state, 'claude') => 'warning',
                        default => 'gray',
                    }),

                TextColumn::make('policy.name')
                    ->label('Policy Violated')
                    ->searchable()
                    ->sortable()
                    ->placeholder('Policy Deleted')
                    ->description(fn (DlpIncident $record) => 'Type: '.($record->policy?->detection_type ?? 'N/A')),

                TextColumn::make('policy.severity')
                    ->label('Severity')
                    ->badge()
                    ->color(fn (?string $state): string => match (strtolower($state ?? '')) {
                        'critical' => 'danger',
                        'high' => 'danger',
                        'medium' => 'warning',
                        'low' => 'info',
                        default => 'gray',
                    }),

                TextColumn::make('action_taken')
                    ->label('Action Taken')
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => match ($state) {
                        'block' => 'HARD BLOCKED',
                        'warn_blocked' => 'WARN - CANCELLED',
                        'warn_bypassed' => 'WARN - BYPASSED',
                        'redact' => 'AUTO-REDACTED',
                        'log' => 'AUDIT LOG',
                        default => strtoupper($state),
                    })
                    ->color(fn (string $state): string => match ($state) {
                        'block', 'warn_blocked' => 'danger',
                        'warn_bypassed' => 'warning',
                        'redact' => 'info',
                        'log' => 'gray',
                        default => 'gray',
                    }),

                TextColumn::make('masked_sample')
                    ->label('Detected Sample')
                    ->fontFamily(FontFamily::Mono)
                    ->copyable()
                    ->searchable()
                    ->placeholder('-'),

                TextColumn::make('prompt_content')
                    ->label('What Was Entered (Prompt)')
                    ->limit(60)
                    ->tooltip(fn (DlpIncident $record): ?string => $record->prompt_content)
                    ->searchable()
                    ->placeholder('Not captured (Network mode)'),

                TextColumn::make('client_ip')
                    ->label('Client IP')
                    ->searchable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('action_taken')
                    ->label('Filter by Action')
                    ->options([
                        'block' => 'Hard Blocked',
                        'warn_bypassed' => 'Warning (Bypassed)',
                        'warn_blocked' => 'Warning (Cancelled)',
                        'redact' => 'Auto-Redacted',
                        'log' => 'Audit Log',
                    ]),

                SelectFilter::make('dlp_policy_id')
                    ->label('Filter by Policy')
                    ->relationship('policy', 'name'),

                SelectFilter::make('domain')
                    ->label('Filter by Domain')
                    ->options([
                        'gemini.google.com' => 'Google Gemini',
                        'chatgpt.com' => 'OpenAI ChatGPT',
                        'claude.ai' => 'Anthropic Claude',
                    ]),
            ])
            ->recordActions([
                ViewAction::make()->slideOver(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make(),
                ]),
            ]);
    }
}
