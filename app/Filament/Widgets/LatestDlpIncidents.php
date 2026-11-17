<?php

namespace App\Filament\Widgets;

use App\Filament\Resources\DlpIncidents\Schemas\DlpIncidentInfolist;
use App\Models\DlpIncident;
use Filament\Actions\ViewAction;
use Filament\Support\Enums\FontFamily;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget;
use Illuminate\Database\Eloquent\Builder;

class LatestDlpIncidents extends TableWidget
{
    protected static ?int $sort = 2;

    protected static ?string $heading = 'Latest Monitored AI Security Events';

    protected int|string|array $columnSpan = 'full';

    public function table(Table $table): Table
    {
        return $table
            ->query(fn (): Builder => DlpIncident::query()->latest('occurred_at'))
            ->columns([
                TextColumn::make('occurred_at')
                    ->label('Timestamp')
                    ->dateTime('M d, Y H:i:s')
                    ->description(fn (DlpIncident $record) => $record->occurred_at?->diffForHumans())
                    ->sortable(),

                TextColumn::make('user_identifier')
                    ->label('Who (User)')
                    ->badge()
                    ->color('gray')
                    ->icon('heroicon-m-user')
                    ->searchable(),

                TextColumn::make('domain')
                    ->label('AI Domain')
                    ->badge()
                    ->color(fn (string $state): string => match (true) {
                        str_contains($state, 'gemini') => 'info',
                        str_contains($state, 'chatgpt') || str_contains($state, 'openai') => 'success',
                        str_contains($state, 'claude') => 'warning',
                        default => 'gray',
                    }),

                TextColumn::make('policy.name')
                    ->label('Policy')
                    ->placeholder('Policy Deleted'),

                TextColumn::make('action_taken')
                    ->label('Enforcement')
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => match ($state) {
                        'block' => 'BLOCKED',
                        'warn_blocked' => 'WARN - CANCELLED',
                        'warn_bypassed' => 'WARN - BYPASSED',
                        'redact' => 'REDACTED',
                        'log' => 'LOGGED',
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
                    ->placeholder('-'),

                TextColumn::make('prompt_content')
                    ->label('What Was Entered (Prompt)')
                    ->limit(55)
                    ->tooltip(fn (DlpIncident $record): ?string => $record->prompt_content)
                    ->placeholder('Not captured (Network mode)'),
            ])
            ->recordActions([
                ViewAction::make()
                    ->slideOver()
                    ->infolist(fn ($infolist) => DlpIncidentInfolist::configure($infolist)),
            ])
            ->paginated([5, 10, 25]);
    }
}
