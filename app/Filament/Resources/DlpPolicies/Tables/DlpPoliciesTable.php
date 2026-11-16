<?php

namespace App\Filament\Resources\DlpPolicies\Tables;

use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Support\Enums\FontFamily;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;

class DlpPoliciesTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('name')
                    ->label('Policy Name')
                    ->weight('bold')
                    ->searchable()
                    ->sortable(),

                TextColumn::make('detection_type')
                    ->label('Detection Method')
                    ->badge()
                    ->formatStateUsing(fn (string $state) => strtoupper($state))
                    ->color(fn (string $state): string => match ($state) {
                        'regex' => 'primary',
                        'keyword' => 'info',
                        'entropy' => 'warning',
                        default => 'gray',
                    }),

                TextColumn::make('pattern')
                    ->label('Rule / Pattern')
                    ->fontFamily(FontFamily::Mono)
                    ->limit(35)
                    ->copyable()
                    ->searchable(),

                TextColumn::make('action')
                    ->label('Action')
                    ->badge()
                    ->formatStateUsing(fn (string $state): string => match ($state) {
                        'block' => 'HARD BLOCK',
                        'warn' => 'USER WARNING',
                        'redact' => 'AUTO-REDACT',
                        'log' => 'AUDIT LOG ONLY',
                        default => strtoupper($state),
                    })
                    ->color(fn (string $state): string => match ($state) {
                        'block' => 'danger',
                        'warn' => 'warning',
                        'redact' => 'info',
                        'log' => 'gray',
                        default => 'gray',
                    }),

                TextColumn::make('severity')
                    ->label('Severity')
                    ->badge()
                    ->color(fn (string $state): string => match (strtolower($state)) {
                        'critical', 'high' => 'danger',
                        'medium' => 'warning',
                        'low' => 'info',
                        default => 'gray',
                    }),

                TextColumn::make('target_domains')
                    ->label('Target Domains')
                    ->badge()
                    ->placeholder('All AI Services')
                    ->color('gray'),

                IconColumn::make('is_active')
                    ->label('Active')
                    ->boolean()
                    ->sortable(),

                TextColumn::make('updated_at')
                    ->label('Last Updated')
                    ->dateTime('M d, Y')
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('action')
                    ->options([
                        'block' => 'Hard Block',
                        'warn' => 'Warning',
                        'redact' => 'Auto-Redact',
                        'log' => 'Audit Log',
                    ]),
                SelectFilter::make('detection_type')
                    ->options([
                        'regex' => 'Regex',
                        'keyword' => 'Keyword',
                        'entropy' => 'Entropy',
                    ]),
                TernaryFilter::make('is_active')
                    ->label('Active Status'),
            ])
            ->recordActions([
                EditAction::make(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make(),
                ]),
            ]);
    }
}
