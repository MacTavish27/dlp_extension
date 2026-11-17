<?php

namespace App\Providers\Filament;

use AlizHarb\ActivityLog\ActivityLogPlugin;
use AlizHarb\ActivityLog\Enums\ActivityLogEvent;
use AlizHarb\ActivityLog\Support\ActivityLogTitle;
use App\Filament\Widgets\DlpStatsOverview;
use App\Filament\Widgets\LatestDlpIncidents;
use App\Models\DlpIncident;
use App\Models\DlpPolicy;
use App\Models\User;
use Filament\Http\Middleware\Authenticate;
use Filament\Http\Middleware\AuthenticateSession;
use Filament\Http\Middleware\DisableBladeIconComponents;
use Filament\Http\Middleware\DispatchServingFilamentEvent;
use Filament\Pages\Dashboard;
use Filament\Panel;
use Filament\PanelProvider;
use Filament\Support\Colors\Color;
use Filament\Tables\Table;
use Filament\Widgets\AccountWidget;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;

class AdminPanelProvider extends PanelProvider
{
    public function panel(Panel $panel): Panel
    {
        return $panel
            ->default()
            ->id('admin')
            ->path('admin')
            ->login()
            ->brandName('Sentinel DLP Console')
            ->colors([
                'primary' => Color::Indigo,
            ])
            ->discoverResources(in: app_path('Filament/Resources'), for: 'App\Filament\Resources')
            ->discoverPages(in: app_path('Filament/Pages'), for: 'App\Filament\Pages')
            ->pages([Dashboard::class])
            ->discoverWidgets(in: app_path('Filament/Widgets'), for: 'App\Filament\Widgets')
            ->widgets([DlpStatsOverview::class, LatestDlpIncidents::class, AccountWidget::class])
            ->middleware([
                EncryptCookies::class,
                AddQueuedCookiesToResponse::class,
                StartSession::class,
                AuthenticateSession::class,
                ShareErrorsFromSession::class,
                PreventRequestForgery::class,
                SubstituteBindings::class,
                DisableBladeIconComponents::class,
                DispatchServingFilamentEvent::class,
            ])
            ->authMiddleware([Authenticate::class])
            ->plugins([
                ActivityLogPlugin::make()
                    ->label('Log')
                    ->pluralLabel('Logs')
                    ->navigationGroup('System')
                    ->configureTableUsing(function (Table $table): Table {
                        // 1. Format the event column with meaningful labels, colors, and icons
                        $eventColumn = $table->getColumn('event');
                        if ($eventColumn) {
                            $eventColumn
                                ->formatStateUsing(fn ($state) => match ($state) {
                                    'login' => 'Login',
                                    'logout' => 'Logout',
                                    'failed' => 'Failed Login',
                                    default => ActivityLogEvent::tryFrom($state)?->getLabel() ?? ucfirst((string) $state),
                                })
                                ->color(fn ($state) => match ($state) {
                                    'created' => 'success',
                                    'updated' => 'warning',
                                    'deleted' => 'danger',
                                    'restored' => 'gray',
                                    'login' => 'success',
                                    'logout' => 'info',
                                    'failed' => 'danger',
                                    default => config("filament-activity-log.events.{$state}.color", 'gray'),
                                })
                                ->icon(fn ($state) => match ($state) {
                                    'created' => 'heroicon-m-plus',
                                    'updated' => 'heroicon-m-pencil',
                                    'deleted' => 'heroicon-m-trash',
                                    'restored' => 'heroicon-m-arrow-uturn-left',
                                    'login' => 'heroicon-m-arrow-right-end-on-rectangle',
                                    'logout' => 'heroicon-m-arrow-left-start-on-rectangle',
                                    'failed' => 'heroicon-m-x-circle',
                                    default => config("filament-activity-log.events.{$state}.icon"),
                                });
                        }

                        // 2. Format subject column to show clean titles & human-readable model types
                        $subjectColumn = $table->getColumn('subject_type');
                        if ($subjectColumn) {
                            $subjectColumn
                                ->formatStateUsing(function ($state, ?Model $record = null) {
                                    if ($record?->subject) {
                                        return ActivityLogTitle::get($record->subject);
                                    }

                                    if ($record?->log_name === 'auth') {
                                        return data_get($record->properties, 'email') ?? '-';
                                    }

                                    return $state ? class_basename($state) : '-';
                                })
                                ->description(function (?Model $record = null) {
                                    if (! $record?->subject_type) {
                                        return $record?->log_name ? ucfirst($record->log_name) : null;
                                    }

                                    return match ($record->subject_type) {
                                        User::class, 'user' => 'User',
                                        DlpPolicy::class, 'dlp_policy' => 'DLP Policy',
                                        DlpIncident::class, 'dlp_incident' => 'DLP Incident',
                                        default => class_basename($record->subject_type),
                                    };
                                });
                        }

                        // 3. Browser column displays the raw user agent string ($request->userAgent())
                        $browserColumn = $table->getColumn('properties.user_agent');
                        if ($browserColumn) {
                            $browserColumn
                                ->label('Browser');
                        }

                        return $table;
                    }),
            ]);
    }
}
