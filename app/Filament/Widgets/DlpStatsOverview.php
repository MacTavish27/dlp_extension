<?php

namespace App\Filament\Widgets;

use App\Models\DlpIncident;
use App\Models\DlpPolicy;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class DlpStatsOverview extends StatsOverviewWidget
{
    protected static ?int $sort = 1;

    protected function getStats(): array
    {
        $totalIncidents = DlpIncident::count();
        $blockedCount = DlpIncident::where('action_taken', 'block')->count();
        $activePolicies = DlpPolicy::where('is_active', true)->count();
        $uniqueUsers = DlpIncident::distinct('user_identifier')->count('user_identifier');

        return [
            Stat::make('Total Security Events', $totalIncidents)
                ->description('All monitored AI prompt violations')
                ->descriptionIcon('heroicon-m-shield-exclamation')
                ->color('primary'),

            Stat::make('Hard Blocked Prompts', $blockedCount)
                ->description('Prevented data leaks')
                ->descriptionIcon('heroicon-m-x-circle')
                ->color('danger'),

            Stat::make('Active Policies', $activePolicies)
                ->description('Enforcing DLP rules')
                ->descriptionIcon('heroicon-m-check-badge')
                ->color('success'),

            Stat::make('Monitored Users', $uniqueUsers)
                ->description('Unique user identifiers active')
                ->descriptionIcon('heroicon-m-users')
                ->color('info'),
        ];
    }
}
