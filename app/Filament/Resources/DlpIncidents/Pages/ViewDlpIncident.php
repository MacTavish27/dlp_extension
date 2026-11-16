<?php

namespace App\Filament\Resources\DlpIncidents\Pages;

use App\Filament\Resources\DlpIncidents\DlpIncidentResource;
use Filament\Actions\EditAction;
use Filament\Resources\Pages\ViewRecord;

class ViewDlpIncident extends ViewRecord
{
    protected static string $resource = DlpIncidentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            EditAction::make(),
        ];
    }
}
