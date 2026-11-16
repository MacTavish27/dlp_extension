<?php

namespace App\Filament\Resources\DlpIncidents\Pages;

use App\Filament\Resources\DlpIncidents\DlpIncidentResource;
use Filament\Actions\DeleteAction;
use Filament\Actions\ViewAction;
use Filament\Resources\Pages\EditRecord;

class EditDlpIncident extends EditRecord
{
    protected static string $resource = DlpIncidentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            ViewAction::make(),
            DeleteAction::make(),
        ];
    }
}
