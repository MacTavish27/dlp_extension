<?php

namespace App\Filament\Resources\DlpIncidents\Pages;

use App\Filament\Resources\DlpIncidents\DlpIncidentResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListDlpIncidents extends ListRecords
{
    protected static string $resource = DlpIncidentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
        ];
    }
}
