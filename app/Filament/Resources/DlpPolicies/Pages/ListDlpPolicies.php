<?php

namespace App\Filament\Resources\DlpPolicies\Pages;

use App\Filament\Resources\DlpPolicies\DlpPolicyResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListDlpPolicies extends ListRecords
{
    protected static string $resource = DlpPolicyResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
        ];
    }
}
