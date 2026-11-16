<?php

namespace App\Filament\Resources\DlpPolicies\Pages;

use App\Filament\Resources\DlpPolicies\DlpPolicyResource;
use Filament\Actions\DeleteAction;
use Filament\Resources\Pages\EditRecord;

class EditDlpPolicy extends EditRecord
{
    protected static string $resource = DlpPolicyResource::class;

    protected function getHeaderActions(): array
    {
        return [
            DeleteAction::make(),
        ];
    }
}
