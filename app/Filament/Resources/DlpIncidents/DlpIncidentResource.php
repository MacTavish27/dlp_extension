<?php

namespace App\Filament\Resources\DlpIncidents;

use App\Filament\Resources\DlpIncidents\Pages\ListDlpIncidents;
use App\Filament\Resources\DlpIncidents\Pages\ViewDlpIncident;
use App\Filament\Resources\DlpIncidents\Schemas\DlpIncidentForm;
use App\Filament\Resources\DlpIncidents\Schemas\DlpIncidentInfolist;
use App\Filament\Resources\DlpIncidents\Tables\DlpIncidentsTable;
use App\Models\DlpIncident;
use BackedEnum;
use UnitEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Model;

class DlpIncidentResource extends Resource
{
    protected static ?string $model = DlpIncident::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldExclamation;

    protected static UnitEnum|string|null $navigationGroup = 'DLP Security';

    protected static ?string $navigationLabel = 'Incident Monitoring';

    protected static ?string $modelLabel = 'Security Event';

    protected static ?string $pluralModelLabel = 'Incident Events';

    protected static ?int $navigationSort = 1;

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit(Model $record): bool
    {
        return false;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::count();
        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'danger';
    }

    public static function form(Schema $schema): Schema
    {
        return DlpIncidentForm::configure($schema);
    }

    public static function infolist(Schema $schema): Schema
    {
        return DlpIncidentInfolist::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return DlpIncidentsTable::configure($table);
    }

    public static function getRelations(): array
    {
        return [
            //
        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListDlpIncidents::route('/'),
            'view' => ViewDlpIncident::route('/{record}'),
        ];
    }
}
