<?php

namespace App\Filament\Resources\DlpPolicies;

use App\Filament\Resources\DlpPolicies\Pages\CreateDlpPolicy;
use App\Filament\Resources\DlpPolicies\Pages\EditDlpPolicy;
use App\Filament\Resources\DlpPolicies\Pages\ListDlpPolicies;
use App\Filament\Resources\DlpPolicies\Schemas\DlpPolicyForm;
use App\Filament\Resources\DlpPolicies\Tables\DlpPoliciesTable;
use App\Models\DlpPolicy;
use BackedEnum;
use UnitEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;

class DlpPolicyResource extends Resource
{
    protected static ?string $model = DlpPolicy::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedAdjustmentsHorizontal;

    protected static UnitEnum|string|null $navigationGroup = 'DLP Security';

    protected static ?string $navigationLabel = 'Detection Policies';

    protected static ?string $modelLabel = 'DLP Policy';

    protected static ?string $pluralModelLabel = 'DLP Policies';

    protected static ?int $navigationSort = 2;

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('is_active', true)->count();
        return (string) $count;
    }

    public static function getNavigationBadgeColor(): ?string
    {
        return 'primary';
    }

    public static function form(Schema $schema): Schema
    {
        return DlpPolicyForm::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return DlpPoliciesTable::configure($table);
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
            'index' => ListDlpPolicies::route('/'),
            'create' => CreateDlpPolicy::route('/create'),
            'edit' => EditDlpPolicy::route('/{record}/edit'),
        ];
    }
}
