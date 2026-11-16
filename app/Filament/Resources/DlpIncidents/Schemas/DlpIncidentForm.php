<?php

namespace App\Filament\Resources\DlpIncidents\Schemas;

use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Textarea;
use Filament\Schemas\Schema;

class DlpIncidentForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->components([
                TextInput::make('dlp_policy_id')
                    ->required()
                    ->numeric(),
                TextInput::make('user_identifier'),
                TextInput::make('domain')
                    ->required(),
                TextInput::make('action_taken')
                    ->required(),
                TextInput::make('masked_sample'),
                DateTimePicker::make('occurred_at')
                    ->required(),
                Textarea::make('prompt_content')
                    ->columnSpanFull(),
                TextInput::make('client_ip'),
                Textarea::make('user_agent')
                    ->columnSpanFull(),
            ]);
    }
}
